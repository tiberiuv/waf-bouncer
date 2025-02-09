use std::net::{IpAddr, SocketAddr};

use crate::crowdsec::CrowdsecAppsecApi;
use axum::extract::{ConnectInfo, FromRef, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::HeaderValue;
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use axum::{async_trait, Json, RequestPartsExt, Router};
use ipnet::IpNet;
use reqwest::StatusCode;
use tower_http::trace::TraceLayer;

use crate::AppState;

pub struct ExtractRealIp(IpAddr);

#[async_trait]
impl<S> FromRequestParts<S> for ExtractRealIp
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let addr = parts
            .extract::<ConnectInfo<SocketAddr>>()
            .await
            .map_err(|_err| (StatusCode::BAD_REQUEST, "Invalid"))?;
        let headers = &parts.headers;
        let remote_client_ip = addr.ip();

        let x_forwarded_for = headers.get("X-Forwarded-For");

        let is_trusted_proxy = app_state
            .config
            .trusted_proxies
            .iter()
            .any(|x| x.contains(&remote_client_ip));
        if !is_trusted_proxy {
            tracing::error!(
                ?remote_client_ip,
                "Received request from untrusted ip rejecting...",
            );
            return Err((StatusCode::FORBIDDEN, "Forbidden"));
        }

        let real_client_ip = get_client_ip_x_forwarded_for(
            app_state.config.trusted_proxies,
            x_forwarded_for,
            remote_client_ip,
        );
        tracing::info!(?real_client_ip);
        Ok(ExtractRealIp(real_client_ip))
    }
}

pub fn get_client_ip_x_forwarded_for(
    trusted_proxies: Vec<IpNet>,
    x_forwarded_for_header: Option<&HeaderValue>,
    remote_client_ip: IpAddr,
) -> IpAddr {
    x_forwarded_for_header
        .and_then(parse_multi_ip_header)
        .and_then(|mut x_forwarded_headers_ips| {
            x_forwarded_headers_ips.push(remote_client_ip);
            let mut rev_ips = x_forwarded_headers_ips.into_iter().rev().peekable();
            while let Some(ip) = rev_ips.next() {
                let trusted = trusted_proxies.iter().any(|proxy| proxy.contains(&ip));
                if !trusted || rev_ips.peek().is_none() {
                    return Some(ip);
                }
            }
            None
        })
        .unwrap_or(remote_client_ip)
}

fn parse_multi_ip_header(header_value: &HeaderValue) -> Option<Vec<IpAddr>> {
    header_value.to_str().ok().and_then(|s| {
        s.split(',')
            .map(|ip| ip.parse())
            .collect::<Result<Vec<_>, _>>()
            .ok()
    })
}

#[derive(serde::Serialize)]
pub struct DebugResponse {
    remote_client_ip: IpAddr,
    real_client_ip: IpAddr,
}

async fn ip_info(
    ExtractRealIp(real_client_ip): ExtractRealIp,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    Json(DebugResponse {
        remote_client_ip: addr.ip(),
        real_client_ip,
    })
}

async fn check_ip(
    State(app_state): State<AppState>,
    ExtractRealIp(real_client_ip): ExtractRealIp,
    request: Request,
) -> impl IntoResponse {
    let is_trusted_network = app_state
        .config
        .trusted_networks
        .iter()
        .any(|x| x.contains(&real_client_ip));

    if is_trusted_network {
        tracing::debug!(?real_client_ip, "Ip is trusted, skipping appsec",);
        return StatusCode::OK.into_response();
    }

    let result = app_state
        .appsec_client
        .appsec_request(request, real_client_ip, app_state.config.proxy_headers)
        .await;
    match result {
        Ok(is_ok) => if is_ok {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        }
        .into_response(),
        Err(_err) => StatusCode::FORBIDDEN.into_response(),
    }
}

async fn health() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

fn api_server_router(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/ip-info", get(ip_info))
        .route("/waf", get(check_ip))
        .route("/health", get(health));

    let api = Router::new().nest("/v1", v1);
    let proxy_headers = state.config.proxy_headers.clone();

    Router::new()
        .nest("/api", api)
        .fallback(
            MethodRouter::new()
                .get(check_ip)
                .head(check_ip)
                .delete(check_ip)
                .options(check_ip)
                .patch(check_ip)
                .post(check_ip)
                .put(check_ip)
                .trace(check_ip),
        )
        .layer(
            TraceLayer::new_for_http().make_span_with(move |request: &Request<_>| {
                let headers = request.headers();
                let proxy_uri = headers.get(&proxy_headers.uri);
                let proxy_method = headers.get(&proxy_headers.method);
                let proxy_host = headers.get(&proxy_headers.host);
                let x_forwarded_for = headers.get("x-forwarded-for");
                let uri = request.uri();

                match uri.path() {
                    "/" | "/api/v1/waf" => {
                        tracing::info_span!(
                            "proxy_request",
                            uri = ?request.uri(),
                            proxy_uri = ?proxy_uri,
                            proxy_method = ?proxy_method,
                            proxy_host = ?proxy_host,
                            x_forwarded_for = ?x_forwarded_for,
                        )
                    }
                    "/api/v1/health" => tracing::Span::none(),
                    _ => {
                        tracing::info_span!(
                            "http_request",
                            uri = ?request.uri(),
                            proxy_uri = ?proxy_uri,
                            proxy_method = ?proxy_method,
                            proxy_host = ?proxy_host,
                            x_forwarded_for = ?x_forwarded_for,
                        )
                    }
                }
            }),
        )
        .with_state(state)
}

pub async fn api_server_listen(state: AppState, socket_addr: SocketAddr) -> std::io::Result<()> {
    let router = api_server_router(state);

    tracing::info!(listen = ?socket_addr, "Starting API server");
    let listener = tokio::net::TcpListener::bind(socket_addr).await.unwrap();
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use axum::http::HeaderValue;

    use super::get_client_ip_x_forwarded_for;

    #[test]
    fn get_real_ip() {
        let cases = [
            (
                (
                    vec![],
                    Some(HeaderValue::from_str("127.0.0.3").unwrap()),
                    "127.0.0.2".parse().unwrap(),
                ),
                "127.0.0.2".parse::<IpAddr>().unwrap(),
            ),
            (
                (
                    vec!["127.0.0.2/32".parse().unwrap()],
                    Some(HeaderValue::from_str("127.0.0.1").unwrap()),
                    "127.0.0.2".parse().unwrap(),
                ),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ),
            (
                (
                    vec!["127.0.0.1/32".parse().unwrap()],
                    Some(HeaderValue::from_str("127.0.0.3,127.0.0.1").unwrap()),
                    "127.0.0.1".parse().unwrap(),
                ),
                "127.0.0.3".parse::<IpAddr>().unwrap(),
            ),
            (
                (
                    vec![
                        "127.0.0.1/32".parse().unwrap(),
                        "127.0.0.2/32".parse().unwrap(),
                    ],
                    Some(HeaderValue::from_str("127.0.0.3,127.0.0.2,127.0.0.1").unwrap()),
                    "127.0.0.2".parse().unwrap(),
                ),
                "127.0.0.3".parse::<IpAddr>().unwrap(),
            ),
        ];

        for (args, expected) in cases {
            let actual = get_client_ip_x_forwarded_for(args.0, args.1.as_ref(), args.2);

            assert_eq!(actual, expected);
        }
    }
}
