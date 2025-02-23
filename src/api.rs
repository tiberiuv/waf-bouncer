use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use crate::crowdsec::CrowdsecAppsecApi;
use axum::extract::{ConnectInfo, FromRef, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::HeaderValue;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, MethodRouter};
use axum::{async_trait, Json, RequestPartsExt, Router};
use ipnet::IpNet;
use reqwest::StatusCode;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::App;

pub struct ExtractRealIp(IpAddr);

pub static FORBIDDEN_HTML: LazyLock<Html<&str>> =
    LazyLock::new(|| Html("<H1>Request blocked!<H1>"));

#[async_trait]
impl<S> FromRequestParts<S> for ExtractRealIp
where
    App: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = axum::response::Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = App::from_ref(state);
        let proxy_headers = app_state.config.proxy_headers;
        let addr = parts
            .extract::<ConnectInfo<SocketAddr>>()
            .await
            .map_err(|_err| (StatusCode::BAD_REQUEST, "Invalid").into_response())?;
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
            return Err((StatusCode::FORBIDDEN, *FORBIDDEN_HTML).into_response());
        }

        let real_client_ip = get_client_ip_x_forwarded_for(
            app_state.config.trusted_proxies,
            x_forwarded_for,
            remote_client_ip,
        );

        let proxy_uri = headers
            .get(&proxy_headers.uri)
            .map(|x| x.to_str().unwrap_or_default())
            .unwrap_or("");
        let proxy_method = headers
            .get(&proxy_headers.method)
            .map(|x| x.to_str().unwrap_or_default())
            .unwrap_or("");
        let proxy_host = headers
            .get(&proxy_headers.host)
            .map(|x| x.to_str().unwrap_or_default())
            .unwrap_or("");
        let x_forwarded_for = headers
            .get("x-forwarded-for")
            .map(|x| x.to_str().unwrap_or_default())
            .unwrap_or("");
        let x_real_ip = headers
            .get("x-real-ip")
            .map(|x| x.to_str().unwrap_or_default())
            .unwrap_or("");

        tracing::info!(
            real_client_ip = real_client_ip.to_string(),
            remote_client_ip = remote_client_ip.to_string(),
            proxy_uri,
            proxy_method,
            proxy_host,
            x_forwarded_for,
            x_real_ip,
        );

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
            let mut ips = x_forwarded_headers_ips.into_iter().rev().peekable();
            while let Some(ip) = ips.next() {
                let is_trusted = trusted_proxies.iter().any(|proxy| proxy.contains(&ip));
                if !is_trusted || ips.peek().is_none() {
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
            .map(|ip| ip.trim_ascii().parse())
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
    State(app): State<App>,
    ExtractRealIp(real_client_ip): ExtractRealIp,
    request: Request,
) -> impl IntoResponse {
    let is_trusted_network = app.config.trusted_networks.contains(&real_client_ip);

    if is_trusted_network {
        tracing::debug!(?real_client_ip, "Ip is trusted, skipping appsec",);
        return StatusCode::OK.into_response();
    }

    if app.blacklist.contains(real_client_ip) {
        tracing::info!(real_client_ip = real_client_ip.to_string(), "Ip is banned!");
        return (StatusCode::FORBIDDEN, *FORBIDDEN_HTML).into_response();
    }

    let result = app
        .appsec_client
        .appsec_request(request, real_client_ip, app.config.proxy_headers)
        .await;
    match result {
        Ok(is_ok) => if is_ok {
            StatusCode::OK.into_response()
        } else {
            (StatusCode::FORBIDDEN, *FORBIDDEN_HTML).into_response()
        }
        .into_response(),
        Err(_err) => (StatusCode::FORBIDDEN, *FORBIDDEN_HTML).into_response(),
    }
}

async fn health() -> impl IntoResponse {
    StatusCode::OK.into_response()
}

fn api_server_router(state: App) -> Router {
    let v1 = Router::new()
        .route("/ip-info", get(ip_info))
        .route("/waf", get(check_ip))
        .route("/health", get(health));

    let api = Router::new().nest("/v1", v1);

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
                let uri = request.uri();

                match uri.path() {
                    "/" | "/api/v1/waf" => {
                        tracing::info_span!("proxy_request",)
                    }
                    "/api/v1/health" => tracing::Span::none(),
                    _ => {
                        tracing::info_span!("http_request",)
                    }
                }
            }),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(5)))
        .with_state(state)
}

pub async fn api_server_listen(
    state: App,
    socket_addr: SocketAddr,
    handle: axum_server::Handle,
) -> std::io::Result<()> {
    let router = api_server_router(state);

    tracing::info!(listen = ?socket_addr, "Starting API server");
    let listener = tokio::net::TcpListener::bind(socket_addr).await.unwrap();

    axum_server::from_tcp(listener.into_std()?)
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use axum::http::HeaderValue;
    use ipnet::IpNet;

    use super::get_client_ip_x_forwarded_for;

    fn parse_ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn parse_cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn parse_cidrs<'a>(l: impl IntoIterator<Item = &'a str>) -> Vec<IpNet> {
        l.into_iter().map(parse_cidr).collect()
    }
    fn parse_hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }
    #[test]
    fn get_real_ip() {
        let cases = [
            (
                (
                    parse_cidrs(["192.168.0.0/30"]),
                    Some(parse_hv("192.168.0.1, 192.168.0.2")),
                    parse_ip("192.168.0.2"),
                ),
                parse_ip("192.168.0.1"),
            ),
            (
                (vec![], Some(parse_hv("127.0.0.3")), parse_ip("127.0.0.2")),
                parse_ip("127.0.0.2"),
            ),
            (
                (
                    parse_cidrs(["192.168.0.0/30"]),
                    Some(parse_hv("127.0.0.3")),
                    parse_ip("192.168.0.3"),
                ),
                parse_ip("127.0.0.3"),
            ),
            (
                (
                    parse_cidrs(["127.0.0.2/32"]),
                    Some(parse_hv("127.0.0.1")),
                    parse_ip("127.0.0.2"),
                ),
                parse_ip("127.0.0.1"),
            ),
            (
                (
                    parse_cidrs(["127.0.0.1/32"]),
                    Some(parse_hv("127.0.0.3,127.0.0.1")),
                    parse_ip("127.0.0.1"),
                ),
                parse_ip("127.0.0.3"),
            ),
            (
                (
                    parse_cidrs(["127.0.0.1/32", "127.0.0.2/32"]),
                    Some(parse_hv("127.0.0.3, 127.0.0.2, 127.0.0.1")),
                    parse_ip("127.0.0.2"),
                ),
                parse_ip("127.0.0.3"),
            ),
        ];

        for (args, expected) in cases {
            let actual = get_client_ip_x_forwarded_for(args.0, args.1.as_ref(), args.2);

            assert_eq!(actual, expected);
        }
    }
}
