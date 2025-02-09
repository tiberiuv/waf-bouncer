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
        .and_then(|x_forwarded_headers_ips| {
            x_forwarded_headers_ips
                .into_iter()
                .rev()
                .find(|&ip| !trusted_proxies.iter().any(|proxy| proxy.contains(&ip)))
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
                let uri = request.uri();

                match uri.path() {
                    "/" | "/api/v1/waf" => {
                        tracing::info_span!(
                            "proxy_request",
                            uri = ?request.uri(),
                            proxy_uri = ?proxy_uri,
                            proxy_method = ?proxy_method,
                            proxy_host = ?proxy_host,
                        )
                    }
                    "/health" => tracing::Span::none(),
                    _ => {
                        tracing::info_span!(
                            "http_request",
                            uri = ?request.uri(),
                            proxy_uri = ?proxy_uri,
                            proxy_method = ?proxy_method,
                            proxy_host = ?proxy_host,
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
