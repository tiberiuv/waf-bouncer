use std::net::{IpAddr, SocketAddr};

use crate::crowdsec::CrowdsecAppsecApi;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderValue;
use axum::response::IntoResponse;
use axum::routing::{get, MethodRouter};
use axum::{Json, Router};
use ipnet::IpNet;
use reqwest::StatusCode;
use tower_http::trace::TraceLayer;

use crate::AppState;

fn get_client_ip_x_forwarded_for(
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
    State(app_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> impl IntoResponse {
    let headers = request.headers();
    let remote_client_ip = addr.ip();

    let x_forwarded_for = headers.get("X-Forwarded-For");

    let real_client_ip = get_client_ip_x_forwarded_for(
        app_state.config.trusted_proxies,
        x_forwarded_for,
        remote_client_ip,
    );

    Json(DebugResponse {
        remote_client_ip,
        real_client_ip,
    })
}

async fn check_ip(
    State(app_state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
) -> impl IntoResponse {
    let headers = request.headers();
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
        return StatusCode::FORBIDDEN.into_response();
    }

    let real_client_ip = get_client_ip_x_forwarded_for(
        app_state.config.trusted_proxies,
        x_forwarded_for,
        remote_client_ip,
    );
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
        .with_state(state)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                tracing::info_span!(
                    "http_request",
                    method = ?request.method(),
                    uri = ?request.uri(),
                    some_other_field = tracing::field::Empty,
                )
            }),
        )
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
