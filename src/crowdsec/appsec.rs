use std::net::IpAddr;

use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderValue, Uri};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use reqwest::{header, Url};
use rustls::{ClientConfig, RootCertStore};

use super::headers::{
    X_CROWDSEC_APPSEC_API_KEY_HEADER, X_CROWDSEC_APPSEC_HOST_HEADER, X_CROWDSEC_APPSEC_IP_HEADER,
    X_CROWDSEC_APPSEC_URI_HEADER, X_CROWDSEC_APPSEC_USER_AGENT_HEADER,
    X_CROWDSEC_APPSEC_VERB_HEADER,
};
use super::CertAuthRustls;
use crate::cli::ProxyRequestHeaders;
use crate::USER_AGENT;

type Client = hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Body>;
#[derive(Debug, Clone)]
pub struct AppsecClient {
    client: Client,
    url: Url,
    apikey: String,
}

impl AppsecClient {
    pub fn new(url: Url, certs: Option<CertAuthRustls>, apikey: String) -> Self {
        let tls_config = if let Some(certs) = certs {
            let mut cert_store = RootCertStore::empty();
            cert_store.add(certs.root_ca).unwrap();
            ClientConfig::builder()
                .with_root_certificates(cert_store)
                .with_client_auth_cert(vec![certs.client_cert], certs.client_key.clone_key())
                .unwrap()
        } else {
            ClientConfig::builder()
                .with_webpki_roots()
                .with_no_client_auth()
        };

        let connector = HttpsConnector::<HttpConnector>::builder()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http2()
            .build();

        let client = hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(connector);

        Self {
            client,
            url,
            apikey,
        }
    }
}

#[allow(async_fn_in_trait)]
pub trait CrowdsecAppsecApi {
    async fn appsec_request(
        &self,
        request: Request,
        real_client_ip: IpAddr,
        proxy_headers_config: ProxyRequestHeaders,
    ) -> anyhow::Result<bool>;
}

impl CrowdsecAppsecApi for AppsecClient {
    async fn appsec_request(
        &self,
        mut request: Request,
        real_client_ip: IpAddr,
        proxy_request_headers_config: ProxyRequestHeaders,
    ) -> anyhow::Result<bool> {
        let forwarded_host = request
            .headers()
            .get(proxy_request_headers_config.host)
            .and_then(|x| x.to_str().ok().map(|x| x.to_string()))
            .unwrap_or_else(|| {
                request
                    .headers()
                    .get(header::HOST)
                    .and_then(|x| x.to_str().ok().map(|x| x.to_string()))
                    .unwrap_or_default()
            });
        let user_agent_header = request
            .headers()
            .get(header::USER_AGENT)
            .and_then(|x| x.to_str().ok())
            .unwrap_or_default();
        let forwarded_uri = request
            .headers()
            .get(proxy_request_headers_config.uri)
            .and_then(|x| x.to_str().ok().map(|x| x.to_string()))
            .unwrap_or(request.uri().to_string());
        let forwarded_method = request
            .headers()
            .get(proxy_request_headers_config.method)
            .and_then(|x| x.to_str().ok().map(|x| x.to_string()))
            .unwrap_or(request.method().to_string());

        let headers = HeaderMap::from_iter([
            (
                X_CROWDSEC_APPSEC_IP_HEADER,
                HeaderValue::from_str(&real_client_ip.to_string())?,
            ),
            (
                X_CROWDSEC_APPSEC_API_KEY_HEADER,
                HeaderValue::from_str(&self.apikey)?,
            ),
            (
                X_CROWDSEC_APPSEC_HOST_HEADER,
                HeaderValue::from_str(&forwarded_host)?,
            ),
            (
                X_CROWDSEC_APPSEC_VERB_HEADER,
                HeaderValue::from_str(&forwarded_method)?,
            ),
            (
                X_CROWDSEC_APPSEC_URI_HEADER,
                HeaderValue::from_str(&forwarded_uri)?,
            ),
            (
                X_CROWDSEC_APPSEC_USER_AGENT_HEADER,
                HeaderValue::from_str(user_agent_header)?,
            ),
            (
                reqwest::header::USER_AGENT,
                HeaderValue::from_str(USER_AGENT)?,
            ),
        ]);

        let mut_headers = request.headers_mut();
        mut_headers.extend(headers);

        *request.uri_mut() = Uri::try_from(self.url.to_string())?;
        *request.method_mut() = if request.body().is_end_stream() {
            reqwest::Method::GET
        } else {
            reqwest::Method::POST
        };

        let response = self.client.request(request).await?;
        let is_ok = response.status() == reqwest::StatusCode::OK;
        tracing::debug!(
            status = ?response.status(),
            original_uri = forwarded_uri,
            original_method = forwarded_method,
            original_host = forwarded_host,
            original_ip = real_client_ip.to_string(),
            "appsec query"
        );
        if !is_ok {
            tracing::info!(
                status = ?response.status(),
                original_uri = forwarded_uri,
                original_method = forwarded_method,
                original_host = forwarded_host,
                original_ip = real_client_ip.to_string(),
                "appsec query forbidden"
            );
        }
        Ok(is_ok)
    }
}
