use std::net::IpAddr;
use std::str::FromStr;

use anyhow::anyhow;
use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use reqwest::{Certificate, Identity, StatusCode, Url};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

use crate::cli::ClientCerts;
use crate::USER_AGENT;

#[derive(Debug, Clone)]
pub struct CertAuthReqwest {
    pub root_ca: Certificate,
    pub identity: Identity,
}

#[derive(Debug)]
pub struct CertAuthRustls {
    pub root_ca: CertificateDer<'static>,
    pub client_cert: CertificateDer<'static>,
    pub client_key: PrivateKeyDer<'static>,
}

impl TryFrom<ClientCerts> for CertAuthReqwest {
    type Error = anyhow::Error;
    fn try_from(value: ClientCerts) -> Result<Self, Self::Error> {
        let mut pem = value.client_cert.clone();
        pem.extend_from_slice(&value.client_key);

        Ok(Self {
            root_ca: Certificate::from_pem(&value.ca_cert)?,
            identity: Identity::from_pem(&pem)?,
        })
    }
}

impl TryFrom<ClientCerts> for CertAuthRustls {
    type Error = anyhow::Error;
    fn try_from(value: ClientCerts) -> Result<Self, Self::Error> {
        Ok(Self {
            client_cert: CertificateDer::from_pem_slice(&value.client_cert)
                .map_err(|e| anyhow!("error in client_cert {:#?}", e))?,
            root_ca: CertificateDer::from_pem_slice(&value.ca_cert)
                .map_err(|e| anyhow!("error in root ca cert {:#?}", e))?,
            client_key: PrivateKeyDer::from_pem_slice(&value.client_key)
                .map_err(|e| anyhow!("error in client key {:#?}", e))?,
        })
    }
}

type Client = hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, Body>;
#[derive(Debug, Clone)]
pub struct LapiClient {
    client: Client,
    url: Url,
    apikey: String,
}

impl LapiClient {
    pub fn new(url: Url, certs: Option<CertAuthRustls>, apikey: String) -> Self {
        /* let builder = Client::builder();
        let client = if let Some(certs) = certs {
            builder
                .use_rustls_tls()
                .identity(certs.identity)
                .add_root_certificate(certs.root_ca)
                .build()
        } else {
            builder.build()
        } */
        let client = if let Some(certs) = certs {
            let mut cert_store = RootCertStore::empty();
            cert_store.add(certs.root_ca).unwrap();
            let client_config = ClientConfig::builder()
                .with_root_certificates(cert_store)
                .with_client_auth_cert(vec![certs.client_cert], certs.client_key.clone_key())
                .unwrap();

            hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new()).build(
                HttpsConnector::<HttpConnector>::builder()
                    .with_tls_config(client_config)
                    .https_or_http()
                    .enable_http2()
                    .build(),
            )
        } else {
            hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new()).build(
                HttpsConnector::<HttpConnector>::builder()
                    .with_webpki_roots()
                    .https_or_http()
                    .enable_http2()
                    .build(),
            )
        };

        Self {
            client,
            url,
            apikey,
        }
    }
}
pub const X_CROWDSEC_APPSEC_IP_HEADER: &str = "X-Crowdsec-Appsec-Ip";
pub const X_CROWDSEC_APPSEC_URI_HEADER: &str = "X-Crowdsec-Appsec-Uri";
pub const X_CROWDSEC_APPSEC_HOST_HEADER: &str = "X-Crowdsec-Appsec-Host";
pub const X_CROWDSEC_APPSEC_VERB_HEADER: &str = "X-Crowdsec-Appsec-Verb";
pub const X_CROWDSEC_APPSEC_API_KEY_HEADER: &str = "X-Crowdsec-Appsec-Api-Key";
pub const X_CROWDSEC_APPSEC_USER_AGENT_HEADER: &str = "X-Crowdsec-Appsec-User-Agent";

#[allow(async_fn_in_trait)]
pub trait CrowdsecLapi {
    async fn appsec_request(
        &self,
        request: Request,
        real_client_ip: IpAddr,
    ) -> anyhow::Result<bool>;
}

impl CrowdsecLapi for LapiClient {
    async fn appsec_request(
        &self,
        mut request: Request,
        real_client_ip: IpAddr,
    ) -> anyhow::Result<bool> {
        let host_header = request
            .headers()
            .get("Host")
            .and_then(|x| x.to_str().ok())
            .unwrap_or_default();
        let user_agent_header = request
            .headers()
            .get("User-Agent")
            .and_then(|x| x.to_str().ok())
            .unwrap_or_default();
        let method = if request.body().is_end_stream() {
            reqwest::Method::GET
        } else {
            reqwest::Method::POST
        };
        let headers = HeaderMap::from_iter([
            (
                HeaderName::from_str(X_CROWDSEC_APPSEC_IP_HEADER).unwrap(),
                HeaderValue::from_str(&real_client_ip.to_string())?,
            ),
            (
                HeaderName::from_str(X_CROWDSEC_APPSEC_API_KEY_HEADER).unwrap(),
                HeaderValue::from_str(&self.apikey)?,
            ),
            (
                HeaderName::from_str(X_CROWDSEC_APPSEC_HOST_HEADER).unwrap(),
                HeaderValue::from_str(host_header)?,
            ),
            (
                HeaderName::from_str(X_CROWDSEC_APPSEC_VERB_HEADER).unwrap(),
                HeaderValue::from_str(request.method().as_ref())?,
            ),
            (
                HeaderName::from_str(X_CROWDSEC_APPSEC_URI_HEADER).unwrap(),
                HeaderValue::from_str(&request.uri().to_string())?,
            ),
            (
                HeaderName::from_str(X_CROWDSEC_APPSEC_USER_AGENT_HEADER).unwrap(),
                HeaderValue::from_str(user_agent_header)?,
            ),
            (
                reqwest::header::USER_AGENT,
                HeaderValue::from_str(USER_AGENT)?,
            ),
        ]);

        *request.uri_mut() = Uri::try_from(self.url.to_string())?;
        *request.method_mut() = method;
        let mut_headers = request.headers_mut();
        mut_headers.extend(headers);

        let response = self.client.request(request).await?;
        Ok(response.status() == StatusCode::OK)
    }
}
