use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::anyhow;
use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Uri};
use chrono::{DateTime, Utc};
use hyper_rustls::HttpsConnector;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use reqwest::{Certificate, Identity, StatusCode, Url};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

use serde::{Deserialize, Serialize};
use tracing::error;

use crate::blacklist::IpRangeMixed;
use crate::cli::ClientCerts;
use crate::USER_AGENT;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    #[default]
    Cscli,
    Crowdsec,
    #[serde(rename = "CAPI")]
    Capi,
    Lists,
    #[serde(untagged)]
    Other(String),
}

impl Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cscli => f.write_str("cscli"),
            Self::Crowdsec => f.write_str("crowdsec"),
            Self::Capi => f.write_str("CAPI"),
            Self::Lists => f.write_str("lists"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(dead_code)]
pub enum Scope {
    #[default]
    Ip,
    Range,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum DecisionType {
    #[default]
    Ban,
    Captcha,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Decision {
    /// the duration of the decisions
    pub duration: String,
    /// (only relevant for GET ops) the unique id
    pub id: Option<i64>,
    /// the origin of the decision : cscli, crowdsec
    pub origin: Origin,
    pub scenario: String,
    /// the scope of decision : does it apply to an IP, a range, a username, etc
    pub scope: Scope,
    /// true if the decision result from a scenario in simulation mode
    pub simulated: Option<bool>,
    /// the type of decision, might be 'ban', 'captcha' or something custom. Ignored when watcher (cscli/crowdsec) is pushing to APIL.
    #[serde(rename = "type")]
    pub type_: DecisionType,
    /// the date until the decisions must be active
    pub until: Option<DateTime<Utc>>,
    /// only relevant for LAPI->CAPI, ignored for cscli->LAPI and crowdsec->LAPI
    pub uuid: Option<String>,
    /// the value of the decision scope : an IP, a range, a username, etc
    pub value: String,
}

impl TryFrom<&Decision> for ipnet::IpNet {
    type Error = anyhow::Error;
    fn try_from(decision: &Decision) -> Result<Self, Self::Error> {
        if let Some(until) = decision.until {
            let now = chrono::Utc::now();
            if until < now {
                return Err(anyhow!("decision skipped due to 'until' in the future"));
            }
        }
        match decision.scope {
            Scope::Ip => Ok(match decision.value.parse::<IpAddr>()? {
                IpAddr::V4(v4) => IpNet::V4(Ipv4Net::new(v4, 32)?),
                IpAddr::V6(v6) => IpNet::V6(Ipv6Net::new(v6, 128)?),
            }),
            Scope::Range => Ok(decision.value.parse::<IpNet>()?),
            Scope::Other(ref scope) => Err(anyhow!("Unhadled scope '{}'", scope)),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DecisionsResponse {
    pub new: Option<Vec<Decision>>,
    pub deleted: Option<Vec<Decision>>,
}

fn parse_crowdsec_decisions(decisions: Option<Vec<Decision>>) -> Vec<IpNet> {
    let (to_add, errors): (Vec<_>, Vec<_>) = decisions
        .unwrap_or_default()
        .iter()
        .map(TryFrom::try_from)
        .partition(Result::is_ok);
    if !errors.is_empty() {
        let errors: Vec<anyhow::Error> = errors.into_iter().map(|ip| ip.unwrap_err()).collect();
        error!(?errors, msg = "Error parsing ips from crowdsec decisions");
    }
    to_add.into_iter().map(|ip| ip.unwrap()).collect()
}

impl From<DecisionsResponse> for DecisionsIpRange {
    fn from(value: DecisionsResponse) -> Self {
        Self {
            new: IpRangeMixed::from(parse_crowdsec_decisions(value.new)),
            deleted: IpRangeMixed::from(parse_crowdsec_decisions(value.deleted)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecisionsIpRange {
    pub new: IpRangeMixed,
    pub deleted: IpRangeMixed,
}

impl DecisionsIpRange {
    /// Only keep new nets that are not in the filter
    pub fn filter_new(self, filter: &IpRangeMixed) -> Self {
        Self {
            new: self.new.exclude(filter),
            deleted: self.deleted,
        }
    }

    /// Only keep deleted nets that are already in the filter
    pub fn filter_deleted(self, filter: &IpRangeMixed) -> Self {
        Self {
            new: self.new,
            deleted: self.deleted.intersect(filter),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.new.is_empty() && self.deleted.is_empty()
    }

    pub fn into_nets(&self) -> DecisionsNets {
        DecisionsNets {
            new: self.new.into_nets(),
            deleted: self.deleted.into_nets(),
        }
    }
}

#[derive(Debug)]
pub struct DecisionsNets {
    pub new: Vec<IpNet>,
    pub deleted: Vec<IpNet>,
}

pub fn ipnets_for_log<'a>(value: impl IntoIterator<Item = &'a IpNet>) -> String {
    value
        .into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>()
        .join(" ")
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    Add,
    Del,
    ReturnValues,
}

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

#[derive(Debug, Clone)]
pub enum CrowdsecAuth {
    Apikey(String),
    Certs(CertAuthReqwest),
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
                .map_err(|e| anyhow!("error in client_cert"))?,
            root_ca: CertificateDer::from_pem_slice(&value.ca_cert)
                .map_err(|e| anyhow!("error in root ca cert"))?,
            client_key: PrivateKeyDer::from_pem_slice(&value.client_key)
                .map_err(|e| anyhow!("error in client key"))?,
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
