use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, RequestBuilder, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::{info, instrument};

use super::types::{CrowdsecAuth, DecisionsResponse, Origin};
use crate::USER_AGENT;

#[allow(async_fn_in_trait)]
pub trait CrowdsecLAPI {
    async fn stream_decisions(
        &self,
        decision_options: &DecisionsOptions,
    ) -> Result<DecisionsResponse, anyhow::Error>;
}

#[derive(Debug, Clone)]
pub struct CrowdsecLapiClient {
    client: Client,
    host: Url,
}

impl CrowdsecLapiClient {
    pub fn new(host: Url, auth: CrowdsecAuth, timeout: Duration) -> Self {
        let builder = Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(3))
            .user_agent(USER_AGENT);
        let client = match auth.clone() {
            CrowdsecAuth::Apikey(apikey) => {
                let mut headers_map = HeaderMap::new();
                headers_map.insert(
                    "apikey",
                    HeaderValue::from_str(&apikey).expect("invalid key"),
                );

                builder.default_headers(headers_map).build()
            }
            CrowdsecAuth::Certs(ref cert_auth) => builder
                .use_rustls_tls()
                .add_root_certificate(cert_auth.root_ca.clone())
                .identity(cert_auth.identity.clone())
                .build(),
        }
        .expect("Failed to build client");
        Self { client, host }
    }

    pub fn new_with_client(host: Url, client: Client) -> Self {
        Self { client, host }
    }

    fn url(&self, path: &str) -> Url {
        self.host.join(path).expect("invalid url")
    }

    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        f: impl FnOnce(RequestBuilder) -> RequestBuilder,
    ) -> Result<T, anyhow::Error> {
        let url = self.url(path);

        let request = self.client.get(url);

        let resp = f(request).send().await?.error_for_status()?;

        Ok(resp.json().await?)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum DecisionType {
    Ban,
    Captcha,
}

#[derive(Serialize, Default, Debug)]
pub struct DecisionsOptions {
    pub startup: bool,
    #[serde(rename = "type")]
    pub type_: Option<DecisionType>,
    pub origins: Option<String>,
    pub dedup: Option<bool>,
}

impl DecisionsOptions {
    pub fn new(origins: &[Origin], startup: bool) -> Self {
        let origins = origins
            .iter()
            .map(|o| o.to_string())
            .collect::<Vec<String>>()
            .join(",");
        Self {
            startup,
            type_: Some(DecisionType::Ban),
            origins: Some(origins),
            dedup: Some(true),
        }
    }

    pub fn set_startup(&mut self, startup: bool) {
        self.startup = startup;
    }

    pub fn get_startup(&self) -> bool {
        self.startup
    }
}

pub const DEFAULT_DECISION_ORIGINS: [Origin; 4] =
    [Origin::Crowdsec, Origin::Lists, Origin::Cscli, Origin::Capi];
impl CrowdsecLAPI for CrowdsecLapiClient {
    #[instrument(skip(self, decision_options))]
    async fn stream_decisions(
        &self,
        decision_options: &DecisionsOptions,
    ) -> Result<DecisionsResponse, anyhow::Error> {
        let path = "/v1/decisions/stream";

        let resp = self
            .get::<DecisionsResponse>(path, |builder| builder.query(&decision_options))
            .await?;
        let added = resp.new.as_ref().map(Vec::len).unwrap_or_default();
        let deleted = resp.deleted.as_ref().map(Vec::len).unwrap_or_default();
        info!(
            added,
            deleted, decision_options.startup, "Retrieved decisions",
        );

        Ok(resp)
    }
}
