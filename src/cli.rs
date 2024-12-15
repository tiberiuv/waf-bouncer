use std::net::SocketAddr;
use std::path::PathBuf;

use axum::http::HeaderName;
use clap::{Args, Parser};
use ipnet::IpNet;
use reqwest::Url;

use crate::utils::read_file;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[arg(long, env, default_value = "127.0.0.1:3000")]
    pub listen_addr: SocketAddr,

    #[arg(long, env, num_args = 1..)]
    pub trusted_proxies: Option<Vec<IpNet>>,

    #[arg(long, env, num_args = 1..)]
    pub trusted_networks: Option<Vec<IpNet>>,

    #[arg(long, env = "CROWDSEC_TIMEOUT", default_value = "10")]
    pub crowdsec_timeout: u64,

    #[arg(long, env = "CROWDSEC_API", default_value = "http://localhost:8080")]
    pub crowdsec_api: Url,

    #[command(flatten)]
    pub auth: Auth,

    #[command(flatten)]
    pub proxy_request_headers: ProxyRequestHeaders,
}

#[derive(Debug, Clone, Args)]
#[group(required = false, multiple = true)]
pub struct ProxyRequestHeaders {
    #[arg(env = "PROXY_REQUEST_HEADER_URI", default_value = "x-forwarded-uri")]
    pub uri: HeaderName,
    #[arg(
        env = "PROXY_REQUEST_HEADER_METHOD",
        default_value = "x-forwarded-method"
    )]
    pub method: HeaderName,
    #[arg(env = "PROXY_REQUEST_HEADER_HOST", default_value = "x-forwarded-host")]
    pub host: HeaderName,
}

#[derive(Debug, Clone, Args)]
#[group(required = false, multiple = true)]
pub struct Auth {
    #[arg(long, env = "CROWDSEC_APIKEY")]
    pub crowdsec_apikey: Option<String>,

    #[command(flatten)]
    pub cert_auth: CertAuth,
}

#[derive(Debug, Args, Clone)]
#[group(required = false, multiple = true)]
pub struct CertAuth {
    #[arg(
        long,
        env = "CROWDSEC_ROOT_CA_CERT",
        default_value = "/etc/crowdsec_bouncer/certs/ca.crt"
    )]
    pub crowdsec_root_ca_cert: PathBuf,

    #[arg(
        long,
        env = "CROWDSEC_CLIENT_CERT",
        default_value = "/etc/crowdsec_bouncer/certs/tls.crt"
    )]
    pub crowdsec_client_cert: PathBuf,

    #[arg(
        long,
        env = "CROWDSEC_CLIENT_KEY",
        default_value = "/etc/crowdsec_bouncer/certs/tls.key"
    )]
    pub crowdsec_client_key: PathBuf,
}

#[allow(dead_code)]
impl CertAuth {
    fn exists(&self) -> bool {
        self.crowdsec_client_key.exists()
            && self.crowdsec_client_cert.exists()
            && self.crowdsec_root_ca_cert.exists()
    }
}

pub struct ClientCerts {
    pub ca_cert: Vec<u8>,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
}

impl TryFrom<CertAuth> for ClientCerts {
    type Error = anyhow::Error;
    fn try_from(value: CertAuth) -> Result<Self, Self::Error> {
        Ok(Self {
            ca_cert: read_file(&value.crowdsec_root_ca_cert)?,
            client_cert: read_file(&value.crowdsec_client_cert)?,
            client_key: read_file(&value.crowdsec_client_key)?,
        })
    }
}
