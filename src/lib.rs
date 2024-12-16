use ipnet::IpNet;

mod crowdsec;
mod utils;

pub mod api;
pub mod cli;
pub mod trace_sub;
pub use crowdsec::{AppsecClient, CertAuthRustls, CrowdsecAppsecApi};

use self::cli::ProxyRequestHeaders;

pub const USER_AGENT: &str = "waf-bouncer/v0.0.1";

#[derive(Clone, Debug)]
pub struct Config {
    pub trusted_proxies: Vec<IpNet>,
    pub trusted_networks: Vec<IpNet>,
    pub proxy_headers: ProxyRequestHeaders,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub appsec_client: AppsecClient,
}
