use ipnet::IpNet;

mod crowdsec;
mod utils;

pub mod api;
pub mod cli;
pub mod trace_sub;
pub use crowdsec::{AppsecClient, CertAuthRustls, CrowdsecAppsecApi};

pub const USER_AGENT: &str = "waf-bouncer/v0.0.1";

#[derive(Clone)]
pub struct Config {
    pub trusted_proxies: Vec<IpNet>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub appsec_client: AppsecClient,
}
