use ipnet::IpNet;

mod blacklist;
mod crowdsec;
mod utils;

pub mod api;
pub mod cli;
pub mod trace_sub;
pub use blacklist::BlacklistCache;
pub use cli::ProxyRequestHeaders;
pub use crowdsec::{
    reconcile, AppsecClient, CertAuthRustls, CrowdsecAppsecApi, CrowdsecAuth, CrowdsecLAPI,
    CrowdsecLapiClient,
};

use self::blacklist::IpRangeMixed;

pub const USER_AGENT: &str = "waf-bouncer/v0.0.1";

#[derive(Clone, Debug)]
pub struct Config {
    pub trusted_proxies: Vec<IpNet>,
    pub trusted_networks: IpRangeMixed,
    pub proxy_headers: ProxyRequestHeaders,
}

#[derive(Clone)]
pub struct App {
    pub config: Config,
    pub appsec_client: AppsecClient,
    pub blacklist: &'static BlacklistCache,
    pub lapi: CrowdsecLapiClient,
}
