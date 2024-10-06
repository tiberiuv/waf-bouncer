use ipnet::IpNet;

mod blacklist;
mod crowdsec;
mod utils;

pub mod api;
pub mod cli;
pub mod trace_sub;
pub use crowdsec::{CrowdsecLapi, LapiClient, CertAuthReqwest, CertAuthRustls};

pub const USER_AGENT: &str = "waf-bouncer/v0.0.1";

#[derive(Clone)]
pub struct Config {
    pub trusted_proxies: Vec<IpNet>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub lapi_client: LapiClient,
}
