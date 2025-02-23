use std::sync::LazyLock;

use clap::Parser;
use rustls::crypto::CryptoProvider;
use tracing::info;
use waf_bouncer::api::api_server_listen;
use waf_bouncer::cli::ClientCerts;
use waf_bouncer::trace_sub::{get_subscriber, init_subscriber};
use waf_bouncer::{
    reconcile, App, AppsecClient, BlacklistCache, CertAuthRustls, Config, CrowdsecLapiClient,
};

pub static BLACKLIST_CACHE: LazyLock<BlacklistCache> = LazyLock::new(Default::default);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("tls crypto");
    let subscriber = get_subscriber("App".to_string(), "info".to_string());
    init_subscriber(subscriber);

    let cli = waf_bouncer::cli::Cli::parse();

    let certs = ClientCerts::try_from(cli.auth.cert_auth.clone())?;
    let lapi = CrowdsecLapiClient::new(
        cli.crowdsec_api.clone(),
        TryFrom::try_from(cli.auth.clone())?,
        std::time::Duration::from_secs(cli.crowdsec_timeout),
    );

    let crowdsec_appsec_api = cli.crowdsec_appsec_api.unwrap_or(cli.crowdsec_api);
    let appsec_client = AppsecClient::new(
        crowdsec_appsec_api,
        Some(CertAuthRustls::try_from(certs)?),
        cli.auth.crowdsec_apikey.unwrap_or_default(),
    );

    let app = App {
        config: Config {
            trusted_proxies: cli.trusted_proxies.unwrap_or_default(),
            trusted_networks: cli.trusted_networks.map(From::from).unwrap_or_default(),
            proxy_headers: cli.proxy_request_headers,
        },
        appsec_client,
        blacklist: &BLACKLIST_CACHE,
        lapi,
    };
    info!(?app.config, "config");

    let mut task_set = tokio::task::JoinSet::new();
    let app_clone = app.clone();
    task_set.spawn(async move { reconcile(app_clone).await });
    task_set.spawn(async move {
        api_server_listen(app, cli.listen_addr)
            .await
            .map_err(anyhow::Error::new)
    });

    while let Some(res) = task_set.join_next().await {
        res??;
    }

    info!("Exit!");

    Ok(())
}
