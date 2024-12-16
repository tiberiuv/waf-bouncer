use clap::Parser;
use rustls::crypto::CryptoProvider;
use tracing::info;
use waf_bouncer::api::api_server_listen;
use waf_bouncer::cli::ClientCerts;
use waf_bouncer::trace_sub::{get_subscriber, init_subscriber};
use waf_bouncer::{AppState, AppsecClient, CertAuthRustls, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .expect("tls crypto");
    let subscriber = get_subscriber("App".to_string(), "info".to_string());
    init_subscriber(subscriber);

    let cli = waf_bouncer::cli::Cli::parse();

    let certs = ClientCerts::try_from(cli.auth.cert_auth)?;
    let state = AppState {
        config: Config {
            trusted_proxies: cli.trusted_proxies.unwrap_or_default(),
            trusted_networks: cli.trusted_networks.unwrap_or_default(),
            proxy_headers: cli.proxy_request_headers,
        },
        appsec_client: AppsecClient::new(
            cli.crowdsec_api,
            Some(CertAuthRustls::try_from(certs)?),
            cli.auth.crowdsec_apikey.unwrap_or_default(),
        ),
    };
    info!(?state.config, "config");

    Ok(api_server_listen(state, cli.listen_addr).await?)
}
