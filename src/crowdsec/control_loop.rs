use tracing::info;

use super::lapi::{CrowdsecLAPI, DecisionsOptions};
use super::types::DecisionsIpRange;
use crate::crowdsec::lapi::DEFAULT_DECISION_ORIGINS;
use crate::utils::retry_op;
use crate::App;

pub async fn reconcile_decisions(
    app: &App,
    decision_options: &DecisionsOptions,
) -> Result<(), anyhow::Error> {
    info!("Fetching decisions");

    let new_decisions = app.lapi.stream_decisions(decision_options).await?;

    let blacklist = app.blacklist.load();
    let decision_ips = DecisionsIpRange::from(new_decisions)
        .filter_new(&app.config.trusted_networks)
        .filter_new(blacklist.as_ref())
        .filter_deleted(blacklist.as_ref());
    let new_blacklist = app
        .blacklist
        .load()
        .as_ref()
        .merge(&decision_ips.new)
        .exclude(&decision_ips.deleted);
    app.blacklist.store(new_blacklist);

    Ok(())
}

pub async fn reconcile(app: App) -> Result<(), anyhow::Error> {
    info!("Starting main loop, fetching decisions...");
    let mut decisions_options = DecisionsOptions::new(&DEFAULT_DECISION_ORIGINS, true);
    loop {
        retry_op(10, || reconcile_decisions(&app, &decisions_options)).await?;

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        if decisions_options.get_startup() {
            decisions_options.set_startup(false);
        }
    }
}
