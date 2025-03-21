mod appsec;
mod control_loop;
mod headers;
mod lapi;
mod types;

pub use appsec::{AppsecClient, CrowdsecAppsecApi};
pub use control_loop::reconcile;
pub use lapi::{CrowdsecLAPI, CrowdsecLapiClient};
pub use types::{Alert, CrowdsecAuth};

use anyhow::anyhow;
use reqwest::{Certificate, Identity};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::cli::ClientCerts;

#[allow(unused)]
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
                .map_err(|e| anyhow!("error in client_cert {:#?}", e))?,
            root_ca: CertificateDer::from_pem_slice(&value.ca_cert)
                .map_err(|e| anyhow!("error in root ca cert {:#?}", e))?,
            client_key: PrivateKeyDer::from_pem_slice(&value.client_key)
                .map_err(|e| anyhow!("error in client key {:#?}", e))?,
        })
    }
}
