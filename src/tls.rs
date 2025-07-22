use anyhow::Result;
use rustls::{ClientConfig, RootCertStore, KeyLogFile};
use std::sync::Arc;

pub fn create_ssl_connector() -> Result<Arc<ClientConfig>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Enable 0-RTT session resumption and early data
    config.enable_early_data = true;

    // To use KeyLogFile, it reads the SSLKEYLOGFILE environment variable
    unsafe {
        std::env::set_var("SSLKEYLOGFILE", "keylog.txt");
    }
    config.key_log = Arc::new(KeyLogFile::new());

    Ok(Arc::new(config))
}
