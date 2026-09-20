use anyhow::Result;
use rustls::{ClientConfig, KeyLog, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct FileKeyLog(Mutex<File>);

impl FileKeyLog {
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self(Mutex::new(File::create(path)?)))
    }
}

impl KeyLog for FileKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        let line = format!("{label} {} {}\n", hex(client_random), hex(secret));
        if let Ok(mut file) = self.0.lock() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn client_config(
    ca_file: Option<&Path>,
    key_log: Option<Arc<dyn KeyLog>>,
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    match ca_file {
        Some(path) => {
            for cert in CertificateDer::pem_file_iter(path)? {
                roots.add(cert?)?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_early_data = true;
    if let Some(key_log) = key_log {
        config.key_log = key_log;
    }
    Ok(Arc::new(config))
}
