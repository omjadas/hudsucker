use crate::certificate_authority::CertificateAuthority;
use async_trait::async_trait;
use http::uri::Authority;
use moka::future::Cache;
use openssl::{
    asn1::Asn1Time,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    x509::{extension::SubjectAlternativeName, X509Builder, X509NameBuilder, X509},
};
use std::sync::Arc;
use tokio_rustls::rustls::{self, ServerConfig};

/// Issues certificates for use when communicating with clients.
///
/// Issues certificates for communicating with clients over TLS. Certificates are cached in memory
/// up to a max size that is provided when creating the authority. Certificates are generated using
/// the `openssl` crate.
#[cfg_attr(docsrs, doc(cfg(feature = "openssl-certs")))]
#[derive(Clone)]
pub struct OpensslAuthority {
    pkey: PKey<Private>,
    private_key: rustls::PrivateKey,
    ca_cert: X509,
    hash: MessageDigest,
    cache: Cache<Authority, Arc<ServerConfig>>,
}

impl OpensslAuthority {
    /// Creates a new openssl authority.
    pub fn new(pkey: PKey<Private>, ca_cert: X509, hash: MessageDigest, cache_size: usize) -> Self {
        let private_key = rustls::PrivateKey(
            pkey.private_key_to_der()
                .expect("Failed to encode private key"),
        );

        Self {
            pkey,
            private_key,
            ca_cert,
            hash,
            cache: Cache::new(cache_size),
        }
    }

    fn gen_cert(&self, authority: &Authority) -> Result<rustls::Certificate, ErrorStack> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", authority.host())?;
        let name = name_builder.build();

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_version(2)?;
        x509_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        x509_builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
        x509_builder.set_pubkey(&self.pkey)?;
        x509_builder.set_issuer_name(self.ca_cert.subject_name())?;

        let alternative_name = SubjectAlternativeName::new()
            .dns(authority.host())
            .build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(alternative_name)?;

        x509_builder.sign(&self.pkey, self.hash)?;
        let x509 = x509_builder.build();
        Ok(rustls::Certificate(x509.to_der()?))
    }
}

#[async_trait]
impl CertificateAuthority for OpensslAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.get(authority) {
            return server_cfg;
        }

        let certs = vec![self
            .gen_cert(authority)
            .unwrap_or_else(|_| panic!("Failed to generate certificate for {}", authority))];

        let mut server_cfg = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone())
            .expect("Failed to build ServerConfig");

        server_cfg.alpn_protocols = vec![
            #[cfg(feature = "http2")]
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];

        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;

        server_cfg
    }
}
