use crate::{
    certificate_authority::{CertificateAuthority, CACHE_TTL, NOT_BEFORE_OFFSET, TTL_SECS},
    Error,
};
use async_trait::async_trait;
use http::uri::Authority;
use moka::future::Cache;
use rand::{thread_rng, Rng};
use rcgen::{DistinguishedName, DnType, KeyPair, RcgenError, SanType};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{self, ServerConfig};
use tracing::debug;

/// Issues certificates for use when communicating with clients.
///
/// Issues certificates for communicating with clients over TLS. Certificates are cached in memory
/// up to a max size that is provided when creating the authority. Certificates are generated using
/// the `rcgen` crate.
///
/// # Examples
///
/// ```rust
/// use hudsucker::{certificate_authority::RcgenAuthority, rustls};
/// use rustls_pemfile as pemfile;
///
/// let mut private_key_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.key");
/// let mut ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
/// let private_key = rustls::PrivateKey(
///     pemfile::pkcs8_private_keys(&mut private_key_bytes)
///         .next()
///         .unwrap()
///         .expect("Failed to parse private key")
///         .secret_pkcs8_der()
///         .to_vec(),
/// );
/// let ca_cert = rustls::Certificate(
///     pemfile::certs(&mut ca_cert_bytes)
///         .next()
///         .unwrap()
///         .expect("Failed to parse CA certificate")
///         .to_vec(),
/// );
///
/// let ca = RcgenAuthority::new(private_key, ca_cert, 1_000).unwrap();
/// ```
#[cfg_attr(docsrs, doc(cfg(feature = "rcgen-ca")))]
#[derive(Clone)]
pub struct RcgenAuthority {
    private_key: rustls::PrivateKey,
    ca_cert: rustls::Certificate,
    cache: Cache<Authority, Arc<ServerConfig>>,
}

impl RcgenAuthority {
    /// Attempts to create a new rcgen authority.
    ///
    /// # Errors
    ///
    /// This will return an error if the provided key or certificate is invalid, or if the key does
    /// not match the certificate.
    pub fn new(
        private_key: rustls::PrivateKey,
        ca_cert: rustls::Certificate,
        cache_size: u64,
    ) -> Result<RcgenAuthority, Error> {
        let ca = Self {
            private_key,
            ca_cert,
            cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(std::time::Duration::from_secs(CACHE_TTL))
                .build(),
        };

        ca.validate()?;
        Ok(ca)
    }

    fn gen_cert(&self, authority: &Authority) -> rustls::Certificate {
        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(thread_rng().gen::<u64>().into());

        let not_before = OffsetDateTime::now_utc() - Duration::seconds(NOT_BEFORE_OFFSET);
        params.not_before = not_before;
        params.not_after = not_before + Duration::seconds(TTL_SECS);

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, authority.host());
        params.distinguished_name = distinguished_name;

        params
            .subject_alt_names
            .push(SanType::DnsName(authority.host().to_owned()));

        let key_pair = KeyPair::from_der(&self.private_key.0).expect("Failed to parse private key");
        params.alg = key_pair
            .compatible_algs()
            .next()
            .expect("Failed to find compatible algorithm");
        params.key_pair = Some(key_pair);

        let key_pair = KeyPair::from_der(&self.private_key.0).expect("Failed to parse private key");

        let ca_cert_params = rcgen::CertificateParams::from_ca_cert_der(&self.ca_cert.0, key_pair)
            .expect("Failed to parse CA certificate");
        let ca_cert = rcgen::Certificate::from_params(ca_cert_params)
            .expect("Failed to generate CA certificate");

        let cert = rcgen::Certificate::from_params(params).expect("Failed to generate certificate");
        rustls::Certificate(
            cert.serialize_der_with_signer(&ca_cert)
                .expect("Failed to serialize certificate"),
        )
    }

    fn validate(&self) -> Result<(), RcgenError> {
        let key_pair = rcgen::KeyPair::from_der(&self.private_key.0)?;
        rcgen::CertificateParams::from_ca_cert_der(&self.ca_cert.0, key_pair)?;
        Ok(())
    }
}

#[async_trait]
impl CertificateAuthority for RcgenAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            debug!("Using cached server config");
            return server_cfg;
        }
        debug!("Generating server config");

        let certs = vec![self.gen_cert(authority)];

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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pemfile as pemfile;

    fn init_ca(cache_size: u64) -> RcgenAuthority {
        let mut private_key_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.key");
        let mut ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
        let private_key = rustls::PrivateKey(
            pemfile::pkcs8_private_keys(&mut private_key_bytes)
                .next()
                .unwrap()
                .expect("Failed to parse private key")
                .secret_pkcs8_der()
                .to_vec(),
        );
        let ca_cert = rustls::Certificate(
            pemfile::certs(&mut ca_cert_bytes)
                .next()
                .unwrap()
                .expect("Failed to parse CA certificate")
                .to_vec(),
        );

        RcgenAuthority::new(private_key, ca_cert, cache_size).unwrap()
    }

    #[test]
    fn error_for_invalid_key() {
        let ca = init_ca(0);
        let private_key = rustls::PrivateKey(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let result = RcgenAuthority::new(private_key, ca.ca_cert, 0);
        assert!(result.is_err());
    }

    #[test]
    fn error_for_invalid_ca_cert() {
        let ca = init_ca(0);
        let ca_cert = rustls::Certificate(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let result = RcgenAuthority::new(ca.private_key, ca_cert, 0);
        assert!(result.is_err());
    }

    #[test]
    fn unique_serial_numbers() {
        let ca = init_ca(0);

        let authority1 = Authority::from_static("example.com");
        let authority2 = Authority::from_static("example2.com");

        let c1 = ca.gen_cert(&authority1);
        let c2 = ca.gen_cert(&authority2);
        let c3 = ca.gen_cert(&authority1);
        let c4 = ca.gen_cert(&authority2);

        let (_, cert1) = x509_parser::parse_x509_certificate(&c1.0).unwrap();
        let (_, cert2) = x509_parser::parse_x509_certificate(&c2.0).unwrap();

        assert_ne!(cert1.raw_serial(), cert2.raw_serial());

        let (_, cert3) = x509_parser::parse_x509_certificate(&c3.0).unwrap();
        let (_, cert4) = x509_parser::parse_x509_certificate(&c4.0).unwrap();

        assert_ne!(cert3.raw_serial(), cert4.raw_serial());

        assert_ne!(cert1.raw_serial(), cert3.raw_serial());
        assert_ne!(cert2.raw_serial(), cert4.raw_serial());
    }
}
