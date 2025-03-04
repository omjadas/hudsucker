use crate::certificate_authority::{CACHE_TTL, CertificateAuthority, NOT_BEFORE_OFFSET, TTL_SECS};
use http::uri::Authority;
use moka::future::Cache;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rand,
    x509::{X509, X509Builder, X509NameBuilder, extension::SubjectAlternativeName},
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio_rustls::rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tracing::debug;

/// Issues certificates for use when communicating with clients.
///
/// Issues certificates for communicating with clients over TLS. Certificates are cached in memory
/// up to a max size that is provided when creating the authority. Certificates are generated using
/// the `openssl` crate.
///
/// # Examples
///
/// ```rust
/// use hudsucker::{
///     certificate_authority::OpensslAuthority,
///     openssl::{hash::MessageDigest, pkey::PKey, x509::X509},
///     rustls::crypto::aws_lc_rs,
/// };
///
/// let private_key_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.key");
/// let ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
/// let private_key = PKey::private_key_from_pem(private_key_bytes).unwrap();
/// let ca_cert = X509::from_pem(ca_cert_bytes).unwrap();
///
/// let ca = OpensslAuthority::new(
///     private_key,
///     ca_cert,
///     MessageDigest::sha256(),
///     1_000,
///     aws_lc_rs::default_provider(),
/// );
/// ```
pub struct OpensslAuthority {
    pkey: PKey<Private>,
    private_key: PrivateKeyDer<'static>,
    ca_cert: X509,
    hash: MessageDigest,
    cache: Cache<Authority, Arc<ServerConfig>>,
    provider: Arc<CryptoProvider>,
}

impl OpensslAuthority {
    /// Creates a new openssl authority.
    pub fn new(
        pkey: PKey<Private>,
        ca_cert: X509,
        hash: MessageDigest,
        cache_size: u64,
        provider: CryptoProvider,
    ) -> Self {
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            pkey.private_key_to_pkcs8()
                .expect("Failed to encode private key"),
        ));

        Self {
            pkey,
            private_key,
            ca_cert,
            hash,
            cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(Duration::from_secs(CACHE_TTL))
                .build(),
            provider: Arc::new(provider),
        }
    }

    fn gen_cert(&self, authority: &Authority) -> Result<CertificateDer<'static>, ErrorStack> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", authority.host())?;
        let name = name_builder.build();

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_version(2)?;

        let not_before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to determine current UNIX time")
            .as_secs() as i64
            - NOT_BEFORE_OFFSET;
        x509_builder.set_not_before(Asn1Time::from_unix(not_before)?.as_ref())?;
        x509_builder.set_not_after(Asn1Time::from_unix(not_before + TTL_SECS)?.as_ref())?;

        x509_builder.set_pubkey(&self.pkey)?;
        x509_builder.set_issuer_name(self.ca_cert.subject_name())?;

        let alternative_name = SubjectAlternativeName::new()
            .dns(authority.host())
            .build(&x509_builder.x509v3_context(Some(&self.ca_cert), None))?;
        x509_builder.append_extension(alternative_name)?;

        let mut serial_number = [0; 16];
        rand::rand_bytes(&mut serial_number)?;

        let serial_number = BigNum::from_slice(&serial_number)?;
        let serial_number = Asn1Integer::from_bn(&serial_number)?;
        x509_builder.set_serial_number(&serial_number)?;

        x509_builder.sign(&self.pkey, self.hash)?;
        let x509 = x509_builder.build();
        Ok(CertificateDer::from(x509.to_der()?))
    }
}

impl CertificateAuthority for OpensslAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            debug!("Using cached server config");
            return server_cfg;
        }
        debug!("Generating server config");

        let certs = vec![
            self.gen_cert(authority)
                .unwrap_or_else(|_| panic!("Failed to generate certificate for {}", authority)),
        ];

        let mut server_cfg = ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .expect("Failed to specify protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone_key())
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
    use tokio_rustls::rustls::crypto::aws_lc_rs;

    fn build_ca(cache_size: u64) -> OpensslAuthority {
        let private_key_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.key");
        let ca_cert_bytes: &[u8] = include_bytes!("../../examples/ca/hudsucker.cer");
        let private_key =
            PKey::private_key_from_pem(private_key_bytes).expect("Failed to parse private key");
        let ca_cert = X509::from_pem(ca_cert_bytes).expect("Failed to parse CA certificate");

        OpensslAuthority::new(
            private_key,
            ca_cert,
            MessageDigest::sha256(),
            cache_size,
            aws_lc_rs::default_provider(),
        )
    }

    #[test]
    fn unique_serial_numbers() {
        let ca = build_ca(0);

        let authority1 = Authority::from_static("example.com");
        let authority2 = Authority::from_static("example2.com");

        let c1 = ca.gen_cert(&authority1).unwrap();
        let c2 = ca.gen_cert(&authority2).unwrap();
        let c3 = ca.gen_cert(&authority1).unwrap();
        let c4 = ca.gen_cert(&authority2).unwrap();

        let (_, cert1) = x509_parser::parse_x509_certificate(&c1).unwrap();
        let (_, cert2) = x509_parser::parse_x509_certificate(&c2).unwrap();

        assert_ne!(cert1.raw_serial(), cert2.raw_serial());

        let (_, cert3) = x509_parser::parse_x509_certificate(&c3).unwrap();
        let (_, cert4) = x509_parser::parse_x509_certificate(&c4).unwrap();

        assert_ne!(cert3.raw_serial(), cert4.raw_serial());

        assert_ne!(cert1.raw_serial(), cert3.raw_serial());
        assert_ne!(cert2.raw_serial(), cert4.raw_serial());
    }
}
