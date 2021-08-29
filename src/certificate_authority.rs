use chrono::{Duration, Utc};
use http::uri::Authority;
use moka::future::Cache;
use rcgen::{KeyPair, SanType};
use rustls::{NoClientAuth, ServerConfig};

#[derive(Clone)]
pub struct CertificateAuthority {
    private_key: rustls::PrivateKey,
    cache: Cache<Authority, ServerConfig>,
}

impl CertificateAuthority {
    pub fn new(private_key: rustls::PrivateKey, cache_size: usize) -> CertificateAuthority {
        CertificateAuthority {
            private_key,
            cache: Cache::new(cache_size),
        }
    }

    fn gen_cert(&self, authority: &Authority) -> rustls::Certificate {
        let now = Utc::now();
        let mut params = rcgen::CertificateParams::default();
        params.not_before = now;
        params.not_after = now + Duration::weeks(52);
        params
            .subject_alt_names
            .push(SanType::DnsName(authority.host().to_string()));

        // This should never panic, as key has already been validated
        let key_pair = KeyPair::from_der(&self.private_key.0).expect("Failed to parse private key");
        params.alg = key_pair
            .compatible_algs()
            .next()
            .expect("Failed to find compatible algorithm");
        params.key_pair = Some(key_pair);

        let cert = rcgen::Certificate::from_params(params).expect("Failed to generate certificate");
        rustls::Certificate(
            cert.serialize_der()
                .expect("Failed to serialize certificate"),
        )
    }

    pub async fn gen_server_config(&self, authority: &Authority) -> ServerConfig {
        if let Some(server_cfg) = self.cache.get(authority) {
            return server_cfg;
        }

        let mut server_cfg = ServerConfig::new(NoClientAuth::new());
        let certs = vec![self.gen_cert(authority); 1];

        server_cfg
            .set_single_cert(certs, self.private_key.clone())
            .expect("Failed to set certificate");

        self.cache
            .insert(authority.clone(), server_cfg.clone())
            .await;

        server_cfg
    }
}
