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

        // This should never panic
        let key_pair = KeyPair::from_der(&self.private_key.0).unwrap();
        // TODO: not sure if this can panic
        params.alg = key_pair.compatible_algs().next().unwrap();
        params.key_pair = Some(key_pair);

        // TODO: not sure if this can panic
        let cert = rcgen::Certificate::from_params(params).unwrap();
        rustls::Certificate(cert.serialize_der().unwrap())
    }

    pub async fn gen_server_config(&self, authority: &Authority) -> ServerConfig {
        if let Some(server_cfg) = self.cache.get(authority) {
            return server_cfg;
        }

        let mut server_cfg = ServerConfig::new(NoClientAuth::new());
        let certs = vec![self.gen_cert(authority); 1];

        // TODO: handle Err
        server_cfg
            .set_single_cert(certs, self.private_key.clone())
            .unwrap();

        self.cache
            .insert(authority.clone(), server_cfg.clone())
            .await;

        server_cfg
    }
}
