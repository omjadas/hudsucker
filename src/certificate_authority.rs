use chrono::{Duration, Utc};
use http::uri::Authority;
use rcgen::{KeyPair, SanType};
use rustls::{NoClientAuth, ServerConfig};

#[derive(Clone)]
pub struct CertificateAuthority {
    key_pair: rustls::PrivateKey,
}

impl CertificateAuthority {
    pub fn new(key_pair: rustls::PrivateKey) -> CertificateAuthority {
        CertificateAuthority { key_pair }
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
        let key_pair = KeyPair::from_der(&self.key_pair.0).unwrap();
        // TODO: not sure if this can panic or not
        params.alg = key_pair.compatible_algs().next().unwrap();
        params.key_pair = Some(key_pair);

        // TODO: handle Err
        let cert = rcgen::Certificate::from_params(params).unwrap();
        rustls::Certificate(cert.serialize_der().unwrap())
    }

    pub fn gen_server_config(&self, authority: &Authority) -> ServerConfig {
        let mut server_cfg = ServerConfig::new(NoClientAuth::new());
        let certs = vec![self.gen_cert(authority)];

        // TODO: handle Err
        server_cfg
            .set_single_cert(certs, self.key_pair.clone())
            .unwrap();

        server_cfg
    }
}
