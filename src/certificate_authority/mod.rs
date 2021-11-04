#[cfg(feature = "openssl-certs")]
mod openssl_authority;
#[cfg(feature = "rcgen-certs")]
mod rcgen_authority;

use async_trait::async_trait;
use http::uri::Authority;
use rustls::ServerConfig;
use std::sync::Arc;

#[cfg(feature = "openssl-certs")]
#[cfg_attr(docsrs, doc(cfg(feature = "openssl-certs")))]
pub use openssl_authority::*;
#[cfg(feature = "rcgen-certs")]
#[cfg_attr(docsrs, doc(cfg(feature = "rcgen-certs")))]
pub use rcgen_authority::*;

/// Issues certificates for use when communicating with clients.
///
/// Clients should be configured to either trust the provided root certificate, or to ignore
/// certificate errors.
#[async_trait]
pub trait CertificateAuthority: Send + Sync + 'static {
    /// Generate ServerConfig for use with rustls.
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig>;
}
