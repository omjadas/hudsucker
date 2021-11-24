#[cfg(feature = "openssl-certs")]
mod openssl_authority;
#[cfg(feature = "rcgen-certs")]
mod rcgen_authority;

use async_trait::async_trait;
use http::uri::Authority;
use std::sync::Arc;
use tokio_rustls::rustls::ServerConfig;

#[cfg(feature = "openssl-certs")]
pub use openssl_authority::*;
#[cfg(feature = "rcgen-certs")]
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
