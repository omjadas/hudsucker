use async_trait::async_trait;
use http::uri::Authority;
use rustls::ServerConfig;
use std::sync::Arc;

#[async_trait]
pub trait CertificateAuthority: Send + Sync + 'static {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig>;
}
