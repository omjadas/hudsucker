use hudsucker::{
    async_trait::async_trait,
    certificate_authority::OpensslAuthority,
    hyper::{Body, Request, Response},
    openssl::{hash::MessageDigest, pkey::PKey, x509::X509},
    *,
};
use log::*;
use std::net::SocketAddr;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct LogHandler {}

#[async_trait]
impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        println!("{:?}", req);
        RequestOrResponse::Request(req)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        println!("{:?}", res);
        res
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let private_key_bytes: &[u8] = include_bytes!("ca/hudsucker.key");
    let ca_cert_bytes: &[u8] = include_bytes!("ca/hudsucker.pem");
    let private_key =
        PKey::private_key_from_pem(private_key_bytes).expect("Failed to parse private key");
    let ca_cert = X509::from_pem(ca_cert_bytes).expect("Failed to parse CA certificate");

    let ca = OpensslAuthority::new(private_key, ca_cert, MessageDigest::sha256(), 1_000);

    let proxy_config = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        shutdown_signal: shutdown_signal(),
        http_handler: LogHandler {},
        incoming_message_handler: NoopMessageHandler::new(),
        outgoing_message_handler: NoopMessageHandler::new(),
        upstream_proxy: None,
        ca,
    };

    if let Err(e) = start_proxy(proxy_config).await {
        error!("{}", e);
    }
}
