use futures::try_join;
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    hyper_proxy::{Intercept, Proxy as UpstreamProxy},
    rustls::internal::pemfile,
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

    let mut private_key_bytes: &[u8] = include_bytes!("ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("ca/hudsucker.pem");
    let private_key = pemfile::pkcs8_private_keys(&mut private_key_bytes)
        .expect("Failed to parse private key")
        .remove(0);
    let ca_cert = pemfile::certs(&mut ca_cert_bytes)
        .expect("Failed to parse CA certificate")
        .remove(0);

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy_config = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3001)),
        shutdown_signal: shutdown_signal(),
        http_handler: LogHandler {},
        incoming_message_handler: NoopMessageHandler::new(),
        outgoing_message_handler: NoopMessageHandler::new(),
        upstream_proxy: None,
        ca: ca.clone(),
    };

    let proxy_config_2 = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        http_handler: NoopHttpHandler::new(),
        incoming_message_handler: NoopMessageHandler::new(),
        outgoing_message_handler: NoopMessageHandler::new(),
        shutdown_signal: shutdown_signal(),
        upstream_proxy: Some(UpstreamProxy::new(
            Intercept::All,
            "http://127.0.0.1:3001"
                .parse()
                .expect("Failed to parse upstream proxy URI"),
        )),
        ca,
    };

    let proxy_1 = start_proxy(proxy_config);
    let proxy_2 = start_proxy(proxy_config_2);

    if let Err(e) = try_join!(proxy_1, proxy_2) {
        error!("{}", e);
    };
}
