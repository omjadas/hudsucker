pub mod lib;

use lib::*;
use std::net::SocketAddr;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    let req_handler: RequestHandler = |req| {
        println!("{:?}", req);
        (req, None)
    };

    let res_handler: ResponseHandler = |res| {
        println!("{:?}", res);
        res
    };

    let proxy_config = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        shutdown_signal: shutdown_signal(),
        request_handler: Some(req_handler),
        response_handler: Some(res_handler),
    };

    if let Err(e) = start_proxy(proxy_config).await {
        eprintln!("{}", e);
    }
}
