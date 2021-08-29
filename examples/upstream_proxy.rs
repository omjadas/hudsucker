use futures::try_join;
use hyper_proxy::{Intercept, Proxy};
use rustproxy::*;
use std::net::SocketAddr;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let req_handler = |req| {
        println!("{:?}", req);
        (req, None)
    };

    let res_handler = |res| {
        println!("{:?}", res);
        res
    };

    let bytes: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCk0LLSzmrgpqzB\nX8zCjO24TH/+f0W1HObrEemQeHwBWyMQUkJ0SO2/6XK7Mu9Dtv8KAMEplUBKFpwn\nGphMN0JH9sbMXou2Ud6x22W0g4MScBzUMBEuNW2o7w+9oomQcz5Tvz/QRlPDLEIg\nwRNyDFXDjdsl9+5MNkPHKRKhHXnAvRjuAOjYcJl1yBAA7JiOhfWA+7o6pAkJR+EF\n3z4HsKoUcOXv9BnT+UU7ihADYyM4P0KBOPYRjKM2Tg7Dm5BeM1q97zwxAkhnPJ5J\nIYyxrBc2Znjw+E6H4stgIDShPQVqnrL+aBgp7n8lfYQTpOR2JJGIEZ/pHH0IuAOT\nUUkb9qkFAgMBAAECggEAe8z4RjkfNxh789VOLWVGu4VbL4PSjLTlD/Yoh4i5PRuE\nPyJLIKYXUGy+7bbY2vh+orjmX6Ho5L4PFaB4feeUNhI8Sg9Kyuy8ZsTypKGUtyjX\nvttMTHV9pcPNAxkwU/z8+FNUT9JD4PtBwPDG9oglc/r+foq5yS2Jw/QqNjO53Pf5\nJg+L92HtAhcQrtT6bmJ3mkLIn5rieEyqXZNbgvWokH3LPDmSKGk2ATsJKdSBna6a\n5LNzadAtuDxp0lQVvdxFoIhYB2crXhBeXj9ntoeQkaS6fv4ismj6YW/KoIgXx13y\nNbuDmsuORLR8Ph3802Kh+Ke0YZuXqDW/oZMJSShrkQKBgQDTbqpAJHtionXrQaSS\nTasE/IY2QXu9UgB1TsVsKC1l8KeGcf63qd3Mk5nI0f18ciQdi7wE3E3oyqdO7egN\nMV8g8iEJDuPlgn4dX5dGZsInBd00jIP3KGURZrwCGC8g42y+tyH8GliDSbw1jSJT\n8lZ5uUlKDpp3oniHddock+Na/wKBgQDHjnpn2bkTcU4tSV8mFRsPJ1yEsFsaK/ph\nUuSFhVATtBfGJ/ZZRaa+TnJQhzbKD+L6bJVXZca6iwzPW+aEOdG7d2elpSDuMUs4\noqlMux58l1mBxzG/euNQtSxN6HSA1LZNyZrjYvDGgIcUT2q7W66ybTIP9G0hUMtv\nmKgv+8iP+wKBgQCZW7vBqrSUZqKBcaudMxjJFSGEWRsXx1Ltw6UPPlUvi873hdfs\nABoROT5im23xxhjMFX7bR7B7GgMhDQ80AoutqfKsT1CeOHihdaSUPBS3mVlJtGJD\n89jbNllIa6JDiLJn4w2TfsiU8fbCIQy1NyHiSLMQNGd2PzKNjr4V3G8coQKBgBG2\nYsT+/T9tiivY3For+2ff7YVVhfCPwLyMt/3l9FKbZJTRDTulRASWP+1H4yQSPupN\nYwAL55S9LNjm5lIMM8J4+bkpLAAYXf3b6j0GStFyOZ6cSJ0fUjfirNkJbfXVa40B\n/P571LU5yUOTPPz+SUZLDOt/nYQcgMIaAauopIerAoGBAM/vVIQ4duY+hDsQqsCQ\nCxQrUAynSxKSDATNUBJVyrWAZ5JygRCVa2pUT5bG1RbvkNULfeDjgk//8Y1fol9d\nShkdsstV+80FMI7/44i71R5+HvDOoN0W8P2O79bIK7J+qboZ9DC02aDaYW313SJ0\nabhqThby5m1QdbkENMvdCoVm\n-----END PRIVATE KEY-----\n";
    let key = rustls::internal::pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(bytes))
        .unwrap()
        .remove(0);

    let proxy_config = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3001)),
        shutdown_signal: shutdown_signal(),
        request_handler: req_handler,
        response_handler: res_handler,
        incoming_message_handler: |msg| msg,
        outgoing_message_handler: |msg| msg,
        private_key: key.clone(),
        upstream_proxy: None,
        cache_size: None,
    };

    let proxy_config_2 = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        request_handler: |req| (req, None),
        response_handler: |res| res,
        incoming_message_handler: |msg| msg,
        outgoing_message_handler: |msg| msg,
        shutdown_signal: shutdown_signal(),
        private_key: key,
        upstream_proxy: Some(Proxy::new(
            Intercept::All,
            "http://127.0.0.1:3001".parse().unwrap(),
        )),
        cache_size: None,
    };

    let proxy_1 = start_proxy(proxy_config);
    let proxy_2 = start_proxy(proxy_config_2);

    if let Err(e) = try_join!(proxy_1, proxy_2) {
        println!("{:?}", e);
    };
}
