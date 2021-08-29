use log::*;
use rustproxy::{rustls::internal::pemfile, *};
use std::{io::BufReader, net::SocketAddr};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install CTRL+C signal handler");
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let request_handler = |req| (req, None);
    let response_handler = |res| res;
    let incoming_message_handler = |msg| msg;
    let outgoing_message_handler = |msg| msg;

    let private_key_bytes: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCk0LLSzmrgpqzB\nX8zCjO24TH/+f0W1HObrEemQeHwBWyMQUkJ0SO2/6XK7Mu9Dtv8KAMEplUBKFpwn\nGphMN0JH9sbMXou2Ud6x22W0g4MScBzUMBEuNW2o7w+9oomQcz5Tvz/QRlPDLEIg\nwRNyDFXDjdsl9+5MNkPHKRKhHXnAvRjuAOjYcJl1yBAA7JiOhfWA+7o6pAkJR+EF\n3z4HsKoUcOXv9BnT+UU7ihADYyM4P0KBOPYRjKM2Tg7Dm5BeM1q97zwxAkhnPJ5J\nIYyxrBc2Znjw+E6H4stgIDShPQVqnrL+aBgp7n8lfYQTpOR2JJGIEZ/pHH0IuAOT\nUUkb9qkFAgMBAAECggEAe8z4RjkfNxh789VOLWVGu4VbL4PSjLTlD/Yoh4i5PRuE\nPyJLIKYXUGy+7bbY2vh+orjmX6Ho5L4PFaB4feeUNhI8Sg9Kyuy8ZsTypKGUtyjX\nvttMTHV9pcPNAxkwU/z8+FNUT9JD4PtBwPDG9oglc/r+foq5yS2Jw/QqNjO53Pf5\nJg+L92HtAhcQrtT6bmJ3mkLIn5rieEyqXZNbgvWokH3LPDmSKGk2ATsJKdSBna6a\n5LNzadAtuDxp0lQVvdxFoIhYB2crXhBeXj9ntoeQkaS6fv4ismj6YW/KoIgXx13y\nNbuDmsuORLR8Ph3802Kh+Ke0YZuXqDW/oZMJSShrkQKBgQDTbqpAJHtionXrQaSS\nTasE/IY2QXu9UgB1TsVsKC1l8KeGcf63qd3Mk5nI0f18ciQdi7wE3E3oyqdO7egN\nMV8g8iEJDuPlgn4dX5dGZsInBd00jIP3KGURZrwCGC8g42y+tyH8GliDSbw1jSJT\n8lZ5uUlKDpp3oniHddock+Na/wKBgQDHjnpn2bkTcU4tSV8mFRsPJ1yEsFsaK/ph\nUuSFhVATtBfGJ/ZZRaa+TnJQhzbKD+L6bJVXZca6iwzPW+aEOdG7d2elpSDuMUs4\noqlMux58l1mBxzG/euNQtSxN6HSA1LZNyZrjYvDGgIcUT2q7W66ybTIP9G0hUMtv\nmKgv+8iP+wKBgQCZW7vBqrSUZqKBcaudMxjJFSGEWRsXx1Ltw6UPPlUvi873hdfs\nABoROT5im23xxhjMFX7bR7B7GgMhDQ80AoutqfKsT1CeOHihdaSUPBS3mVlJtGJD\n89jbNllIa6JDiLJn4w2TfsiU8fbCIQy1NyHiSLMQNGd2PzKNjr4V3G8coQKBgBG2\nYsT+/T9tiivY3For+2ff7YVVhfCPwLyMt/3l9FKbZJTRDTulRASWP+1H4yQSPupN\nYwAL55S9LNjm5lIMM8J4+bkpLAAYXf3b6j0GStFyOZ6cSJ0fUjfirNkJbfXVa40B\n/P571LU5yUOTPPz+SUZLDOt/nYQcgMIaAauopIerAoGBAM/vVIQ4duY+hDsQqsCQ\nCxQrUAynSxKSDATNUBJVyrWAZ5JygRCVa2pUT5bG1RbvkNULfeDjgk//8Y1fol9d\nShkdsstV+80FMI7/44i71R5+HvDOoN0W8P2O79bIK7J+qboZ9DC02aDaYW313SJ0\nabhqThby5m1QdbkENMvdCoVm\n-----END PRIVATE KEY-----\n";
    let ca_cert_bytes: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIDoTCCAomgAwIBAgIGDhfQ/6XSMA0GCSqGSIb3DQEBCwUAMCgxEjAQBgNVBAMM\nCW1pdG1wcm94eTESMBAGA1UECgwJbWl0bXByb3h5MB4XDTE5MDIwNTEzMTU0NVoX\nDTIyMDIwNjEzMTU0NVowKDESMBAGA1UEAwwJbWl0bXByb3h5MRIwEAYDVQQKDAlt\naXRtcHJveHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCk0LLSzmrg\npqzBX8zCjO24TH/+f0W1HObrEemQeHwBWyMQUkJ0SO2/6XK7Mu9Dtv8KAMEplUBK\nFpwnGphMN0JH9sbMXou2Ud6x22W0g4MScBzUMBEuNW2o7w+9oomQcz5Tvz/QRlPD\nLEIgwRNyDFXDjdsl9+5MNkPHKRKhHXnAvRjuAOjYcJl1yBAA7JiOhfWA+7o6pAkJ\nR+EF3z4HsKoUcOXv9BnT+UU7ihADYyM4P0KBOPYRjKM2Tg7Dm5BeM1q97zwxAkhn\nPJ5JIYyxrBc2Znjw+E6H4stgIDShPQVqnrL+aBgp7n8lfYQTpOR2JJGIEZ/pHH0I\nuAOTUUkb9qkFAgMBAAGjgdAwgc0wDwYDVR0TAQH/BAUwAwEB/zARBglghkgBhvhC\nAQEEBAMCAgQweAYDVR0lBHEwbwYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcD\nBAYIKwYBBQUHAwgGCisGAQQBgjcCARUGCisGAQQBgjcCARYGCisGAQQBgjcKAwEG\nCisGAQQBgjcKAwMGCisGAQQBgjcKAwQGCWCGSAGG+EIEATAOBgNVHQ8BAf8EBAMC\nAQYwHQYDVR0OBBYEFLFXwBvekFD9FA8KXOhYwe2c8sJRMA0GCSqGSIb3DQEBCwUA\nA4IBAQAhsHypdSKBHhxq2xPUfM7J3o2CYtIvJMc8ZAswrRMBx9i3IkGPwxjz1xTt\nkDQAw4ioHIa7S8m/bGap/PLeN0tzUnRa7fxNjvj3R0+tTp5d3JpBy7DngfPNotNI\nXiXmzES4Clx/Wjy/7ObKLdBrr4f9sVyB+ft9NIyRqRjl4uQOHdzCfLDcuglK5Wt6\nt3y+gXOCXZ4TvPRLmYeLCv7M8+fdwxkf9hMWkNWH8+pZvHhIS/Bo+BRaBYJmuktg\nloLPkWsOboeL+sotP25EFQFTxoF2yGJQi+SY9hFxnmOdBuF5IWsbspYJYr1IRkAE\nVm49xNYbNyz5rSKt2zXqF9G5cWqB\n-----END CERTIFICATE-----\n";
    let private_key = pemfile::pkcs8_private_keys(&mut BufReader::new(private_key_bytes))
        .unwrap()
        .remove(0);
    let ca_cert = pemfile::certs(&mut BufReader::new(ca_cert_bytes))
        .unwrap()
        .remove(0);

    let proxy_config = ProxyConfig {
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 3000)),
        shutdown_signal: shutdown_signal(),
        request_handler,
        response_handler,
        incoming_message_handler,
        outgoing_message_handler,
        private_key,
        ca_cert,
        upstream_proxy: None,
        cache_size: None,
    };

    if let Err(e) = start_proxy(proxy_config).await {
        error!("{}", e);
    }
}
