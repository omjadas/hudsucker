mod certificate_authority;
mod error;
mod rewind;
use rewind::Rewind;

use certificate_authority::CertificateAuthority;
use error::Error;
use futures::{sink::SinkExt, stream::StreamExt};
use hyper::{
    client::HttpConnector,
    server::conn::Http,
    service::{make_service_fn, service_fn},
    upgrade::Upgraded,
    Body, Client, Method, Request, Response, Server,
};
use hyper_proxy::ProxyConnector;
use hyper_rustls::HttpsConnector;
use log::*;
use rcgen::RcgenError;
use rustls::ClientConfig;
use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{connect_async, WebSocketStream};

pub type RequestHandler = fn(Request<Body>) -> (Request<Body>, Option<Response<Body>>);
pub type ResponseHandler = fn(Response<Body>) -> Response<Body>;

#[derive(Clone)]
pub enum HttpClient {
    Proxy(Client<ProxyConnector<HttpsConnector<HttpConnector>>>),
    Https(Client<HttpsConnector<HttpConnector>>),
}

#[derive(Clone)]
pub struct ProxyConfig<F: Future<Output = ()>> {
    pub listen_addr: SocketAddr,
    pub shutdown_signal: F,
    pub private_key: rustls::PrivateKey,
    pub request_handler: Option<RequestHandler>,
    pub response_handler: Option<ResponseHandler>,
    pub upstream_proxy: Option<hyper_proxy::Proxy>,
}

#[derive(Clone)]
struct ProxyState {
    pub ca: CertificateAuthority,
    pub client: HttpClient,
    pub request_handler: RequestHandler,
    pub response_handler: ResponseHandler,
}

pub async fn start_proxy<F>(
    ProxyConfig {
        listen_addr,
        shutdown_signal,
        private_key,
        request_handler,
        response_handler,
        upstream_proxy,
    }: ProxyConfig<F>,
) -> Result<(), Error>
where
    F: Future<Output = ()>,
{
    validate_key(&private_key)?;

    let client = gen_client(upstream_proxy);
    let ca = CertificateAuthority::new(private_key, 1_000);
    let request_handler = request_handler.unwrap_or(|req| (req, None));
    let response_handler = response_handler.unwrap_or(|res| res);

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        let ca = ca.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy(
                    ProxyState {
                        ca: ca.clone(),
                        client: client.clone(),
                        request_handler,
                        response_handler,
                    },
                    req,
                )
            }))
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|err| err.into())
}

fn gen_client(upstream_proxy: Option<hyper_proxy::Proxy>) -> HttpClient {
    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let mut config = ClientConfig::new();
    config.ct_logs = Some(&ct_logs::LOGS);
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    let https: HttpsConnector<HttpConnector> = (http, config).into();

    if let Some(proxy) = upstream_proxy {
        let connector = ProxyConnector::from_proxy(https, proxy).unwrap();
        return HttpClient::Proxy(
            Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(connector),
        );
    } else {
        HttpClient::Https(
            Client::builder()
                .http1_title_case_headers(true)
                .http1_preserve_header_case(true)
                .build(https),
        )
    }
}

async fn proxy(state: ProxyState, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    if req.method() == Method::CONNECT {
        process_connect(state, req).await
    } else {
        process_request(state, req).await
    }
}

async fn process_request(
    state: ProxyState,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let (req, res) = (state.request_handler)(req);
    if let Some(res) = res {
        return Ok(res);
    }

    if hyper_tungstenite::is_upgrade_request(&req) {
        let scheme = if req.uri().scheme().unwrap() == "http" {
            "ws"
        } else {
            "wss"
        };

        let uri = http::uri::Builder::new()
            .scheme(scheme)
            .authority(req.uri().authority().unwrap().to_owned())
            .path_and_query(req.uri().path_and_query().unwrap().to_owned())
            .build()
            .unwrap();

        let (res, websocket) = hyper_tungstenite::upgrade(req, None).unwrap();

        tokio::spawn(async move {
            let server_socket = websocket.await.unwrap();
            handle_websocket(server_socket, &uri).await;
        });

        return Ok(res);
    }

    let res = match state.client {
        HttpClient::Proxy(client) => client.request(req).await?,
        HttpClient::Https(client) => client.request(req).await?,
    };

    Ok((state.response_handler)(res))
}

async fn process_connect(
    state: ProxyState,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    tokio::task::spawn(async move {
        let authority = req.uri().authority().unwrap();
        let server_config = Arc::new(state.ca.gen_server_config(authority).await);

        match hyper::upgrade::on(req).await {
            Ok(mut upgraded) => {
                // TODO: handle Err
                let mut buffer = [0; 3];
                let bytes_read = upgraded.read(&mut buffer).await.unwrap();
                let upgraded = Rewind::new_buffered(
                    upgraded,
                    bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                );

                if bytes_read == 3 && buffer == [71, 69, 84] {
                    if let Err(e) = serve_websocket(state, upgraded).await {
                        error!("websocket error: {}", e);
                    }
                } else {
                    let stream = TlsAcceptor::from(server_config)
                        .accept(upgraded)
                        .await
                        .unwrap();

                    if let Err(e) = serve_https(state, stream).await {
                        let e_string = e.to_string();
                        if !e_string.starts_with("error shutting down connection") {
                            error!("https error: {}", e);
                        }
                    }
                }
            }
            Err(e) => error!("upgrade error: {}", e),
        };
    });

    Ok(Response::new(Body::empty()))
}

async fn handle_websocket(server_socket: WebSocketStream<Upgraded>, uri: &http::Uri) {
    let (client_socket, _) = connect_async(uri).await.unwrap();

    let (mut server_sink, mut server_stream) = server_socket.split();
    let (mut client_sink, mut client_stream) = client_socket.split();

    tokio::spawn(async move {
        while let Some(message) = server_stream.next().await {
            // TODO: handle Err
            client_sink.send(message.unwrap()).await.unwrap();
        }
    });

    tokio::spawn(async move {
        while let Some(message) = client_stream.next().await {
            // TODO: handle Err
            server_sink.send(message.unwrap()).await.unwrap();
        }
    });
}

async fn serve_websocket(state: ProxyState, stream: Rewind<Upgraded>) -> Result<(), hyper::Error> {
    let service = service_fn(|req| {
        let authority = req.headers().get("host").unwrap().to_str().unwrap();
        let uri = http::uri::Builder::new()
            .scheme("http")
            .authority(authority)
            .path_and_query(req.uri().to_string())
            .build()
            .unwrap();
        let (mut parts, body) = req.into_parts();
        parts.uri = uri;
        let req = Request::from_parts(parts, body);
        process_request(state.clone(), req)
    });

    Http::new()
        .serve_connection(stream, service)
        .with_upgrades()
        .await
}

async fn serve_https(
    state: ProxyState,
    stream: tokio_rustls::server::TlsStream<Rewind<Upgraded>>,
) -> Result<(), hyper::Error> {
    let service = service_fn(|req| {
        let authority = req.headers().get("host").unwrap().to_str().unwrap();
        let uri = http::uri::Builder::new()
            .scheme("https")
            .authority(authority)
            .path_and_query(req.uri().to_string())
            .build()
            .unwrap();
        let (mut parts, body) = req.into_parts();
        parts.uri = uri;
        let req = Request::from_parts(parts, body);
        process_request(state.clone(), req)
    });
    Http::new()
        .serve_connection(stream, service)
        .with_upgrades()
        .await
}

pub fn validate_key(key_pair: &rustls::PrivateKey) -> Result<(), RcgenError> {
    rcgen::KeyPair::from_der(&key_pair.0)?;
    Ok(())
}
