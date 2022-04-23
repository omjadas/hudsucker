use crate::{
    certificate_authority::CertificateAuthority, HttpContext, HttpHandler, RequestOrResponse,
    Rewind, WebSocketContext, WebSocketHandler,
};
use futures::{Sink, SinkExt, Stream, StreamExt};
use http::uri::PathAndQuery;
use hyper::{
    client::connect::Connect, header::HeaderValue, server::conn::Http, service::service_fn,
    upgrade::Upgraded, Body, Client, Method, Request, Response, Uri,
};
use std::{future::Future, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    tungstenite::{self, Message},
    Connector, WebSocketStream,
};
use tracing::*;

async fn trace_future<T>(span: Span, fut: impl Future<Output = T>) -> T {
    fut.instrument(span).await
}

fn spawn_with_trace<T: Send + Sync + 'static>(
    span: Span,
    fut: impl Future<Output = T> + Send + 'static,
) -> JoinHandle<T> {
    tokio::spawn(trace_future(span, fut))
}

macro_rules! span_from_request {
    ($name:expr, $req:expr, $client_addr:expr) => {{
        info_span!(
            $name,
            version = ?$req.version(),
            method = %$req.method(),
            uri = %$req.uri(),
            client_addr = %$client_addr
        )
    }};
}

pub(crate) struct InternalProxy<C, CA, H, W>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    pub ca: Arc<CA>,
    pub client: Client<C>,
    pub http_handler: H,
    pub websocket_handler: W,
    pub websocket_connector: Option<Connector>,
    pub client_addr: SocketAddr,
}

impl<C, CA, H, W> Clone for InternalProxy<C, CA, H, W>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    fn clone(&self) -> Self {
        InternalProxy {
            ca: Arc::clone(&self.ca),
            client: self.client.clone(),
            http_handler: self.http_handler.clone(),
            websocket_handler: self.websocket_handler.clone(),
            websocket_connector: self.websocket_connector.clone(),
            client_addr: self.client_addr,
        }
    }
}

impl<C, CA, H, W> InternalProxy<C, CA, H, W>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    pub(crate) async fn proxy(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        }
    }

    async fn process_request(mut self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let span = span_from_request!("process_request", req, self.client_addr);
        let fut = async move {
            let ctx = HttpContext {
                client_addr: self.client_addr,
            };

            let req = match self.http_handler.handle_request(&ctx, req).await {
                RequestOrResponse::Request(req) => normalize_request(req),
                RequestOrResponse::Response(res) => return Ok(res),
            };

            if hyper_tungstenite::is_upgrade_request(&req) {
                let (parts, body) = req.into_parts();

                let scheme = if parts.uri.scheme().unwrap_or(&http::uri::Scheme::HTTP)
                    == &http::uri::Scheme::HTTP
                {
                    "ws"
                } else {
                    "wss"
                };

                let authority = parts
                    .uri
                    .authority()
                    .expect("Authority not included in request")
                    .clone();

                let host = HeaderValue::try_from(authority.host()).expect("Invalid host");

                let uri = Uri::builder()
                    .scheme(scheme)
                    .authority(authority)
                    .path_and_query(
                        parts
                            .uri
                            .path_and_query()
                            .unwrap_or(&PathAndQuery::from_static("/"))
                            .clone(),
                    )
                    .build()
                    .expect("Failed to build URI for websocket connection");

                let ws_req = {
                    let mut builder = Request::builder()
                        .version(parts.version)
                        .method(parts.method.clone())
                        .uri(uri);

                    if let Some(headers) = builder.headers_mut() {
                        *headers = parts.headers.clone();
                        headers.append(hyper::header::HOST, host);
                    }

                    builder.body(()).expect("Failed to build websocket request")
                };

                let req = Request::from_parts(parts, body);
                let span = span_from_request!("websocket", req, self.client_addr);
                let (res, websocket) =
                    hyper_tungstenite::upgrade(req, None).expect("Request has missing headers");

                let fut = async move {
                    match websocket.await {
                        Ok(ws) => {
                            if let Err(e) = self.handle_websocket(ws, ws_req).await {
                                error!("Failed to handle websocket: {:?}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to upgrade to websocket: {}", e);
                        }
                    }
                };

                spawn_with_trace(span, fut);
                return Ok(res);
            }

            let res = self.client.request(req).await?;
            Ok(self.http_handler.handle_response(&ctx, res).await)
        };

        trace_future(span, fut).await
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let span = span_from_request!("process_connect", req, self.client_addr);
        let authority = req
            .uri()
            .authority()
            .expect("URI does not contain authority")
            .clone();

        let fut = async move {
            match hyper::upgrade::on(req).await {
                Ok(mut upgraded) => {
                    let mut buffer = [0; 4];
                    let bytes_read = match upgraded.read(&mut buffer).await {
                        Ok(bytes_read) => bytes_read,
                        Err(e) => {
                            error!("Failed to read from upgraded connection: {}", e);
                            return;
                        }
                    };

                    let upgraded = Rewind::new_buffered(
                        upgraded,
                        bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                    );

                    if bytes_read == 4 && buffer == *b"GET " {
                        if let Err(e) = self.serve_stream(upgraded, http::uri::Scheme::HTTP).await {
                            error!("Websocket connect error: {}", e);
                        }
                    } else if bytes_read >= 2 && buffer[..2] == *b"\x16\x03" {
                        let server_config = self.ca.gen_server_config(&authority).await;
                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                error!("Failed to establish TLS connection: {}", e);
                                return;
                            }
                        };

                        if let Err(e) = self.serve_stream(stream, http::uri::Scheme::HTTPS).await {
                            if !e.to_string().starts_with("error shutting down connection") {
                                error!("HTTPS connect error: {}", e);
                            }
                        }
                    } else {
                        error!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            &buffer[..bytes_read]
                        );
                    }
                }
                Err(e) => error!("Upgrade error: {}", e),
            };
        };

        spawn_with_trace(span, fut);
        Ok(Response::new(Body::empty()))
    }

    async fn handle_websocket(
        self,
        server_socket: WebSocketStream<Upgraded>,
        req: Request<()>,
    ) -> Result<(), tungstenite::Error> {
        let uri = req.uri().clone();

        #[cfg(any(feature = "rustls-client", feature = "native-tls-client"))]
        let (client_socket, _) =
            tokio_tungstenite::connect_async_tls_with_config(req, None, self.websocket_connector)
                .await?;

        #[cfg(not(any(feature = "rustls-client", feature = "native-tls-client")))]
        let (client_socket, _) = tokio_tungstenite::connect_async(req).await?;

        let (server_sink, server_stream) = server_socket.split();
        let (client_sink, client_stream) = client_socket.split();

        let InternalProxy {
            websocket_handler, ..
        } = self;

        spawn_message_forwarder(
            server_stream,
            client_sink,
            websocket_handler.clone(),
            WebSocketContext::ServerToClient {
                src: uri.clone(),
                dst: self.client_addr,
            },
        );

        spawn_message_forwarder(
            client_stream,
            server_sink,
            websocket_handler,
            WebSocketContext::ClientToServer {
                src: self.client_addr,
                dst: uri,
            },
        );

        Ok(())
    }

    async fn serve_stream<I>(self, stream: I, scheme: http::uri::Scheme) -> Result<(), hyper::Error>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                let authority = parts
                    .headers
                    .get(hyper::header::HOST)
                    .expect("Host is a required header")
                    .to_str()
                    .expect("Failed to convert host to str");

                parts.uri = {
                    let parts = parts.uri.into_parts();

                    Uri::builder()
                        .scheme(scheme.clone())
                        .authority(authority)
                        .path_and_query(
                            parts
                                .path_and_query
                                .unwrap_or_else(|| PathAndQuery::from_static("/")),
                        )
                        .build()
                        .expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };

            self.clone().process_request(req)
        });

        Http::new()
            .serve_connection(stream, service)
            .with_upgrades()
            .await
    }
}

fn spawn_message_forwarder(
    mut stream: impl Stream<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
    mut sink: impl Sink<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    mut handler: impl WebSocketHandler,
    ctx: WebSocketContext,
) {
    let span = info_span!("message_forwarder", context = ?ctx);

    let fut = async move {
        while let Some(message) = stream.next().await {
            match message {
                Ok(message) => {
                    let message = match handler.handle_message(&ctx, message).await {
                        Some(message) => message,
                        None => continue,
                    };

                    match sink.send(message).await {
                        Err(tungstenite::Error::ConnectionClosed) => (),
                        Err(e) => error!("Websocket send error: {}", e),
                        _ => (),
                    }
                }
                Err(e) => {
                    error!("Websocket message error: {}", e);

                    match sink.send(Message::Close(None)).await {
                        Err(tungstenite::Error::ConnectionClosed) => (),
                        Err(e) => error!("Websocket close error: {}", e),
                        _ => (),
                    };

                    break;
                }
            }
        }
    };

    spawn_with_trace(span, fut);
}

fn normalize_request<T>(mut req: Request<T>) -> Request<T> {
    // Hyper will automatically add a Host header if needed.
    req.headers_mut().remove(hyper::header::HOST);

    // HTTP/2.0 supports multiple cookie headers, but HTTP/1.x only supports one.
    if let hyper::header::Entry::Occupied(cookies) = req.headers_mut().entry(hyper::header::COOKIE)
    {
        let joined_cookies: String = cookies
            .remove_entry_mult()
            .1
            .map(|c| c.to_str().unwrap_or("").to_string())
            .collect::<Vec<_>>()
            .join("; ");

        req.headers_mut().insert(
            hyper::header::COOKIE,
            joined_cookies.try_into().expect("Failed to join cookies"),
        );
    }

    let (mut parts, body) = req.into_parts();
    parts.version = hyper::Version::HTTP_11;
    Request::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod normalize_request {
        use super::*;

        #[test]
        fn removes_host_header() {
            let req = Request::builder()
                .uri("http://example.com/")
                .header(hyper::header::HOST, "example.com")
                .body(())
                .unwrap();

            let req = normalize_request(req);

            assert_eq!(req.headers().get(hyper::header::HOST), None);
        }

        #[test]
        fn joins_cookies() {
            let req = Request::builder()
                .uri("http://example.com/")
                .header(hyper::header::COOKIE, "foo=bar")
                .header(hyper::header::COOKIE, "baz=qux")
                .body(())
                .unwrap();

            let req = normalize_request(req);

            assert_eq!(
                req.headers().get(hyper::header::COOKIE),
                Some(&"foo=bar; baz=qux".parse().unwrap())
            );
        }
    }
}
