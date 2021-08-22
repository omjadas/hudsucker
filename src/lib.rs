use hyper::service::{make_service_fn, service_fn};
use hyper::upgrade::Upgraded;
use hyper::{Body, Client, Method, Request, Response, Server};
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::TcpStream;

type HttpClient = Client<hyper::client::HttpConnector>;

pub type RequestHandler = fn(Request<Body>) -> (Request<Body>, Option<Response<Body>>);
pub type ResponseHandler = fn(Response<Body>) -> Response<Body>;

async fn proxy(
    req: Request<Body>,
    client: HttpClient,
    handle_req: RequestHandler,
    handle_res: ResponseHandler,
) -> Result<Response<Body>, hyper::Error> {
    let (req, res) = handle_req(req);

    if let Some(res) = res {
        return Ok(res);
    }

    if req.method() == Method::CONNECT {
        if let Some(addr) = host_addr(req.uri()) {
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr).await {
                            eprintln!("server io error: {}", e);
                        };
                    }
                    Err(e) => eprintln!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(Body::empty()))
        } else {
            eprintln!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut res = Response::new(Body::from("CONNECT must be to a socket address"));
            *res.status_mut() = http::StatusCode::BAD_REQUEST;

            Ok(res)
        }
    } else {
        let res = client.request(req).await?;
        Ok(handle_res(res))
    }
}

fn host_addr(uri: &http::Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

// Create a TCP connection to host:port, build a tunnel between the connection and
// the upgraded connection
async fn tunnel(mut upgraded: Upgraded, addr: String) -> std::io::Result<()> {
    // Connect to remote server
    let mut server = TcpStream::connect(addr).await?;

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;

    // Print message when done
    println!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );

    Ok(())
}

pub struct ProxyConfig<F: Future<Output = ()>> {
    pub listen_addr: SocketAddr,
    pub shutdown_signal: F,
    pub request_handler: Option<RequestHandler>,
    pub response_handler: Option<ResponseHandler>,
}

pub async fn start_proxy<F>(
    ProxyConfig {
        listen_addr,
        shutdown_signal,
        request_handler,
        response_handler,
    }: ProxyConfig<F>,
) -> Result<(), hyper::Error>
where
    F: Future<Output = ()>,
{
    let client = Client::builder()
        .http1_title_case_headers(true)
        .http1_preserve_header_case(true)
        .build_http();

    let request_handler = request_handler.unwrap_or(|req| (req, None));
    let response_handler = response_handler.unwrap_or(|res| res);

    let make_service = make_service_fn(move |_| {
        let client = client.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                proxy(req, client.clone(), request_handler, response_handler)
            }))
        }
    });

    let server = Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .with_graceful_shutdown(shutdown_signal);
    server.await
}
