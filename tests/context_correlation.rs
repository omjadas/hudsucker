use hudsucker::{
    Body,
    HttpContext,
    HttpHandler,
    RequestOrResponse,
    hyper::{Method, Request, Response, Uri},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct CorrelationHandler {
    requests: Arc<Mutex<HashMap<Uri, String>>>,
    responses: Arc<Mutex<Vec<(Uri, String)>>>,
}

impl CorrelationHandler {
    fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            responses: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn get_responses(&self) -> Vec<(Uri, String)> {
        self.responses.lock().unwrap().clone()
    }
}

impl HttpHandler for CorrelationHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        let uri = req.uri().clone();
        let method = req.method().to_string();

        // Store the request method by URI
        self.requests.lock().unwrap().insert(uri.clone(), method);

        // Verify context has request info
        assert_eq!(ctx.request_uri, uri);
        assert_eq!(ctx.request_method, *req.method());

        req.into()
    }

    async fn handle_response(&mut self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // Verify context contains the correct request info
        let stored_method = self.requests.lock().unwrap().get(&ctx.request_uri).cloned();

        if let Some(method) = stored_method {
            // Verify the context matches what we stored
            assert_eq!(ctx.request_method.as_str(), method.as_str());

            // Record the correlation
            self.responses
                .lock()
                .unwrap()
                .push((ctx.request_uri.clone(), method));
        }

        res
    }
}

#[tokio::test]
async fn test_request_response_correlation() {
    let mut handler = CorrelationHandler::new();

    // Simulate multiple request-response cycles
    let test_cases = vec![
        ("http://example.com/path1", Method::GET),
        ("http://example.com/path2", Method::POST),
        ("http://example.com/path3", Method::PUT),
    ];

    for (uri_str, method) in &test_cases {
        let uri: Uri = uri_str.parse().unwrap();

        // Create request
        let req = Request::builder()
            .method(method.clone())
            .uri(uri.clone())
            .body(Body::empty())
            .unwrap();

        // Create context (simulating what InternalProxy does)
        let ctx = HttpContext {
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            request_method: method.clone(),
            request_uri: uri.clone(),
        };

        // Handle request
        let result = handler.handle_request(&ctx, req).await;
        assert!(matches!(result, RequestOrResponse::Request(_)));

        // Handle response with same context
        let res = Response::builder().body(Body::empty()).unwrap();
        let _ = handler.handle_response(&ctx, res).await;
    }

    // Verify all correlations were recorded correctly
    let responses = handler.get_responses();
    assert_eq!(responses.len(), 3);

    for ((uri, method), (expected_uri, expected_method)) in responses.iter().zip(test_cases.iter())
    {
        assert_eq!(uri.to_string(), *expected_uri);
        assert_eq!(method, expected_method.as_str());
    }
}

#[tokio::test]
async fn test_context_fields_populated() {
    #[derive(Clone)]
    struct ContextChecker {
        verified: Arc<Mutex<bool>>,
    }

    impl HttpHandler for ContextChecker {
        async fn handle_request(
            &mut self,
            ctx: &HttpContext,
            req: Request<Body>,
        ) -> RequestOrResponse {
            // Verify context fields match request
            assert_eq!(ctx.request_method, *req.method());
            assert_eq!(ctx.request_uri, *req.uri());
            assert_ne!(ctx.client_addr.port(), 0);

            req.into()
        }

        async fn handle_response(
            &mut self,
            ctx: &HttpContext,
            res: Response<Body>,
        ) -> Response<Body> {
            // Verify context still has request info in response handler
            assert_eq!(ctx.request_method, Method::GET);
            assert_eq!(ctx.request_uri.path(), "/test");
            *self.verified.lock().unwrap() = true;

            res
        }
    }

    let verified = Arc::new(Mutex::new(false));
    let mut handler = ContextChecker {
        verified: verified.clone(),
    };

    // Create request
    let uri: Uri = "http://example.com/test".parse().unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri.clone())
        .body(Body::empty())
        .unwrap();

    // Create context
    let ctx = HttpContext {
        client_addr: "127.0.0.1:12345".parse().unwrap(),
        request_method: Method::GET,
        request_uri: uri,
    };

    // Handle request
    let result = handler.handle_request(&ctx, req).await;
    assert!(matches!(result, RequestOrResponse::Request(_)));

    // Handle response
    let res = Response::builder().body(Body::empty()).unwrap();
    let _ = handler.handle_response(&ctx, res).await;

    // Verify response handler was called and verified context
    assert!(*verified.lock().unwrap());
}
