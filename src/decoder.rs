use crate::{Body, Error};
use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder, ZlibDecoder, ZstdDecoder};
use bstr::ByteSlice;
use futures::Stream;
use hyper::{
    Request,
    Response,
    body::{Body as HttpBody, Bytes},
    header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderMap, HeaderValue},
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncBufRead, AsyncRead, BufReader};
use tokio_util::io::{ReaderStream, StreamReader};

struct IoStream<T>(T);

impl<T: HttpBody<Data = Bytes, Error = Error> + Unpin> Stream for IoStream<T> {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            return match futures::ready!(Pin::new(&mut self.0).poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(buf) => Poll::Ready(Some(Ok(buf))),
                    Err(_) => continue,
                },
                Some(Err(Error::Io(err))) => Poll::Ready(Some(Err(err))),
                Some(Err(err)) => Poll::Ready(Some(Err(io::Error::other(err)))),
                None => Poll::Ready(None),
            };
        }
    }
}

fn decode(
    encoding: &[u8],
    reader: impl AsyncBufRead + Send + Sync + Unpin + 'static,
) -> Result<Box<dyn AsyncRead + Send + Sync + Unpin>, Error> {
    Ok(match encoding {
        b"gzip" | b"x-gzip" => Box::new(GzipDecoder::new(reader)),
        b"deflate" => Box::new(ZlibDecoder::new(reader)),
        b"br" => Box::new(BrotliDecoder::new(reader)),
        b"zstd" => Box::new(ZstdDecoder::new(reader)),
        _ => Err(Error::Decode)?,
    })
}

enum Decoder<T> {
    Body(T),
    Decoder(Box<dyn AsyncRead + Send + Sync + Unpin>),
}

impl Decoder<Body> {
    pub fn decode(self, encoding: &[u8]) -> Result<Self, Error> {
        if encoding == b"identity" {
            return Ok(self);
        }

        Ok(Self::Decoder(match self {
            Self::Body(body) => decode(encoding, StreamReader::new(IoStream(body))),
            Self::Decoder(decoder) => decode(encoding, BufReader::new(decoder)),
        }?))
    }
}

impl From<Decoder<Body>> for Body {
    fn from(decoder: Decoder<Body>) -> Body {
        match decoder {
            Decoder::Body(body) => body,
            Decoder::Decoder(decoder) => Body::from_stream(ReaderStream::new(decoder)),
        }
    }
}

fn extract_encodings(headers: &HeaderMap<HeaderValue>) -> impl Iterator<Item = &[u8]> {
    headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .rev()
        .flat_map(|val| val.as_bytes().rsplit_str(b",").map(|v| v.trim()))
}

fn decode_body<'a>(
    encodings: impl IntoIterator<Item = &'a [u8]>,
    body: Body,
) -> Result<Body, Error> {
    let mut decoder = Decoder::Body(body);

    for encoding in encodings {
        decoder = decoder.decode(encoding)?;
    }

    Ok(decoder.into())
}

/// Decode the body of a request.
///
/// # Errors
///
/// This will return an error if one of the values specified in the
/// `content-encoding` header is not supported.
///
/// # Examples
///
/// ```rust
/// use hudsucker::{
///     Body,
///     HttpContext,
///     HttpHandler,
///     RequestOrResponse,
///     decode_request,
///     hyper::Request,
/// };
///
/// #[derive(Clone)]
/// pub struct MyHandler;
///
/// impl HttpHandler for MyHandler {
///     async fn handle_request(
///         &mut self,
///         _ctx: &HttpContext,
///         req: Request<Body>,
///     ) -> RequestOrResponse {
///         let req = decode_request(req).unwrap();
///
///         // Do something with the request
///
///         RequestOrResponse::Request(req)
///     }
/// }
/// ```
pub fn decode_request(mut req: Request<Body>) -> Result<Request<Body>, Error> {
    if !req.headers().contains_key(CONTENT_ENCODING) {
        return Ok(req);
    }

    if let Some(val) = req.headers_mut().remove(CONTENT_LENGTH) {
        if val == "0" {
            return Ok(req);
        }
    }

    let (mut parts, body) = req.into_parts();

    let body = {
        let encodings = extract_encodings(&parts.headers);
        decode_body(encodings, body)?
    };

    parts.headers.remove(CONTENT_ENCODING);

    Ok(Request::from_parts(parts, body))
}

/// Decode the body of a response.
///
/// # Errors
///
/// This will return an error if one of the values specified in the
/// `content-encoding` header is not supported.
///
/// # Examples
///
/// ```rust
/// use hudsucker::{Body, HttpContext, HttpHandler, decode_response, hyper::Response};
///
/// #[derive(Clone)]
/// pub struct MyHandler;
///
/// impl HttpHandler for MyHandler {
///     async fn handle_response(
///         &mut self,
///         _ctx: &HttpContext,
///         res: Response<Body>,
///     ) -> Response<Body> {
///         let res = decode_response(res).unwrap();
///
///         // Do something with the response
///
///         res
///     }
/// }
/// ```
pub fn decode_response(mut res: Response<Body>) -> Result<Response<Body>, Error> {
    if !res.headers().contains_key(CONTENT_ENCODING) {
        return Ok(res);
    }

    if let Some(val) = res.headers_mut().remove(CONTENT_LENGTH) {
        if val == "0" {
            return Ok(res);
        }
    }

    let (mut parts, body) = res.into_parts();

    let body = {
        let encodings = extract_encodings(&parts.headers);
        decode_body(encodings, body)?
    };

    parts.headers.remove(CONTENT_ENCODING);

    Ok(Response::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod extract_encodings {
        use super::*;

        #[test]
        fn no_headers() {
            let headers = HeaderMap::new();

            assert_eq!(extract_encodings(&headers).count(), 0);
        }

        #[test]
        fn single_header_single_value() {
            let mut headers = HeaderMap::new();
            headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

            assert_eq!(
                extract_encodings(&headers).collect::<Vec<_>>(),
                vec![b"gzip"]
            );
        }

        #[test]
        fn single_header_multiple_values() {
            let mut headers = HeaderMap::new();
            headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip, deflate"));

            assert_eq!(
                extract_encodings(&headers).collect::<Vec<_>>(),
                vec![&b"deflate"[..], &b"gzip"[..]]
            );
        }

        #[test]
        fn multiple_headers_single_value() {
            let mut headers = HeaderMap::new();
            headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
            headers.append(CONTENT_ENCODING, HeaderValue::from_static("deflate"));

            assert_eq!(
                extract_encodings(&headers).collect::<Vec<_>>(),
                vec![&b"deflate"[..], &b"gzip"[..]]
            );
        }

        #[test]
        fn multiple_headers_multiple_values() {
            let mut headers = HeaderMap::new();
            headers.append(CONTENT_ENCODING, HeaderValue::from_static("gzip, deflate"));
            headers.append(CONTENT_ENCODING, HeaderValue::from_static("br, zstd"));

            assert_eq!(
                extract_encodings(&headers).collect::<Vec<_>>(),
                vec![&b"zstd"[..], &b"br"[..], &b"deflate"[..], &b"gzip"[..]]
            );
        }
    }

    async fn to_bytes<H: HttpBody>(body: H) -> Bytes
    where
        H::Error: std::fmt::Debug,
    {
        use http_body_util::BodyExt;
        body.collect().await.unwrap().to_bytes()
    }

    mod decode_body {
        use super::*;
        use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};

        #[tokio::test]
        async fn no_encodings() {
            let content = "hello, world";
            let body = Body::from(content);

            assert_eq!(
                &to_bytes(decode_body(vec![], body).unwrap()).await[..],
                content.as_bytes()
            );
        }

        #[tokio::test]
        async fn identity_encoding() {
            let content = "hello, world";
            let body = Body::from(content);

            assert_eq!(
                &to_bytes(decode_body(vec![&b"identity"[..]], body).unwrap()).await[..],
                content.as_bytes()
            );
        }

        #[tokio::test]
        async fn single_encoding() {
            let content = b"hello, world";
            let encoder = GzipEncoder::new(&content[..]);
            let body = Body::from_stream(ReaderStream::new(encoder));

            assert_eq!(
                &to_bytes(decode_body(vec![&b"gzip"[..]], body).unwrap()).await[..],
                content
            );
        }

        #[tokio::test]
        async fn multiple_encodings() {
            let content = b"hello, world";
            let encoder = GzipEncoder::new(&content[..]);
            let encoder = BrotliEncoder::new(BufReader::new(encoder));
            let body = Body::from_stream(ReaderStream::new(encoder));

            assert_eq!(
                &to_bytes(decode_body(vec![&b"br"[..], &b"gzip"[..]], body).unwrap()).await[..],
                content
            );
        }

        #[test]
        fn invalid_encoding() {
            let body = Body::empty();

            assert!(decode_body(vec![&b"invalid"[..]], body).is_err());
        }
    }

    mod decode_request {
        use super::*;
        use async_compression::tokio::bufread::GzipEncoder;

        #[tokio::test]
        async fn decodes_request() {
            let content = b"hello, world";
            let encoder = GzipEncoder::new(&content[..]);
            let req = Request::builder()
                .header(CONTENT_LENGTH, 123)
                .header(CONTENT_ENCODING, "gzip")
                .body(Body::from_stream(ReaderStream::new(encoder)))
                .unwrap();

            let req = decode_request(req).unwrap();

            assert!(!req.headers().contains_key(CONTENT_LENGTH));
            assert!(!req.headers().contains_key(CONTENT_ENCODING));
            assert_eq!(&to_bytes(req.into_body()).await[..], content);
        }
    }

    mod decode_response {
        use super::*;
        use async_compression::tokio::bufread::GzipEncoder;

        #[tokio::test]
        async fn decodes_response() {
            let content = b"hello, world";
            let encoder = GzipEncoder::new(&content[..]);
            let res = Response::builder()
                .header(CONTENT_LENGTH, 123)
                .header(CONTENT_ENCODING, "gzip")
                .body(Body::from_stream(ReaderStream::new(encoder)))
                .unwrap();

            let res = decode_response(res).unwrap();

            assert!(!res.headers().contains_key(CONTENT_LENGTH));
            assert!(!res.headers().contains_key(CONTENT_ENCODING));
            assert_eq!(&to_bytes(res.into_body()).await[..], content);
        }
    }
}
