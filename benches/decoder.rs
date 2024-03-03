use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use hudsucker::{
    decode_request, decode_response,
    hyper::{
        header::{CONTENT_ENCODING, CONTENT_LENGTH},
        Request, Response,
    },
    Body,
};
use tokio::io::BufReader;
use tokio_util::io::ReaderStream;

const BODY: &[u8; 12] = b"Hello, World";

fn raw_body() -> Body {
    Body::from(&BODY[..])
}

fn gzip_body() -> Body {
    let encoder = GzipEncoder::new(&BODY[..]);
    Body::wrap_stream(ReaderStream::new(encoder))
}

fn gzip_brotli_body() -> Body {
    let encoder = GzipEncoder::new(&BODY[..]);
    let encoder = BrotliEncoder::new(BufReader::new(encoder));
    Body::wrap_stream(ReaderStream::new(encoder))
}

fn raw_request() -> Request<Body> {
    Request::builder()
        .header(CONTENT_LENGTH, BODY.len())
        .body(raw_body())
        .unwrap()
}

fn gzip_request() -> Request<Body> {
    Request::builder()
        .header(CONTENT_LENGTH, 123)
        .header(CONTENT_ENCODING, "gzip")
        .body(gzip_body())
        .unwrap()
}

fn gzip_brotli_request() -> Request<Body> {
    Request::builder()
        .header(CONTENT_LENGTH, 123)
        .header(CONTENT_ENCODING, "gzip, br")
        .body(gzip_brotli_body())
        .unwrap()
}

fn raw_response() -> Response<Body> {
    Response::builder()
        .header(CONTENT_LENGTH, BODY.len())
        .body(raw_body())
        .unwrap()
}

fn gzip_response() -> Response<Body> {
    Response::builder()
        .header(CONTENT_LENGTH, 123)
        .header(CONTENT_ENCODING, "gzip")
        .body(gzip_body())
        .unwrap()
}

fn gzip_brotli_response() -> Response<Body> {
    Response::builder()
        .header(CONTENT_LENGTH, BODY.len())
        .header(CONTENT_ENCODING, "gzip, br")
        .body(gzip_brotli_body())
        .unwrap()
}

fn bench_decode_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_request");
    group.bench_function("raw", |b| {
        b.iter_batched(raw_request, decode_request, BatchSize::SmallInput)
    });
    group.bench_function("gzip", |b| {
        b.iter_batched(gzip_request, decode_request, BatchSize::SmallInput)
    });
    group.bench_function("gzip, br", |b| {
        b.iter_batched(gzip_brotli_request, decode_request, BatchSize::SmallInput)
    });
    group.finish();
}

fn bench_decode_response(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_response");
    group.bench_function("raw", |b| {
        b.iter_batched(raw_response, decode_response, BatchSize::SmallInput)
    });
    group.bench_function("gzip", |b| {
        b.iter_batched(gzip_response, decode_response, BatchSize::SmallInput)
    });
    group.bench_function("gzip, br", |b| {
        b.iter_batched(gzip_brotli_response, decode_response, BatchSize::SmallInput)
    });
    group.finish();
}

criterion_group!(benches, bench_decode_request, bench_decode_response);
criterion_main!(benches);
