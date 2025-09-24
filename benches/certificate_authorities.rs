use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http::uri::Authority;
use hudsucker::{
    certificate_authority::{CertificateAuthority, OpensslAuthority, RcgenAuthority},
    openssl::{hash::MessageDigest, pkey::PKey, x509::X509},
    rcgen::{Issuer, KeyPair},
    rustls::crypto::aws_lc_rs,
};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

fn build_rcgen_ca(cache_size: u64) -> RcgenAuthority {
    let key_pair = include_str!("../examples/ca/hudsucker.key");
    let ca_cert = include_str!("../examples/ca/hudsucker.cer");
    let key_pair = KeyPair::from_pem(key_pair).expect("Failed to parse private key");
    let issuer =
        Issuer::from_ca_cert_pem(ca_cert, key_pair).expect("Failed to parse CA certificate");

    RcgenAuthority::new(issuer, cache_size, aws_lc_rs::default_provider())
}

fn build_openssl_ca(cache_size: u64) -> OpensslAuthority {
    let private_key: &[u8] = include_bytes!("../examples/ca/hudsucker.key");
    let ca_cert: &[u8] = include_bytes!("../examples/ca/hudsucker.cer");
    let private_key = PKey::private_key_from_pem(private_key).expect("Failed to parse private key");
    let ca_cert = X509::from_pem(ca_cert).expect("Failed to parse CA certificate");

    OpensslAuthority::new(
        private_key,
        ca_cert,
        MessageDigest::sha256(),
        cache_size,
        aws_lc_rs::default_provider(),
    )
}

fn compare_cas(c: &mut Criterion) {
    let rcgen_ca = build_rcgen_ca(0);
    let openssl_ca = build_openssl_ca(0);
    let authority = Authority::from_static("example.com");
    let runtime = runtime();

    let mut group = c.benchmark_group("cas");
    group.bench_function("rcgen", |b| {
        b.to_async(&runtime)
            .iter(|| rcgen_ca.gen_server_config(black_box(&authority)))
    });
    group.bench_function("openssl", |b| {
        b.to_async(&runtime)
            .iter(|| openssl_ca.gen_server_config(black_box(&authority)))
    });
    group.finish();
}

fn rcgen_ca(c: &mut Criterion) {
    let cache_ca = build_rcgen_ca(1000);
    let no_cache_ca = build_rcgen_ca(0);
    let authority = Authority::from_static("example.com");
    let runtime = runtime();

    let mut group = c.benchmark_group("rcgen ca");
    group.bench_function("with cache", |b| {
        b.to_async(&runtime)
            .iter(|| cache_ca.gen_server_config(black_box(&authority)))
    });
    group.bench_function("without cache", |b| {
        b.to_async(&runtime)
            .iter(|| no_cache_ca.gen_server_config(black_box(&authority)))
    });
    group.finish();
}

fn openssl_ca(c: &mut Criterion) {
    let cache_ca = build_openssl_ca(1000);
    let no_cache_ca = build_openssl_ca(0);
    let authority = Authority::from_static("example.com");
    let runtime = runtime();

    let mut group = c.benchmark_group("openssl ca");
    group.bench_function("with cache", |b| {
        b.to_async(&runtime)
            .iter(|| cache_ca.gen_server_config(black_box(&authority)))
    });
    group.bench_function("without cache", |b| {
        b.to_async(&runtime)
            .iter(|| no_cache_ca.gen_server_config(black_box(&authority)))
    });
    group.finish();
}

criterion_group!(benches, compare_cas, rcgen_ca, openssl_ca);
criterion_main!(benches);
