# ideamans-hudsucker

[![crates.io](https://img.shields.io/crates/v/ideamans-hudsucker)](https://crates.io/crates/ideamans-hudsucker)
[![docs.rs](https://docs.rs/ideamans-hudsucker/badge.svg)](https://docs.rs/ideamans-hudsucker)

**Fork of [hudsucker](https://github.com/omjadas/hudsucker) with HTTP/2 request-response correlation support.**

This fork adds `request_method` and `request_uri` fields to `HttpContext`, enabling handlers to properly correlate responses with their originating requests. This is particularly important for HTTP/2 multiplexing where responses may arrive out of order.

**Upstream PR:** https://github.com/omjadas/hudsucker/pull/165

---

Hudsucker is a MITM HTTP/S proxy written in Rust that allows you to:

- Modify HTTP/S requests
- Modify HTTP/S responses
- Modify WebSocket messages

## What's New in This Fork (v0.25.0)

### HTTP/2 Request-Response Correlation

The `HttpContext` now includes request information, allowing handlers to correlate responses with their originating requests:

```rust
impl HttpHandler for MyHandler {
    async fn handle_response(&mut self, ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        // Access request info in response handler!
        println!("Response for: {} {}", ctx.request_method, ctx.request_uri);
        res
    }
}
```

**Breaking Changes from upstream hudsucker 0.24.0:**
- `HttpContext` now has `request_method` and `request_uri` fields
- `#[non_exhaustive]` removed from `HttpContext`

See [CHANGELOG.md](CHANGELOG.md) for details.

## Features

- `decoder`: Enables `decode_request` and `decode_response` helpers (enabled by default).
- `full`: Enables all features.
- `http2`: Enables HTTP/2 support.
- `native-tls-client`: Enables `ProxyBuilder::with_native_tls_connector`.
- `openssl-ca`: Enables `certificate_authority::OpensslAuthority`.
- `rcgen-ca`: Enables `certificate_authority::RcgenAuthority` (enabled by default).
- `rustls-client`: Enables `ProxyBuilder::with_rustls_connector` (enabled by default).

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
ideamans-hudsucker = "0.25.0"
```

## Usage

For usage, refer to the [provided examples](https://github.com/ideamans/hudsucker/tree/main/examples).

### Built With Hudsucker

- [Cruster](https://github.com/sinKettu/cruster)

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

## Contribution

This is a fork maintained by Ideamans. For contributions to the upstream project, see [omjadas/hudsucker](https://github.com/omjadas/hudsucker).

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## Credits

Original project: [hudsucker](https://github.com/omjadas/hudsucker) by [@omjadas](https://github.com/omjadas)
