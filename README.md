# hudsucker

[![crates.io](https://img.shields.io/crates/v/hudsucker)](https://crates.io/crates/hudsucker)
[![docs.rs](https://docs.rs/hudsucker/badge.svg)](https://docs.rs/hudsucker)
[![Build](https://github.com/omjadas/hudsucker/actions/workflows/build.yml/badge.svg)](https://github.com/omjadas/hudsucker/actions/workflows/build.yml)

Hudsucker is a MITM HTTP/S proxy written in Rust that allows you to:

- Modify HTTP/S requests
- Modify HTTP/S responses
- Modify websocket messages

## Features

- `decoder`: Enables `decode_request` and `decode_response` helpers (enabled by default).
- `full`: Enables all features.
- `http2`: Enables HTTP/2 support.
- `native-tls-client`: Enables `ProxyBuilder::with_native_tls_client`.
- `openssl-ca`: Enables `certificate_authority::OpensslAuthority`.
- `rcgen-ca`: Enables `certificate_authority::RcgenAuthority` (enabled by default).
- `rustls-client`: Enables `ProxyBuilder::with_rustls_client` (enabled by default).

## Usage

For usage, refer to the [provided examples](https://github.com/omjadas/hudsucker/tree/main/examples).

### Built With Hudsucker

- [Cruster](https://github.com/sinKettu/cruster)

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT license](LICENSE-MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
