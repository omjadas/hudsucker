# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Hudsucker - MITM HTTP/S Proxy

### Overview

Hudsucker is a MITM HTTP/S proxy library written in Rust that allows intercepting and modifying:
- HTTP/S requests and responses
- WebSocket messages

This is a **library crate** published to crates.io, not an application. The primary deliverable is the library API.

### Development Commands

```bash
# Build with all features
cargo build --release --all-targets --all-features

# Run tests with all features
cargo test --release --all-features

# Run clippy linter
cargo clippy --all-targets --all-features

# Format code (requires nightly rustfmt)
cargo +nightly fmt --all

# Check formatting
cargo +nightly fmt --all -- --check

# Run a specific example
cargo run --example log --features "rcgen-ca,rustls-client"
cargo run --example noop --features "rcgen-ca,rustls-client"
cargo run --example openssl --features "openssl-ca,rustls-client"

# Run benchmarks
cargo bench --bench certificate_authorities --features "openssl-ca,rcgen-ca"
cargo bench --bench decoder --features "decoder"
cargo bench --bench proxy --features "rcgen-ca,rustls-client"

# Run a specific test
cargo test --test rcgen_ca --features "decoder,rcgen-ca,native-tls-client,rustls-client"
cargo test --test openssl_ca --features "decoder,openssl-ca,native-tls-client,rustls-client"
cargo test --test websocket --features "decoder,rcgen-ca,native-tls-client,rustls-client"
```

### Tech Stack & Requirements

**Language & Toolchain:**
- Rust 1.85.0+ (MSRV: Minimum Supported Rust Version)
- Rust Edition 2024
- Nightly rustfmt for code formatting

**Core Dependencies:**
- hyper 1.x (HTTP library)
- tokio (async runtime)
- tokio-rustls (TLS for Rustls)
- hyper-tungstenite / tokio-tungstenite (WebSocket support)

**Certificate Authority Implementations:**
- rcgen (default, pure Rust)
- OpenSSL (optional, requires system OpenSSL)

### Feature Flags

Understanding the feature system is critical for working with this crate:

**Default features:** `decoder`, `rcgen-ca`, `rustls-client`

**Available features:**
- `decoder`: Enables `decode_request` and `decode_response` helpers for decompressing HTTP bodies
- `full`: Enables all features
- `http2`: Enables HTTP/2 support
- `native-tls-client`: Enables native TLS connector using system TLS
- `openssl-ca`: Enables OpenSSL-based certificate authority
- `rcgen-ca`: Enables pure Rust certificate authority (default)
- `rustls-client`: Enables Rustls-based TLS connector (default)

**Feature dependencies in examples/tests:**
- Examples and tests declare `required-features` in Cargo.toml
- When adding new examples/tests, ensure proper feature requirements are specified

### Architecture

**Builder Pattern with Type States:**
The proxy uses a compile-time enforced builder pattern (`ProxyBuilder`) with type states:

1. `WantsAddr` → Set address/listener → `WantsCa`
2. `WantsCa` → Set certificate authority → `WantsClient`
3. `WantsClient` → Set connector (rustls/native-tls/custom) → `WantsHandlers`
4. `WantsHandlers` → Optionally set handlers → `build()` returns `Proxy`

This ensures required configuration is provided at compile time.

**Core Traits:**
- `CertificateAuthority`: Generates server configs for MITM TLS (implementations: `RcgenAuthority`, `OpensslAuthority`)
- `HttpHandler`: Intercepts HTTP requests and responses
  - `handle_request`: Can return modified request OR early response
  - `handle_response`: Modifies responses before forwarding to client
  - `handle_error`: Handles upstream connection errors
  - `should_intercept`: Decides whether to intercept CONNECT requests
- `WebSocketHandler`: Intercepts WebSocket messages
  - `handle_websocket`: Manages message stream/sink
  - `handle_message`: Processes individual WebSocket messages

**Proxy Flow:**
1. Client connects to proxy
2. For HTTPS (CONNECT requests):
   - Proxy generates on-the-fly certificate using `CertificateAuthority`
   - Establishes TLS with client using generated cert
   - Connects to upstream server
   - Passes decrypted traffic through handlers
3. For HTTP requests:
   - Directly proxies to upstream
   - Passes traffic through handlers
4. For WebSocket upgrades:
   - Upgrades both client and server connections
   - Passes messages through `WebSocketHandler`

**Internal Structure:**
- `src/proxy/mod.rs`: Main `Proxy` struct and startup logic
- `src/proxy/builder.rs`: Type-safe builder implementation
- `src/proxy/internal.rs`: Internal proxy logic (request routing)
- `src/certificate_authority/`: CA trait and implementations
- `src/body.rs`: HTTP body handling
- `src/decoder.rs`: Body decompression (gzip, brotli, zstd, etc.)
- `src/rewind.rs`: Rewinding stream support for request/response inspection

### Rustfmt Configuration

The project uses custom rustfmt settings (rustfmt.toml):
- Horizontal/Vertical imports layout with crate-level granularity
- Field init shorthand enabled
- Comment wrapping enabled
- Code formatting in doc comments enabled
- Unix newline style

Always use `cargo +nightly fmt` as stable rustfmt doesn't support all config options.

### Testing Strategy

**Test Organization:**
- Unit tests: Inline in source files
- Integration tests: `tests/` directory with separate files per feature
- Benchmarks: `benches/` directory using criterion

**Testing with Features:**
Each test module may require specific features. Check `Cargo.toml` for `required-features`.

**Common Test Pattern:**
```rust
// Tests use real certificate authorities and TLS connectors
// Mock HTTP servers are created using tokio and hyper
// Proxy is configured with test handlers
// Requests are sent through the proxy
// Assertions verify handler behavior
```

### CI/CD

GitHub Actions workflow (`.github/workflows/build.yml`):
- Tests on: stable, beta, nightly, and MSRV (1.85.0)
- Runs: build, test, clippy, fmt check
- Minimal versions check (ensures dependency lower bounds are correct)
- Auto-publish to crates.io on GitHub releases

### Common Development Patterns

**Adding a new handler:**
1. Implement `HttpHandler` and/or `WebSocketHandler` trait
2. Clone trait is required (handlers are cloned per connection)
3. Use interior mutability if state needs to be shared across connections

**Modifying request/response bodies:**
1. Use `decode_request`/`decode_response` to decompress if needed
2. Convert `Body` to bytes using `http_body_util::BodyExt`
3. Modify bytes
4. Create new `Body` with `Body::from()`

**Example structure:**
- Keep examples minimal and focused on specific features
- Include graceful shutdown signal handling
- Use `tracing_subscriber::fmt::init()` for logging

### Breaking Changes in v0.25.0

**HttpContext now includes request information:**
- Added `request_method: hyper::Method` field
- Added `request_uri: Uri` field
- Removed `#[non_exhaustive]` attribute

This change enables proper request-response correlation, especially important for HTTP/2 multiplexing where responses may arrive out of order. Handlers can now reliably match responses to their originating requests by accessing `ctx.request_method` and `ctx.request_uri` in `handle_response`.

**Migration guide:**
- If you construct `HttpContext` in tests, add the new required fields
- If you only read `ctx.client_addr`, no changes needed
- If you need to correlate requests/responses, use `ctx.request_uri` and `ctx.request_method`

### Publishing Checklist

When preparing a release:
1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with changes
3. Ensure all features compile: `cargo build --all-features`
4. Ensure all tests pass: `cargo test --all-features`
5. Check formatting: `cargo +nightly fmt --all -- --check`
6. Run clippy: `cargo clippy --all-targets --all-features`
7. Update README.md if API changed
8. Create GitHub release (triggers auto-publish)
