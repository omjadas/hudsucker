# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.25.0] - 2025-11-13

### Changed

- **BREAKING**: `HttpContext` now includes `request_method` and `request_uri` fields
  - This enables proper request-response correlation in `handle_response`
  - Particularly important for HTTP/2 multiplexing where responses may arrive out of order
  - The same `HttpContext` instance is now passed to both `handle_request` and `handle_response`
- **BREAKING**: Removed `#[non_exhaustive]` from `HttpContext` to allow construction in tests

### Added

- New `request_method: hyper::Method` field in `HttpContext`
- New `request_uri: Uri` field in `HttpContext`
- Test suite (`tests/context_correlation.rs`) for request-response correlation
- Documentation explaining the purpose of `HttpContext` fields

### Fixed

- HTTP/2 multiplexed requests can now be properly correlated with their responses
- Handlers can now reliably match responses to their originating requests

## [0.24.0] - Previous version

See git history for earlier changes.
