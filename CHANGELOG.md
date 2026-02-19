# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-02-19

### Fixed

- `test_stress_wrong_credentials` now reads `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB` from env vars instead of hardcoding `localhost:5432`, so it works against Docker-exposed Postgres instances
- Added missing `#[ignore]` attribute to `test_stress_wrong_credentials`

## [0.1.2] - 2026-02-19

### Added

- TLS support with `sslmode` connection string parameter (disable/require/verify-ca/verify-full)
- SSLRequest protocol negotiation for Postgres SSL handshake
- SCRAM-SHA-256 authentication with channel binding (`tls-server-end-point`)
- Fuzz targets for protocol parsing and `MAX_MESSAGE_LENGTH` safety limit
- 20 SCRAM edge case and failure path unit tests
- 6 concurrent connection load tests using `JoinSet`

### Security

- SCRAM-SHA-256 replaces cleartext-only authentication
- Channel binding prevents MITM attacks on TLS connections
- `MAX_MESSAGE_LENGTH` limits memory usage from malformed messages
- Constant-time comparison for server signature verification

## [0.1.1] - 2026-01-31

### Fixed

- Fixed compilation error in `tls_integration.rs` where client ownership wasn't properly transferred to `query()` method
- Removed unnecessary `mut` qualifier from stream variable
- Resolved unused variable warnings in benchmark utilities
- Improved benchmark code efficiency with `Vec::resize()` instead of repeated `push()` calls

## [0.1.0] - 2026-01-13

### Added

- Initial release of fraiseql-wire
- Async JSON streaming from Postgres 17
- Connection via TCP or Unix sockets
- Simple Query protocol support (no prepared statements)
- SQL predicate pushdown with `where_sql()`
- Rust-side predicate filtering with `where_rust()`
- SERVER-side `ORDER BY` support
- Configurable chunk size for memory control
- Automatic query cancellation on drop
- Bounded memory usage (scales with chunk size, not result size)
- Backpressure via async channels
- `FraiseClient` high-level API with fluent query builder
- Connection string parsing (postgres:// and postgres:///)
- Comprehensive error types with context
- Module-level documentation
- Integration tests with real Postgres
- Examples demonstrating key use cases

### Design Constraints

- Single `data` column (json/jsonb type)
- View naming convention: `v_{entity}`
- Read-only operations only (no INSERT/UPDATE/DELETE)
- No prepared statements (Simple Query protocol only)
- No transaction support
- One active query per connection
- Sequential result streaming (no client-side reordering)

### Features NOT Included

- Arbitrary SQL support (limited to SELECT with WHERE/ORDER BY)
- Multi-column result sets
- Client-side sorting or aggregation
- Server-side cursors
- COPY protocol
- Transactions
- Write operations
- Analytical SQL (GROUP BY, HAVING, window functions)
- Fact tables (`tf_{entity}`)
- Arrow data plane (`va_{entity}`)
- Connection pooling
- TLS support
- SCRAM authentication (cleartext only)
- Typed streaming (returns `serde_json::Value`)

### Performance Characteristics

- Time-to-first-row: sub-millisecond (no buffering)
- Memory overhead: O(chunk_size) only
- Protocol overhead: minimal (from-scratch implementation)
- Latency: optimized for streaming use cases
- Not optimized for: single-row retrieval, batch operations

### Documentation

- Comprehensive README with quick start
- API documentation for all public modules
- Integration test examples
- Error handling patterns
- Advanced filtering example
- Contributing guidelines

---

## How to Read This Changelog

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

[0.1.3]: https://github.com/fraiseql/fraiseql-wire/releases/tag/v0.1.3
[0.1.2]: https://github.com/fraiseql/fraiseql-wire/releases/tag/v0.1.2
[0.1.1]: https://github.com/fraiseql/fraiseql-wire/releases/tag/v0.1.1
[0.1.0]: https://github.com/fraiseql/fraiseql-wire/releases/tag/v0.1.0
