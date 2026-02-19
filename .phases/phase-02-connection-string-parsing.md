# Phase 2: Connection String Parsing for TLS

## Objective
Parse `sslmode` and TLS-related parameters from PostgreSQL connection URLs.

## Success Criteria
- [ ] `sslmode` parsed from query params: `postgres://host/db?sslmode=require`
- [ ] `sslrootcert` parsed from query params (custom CA path)
- [ ] `sslcert` and `sslkey` parsed from query params (for mTLS, Phase 4)
- [ ] `ConnectionInfo` carries parsed TLS parameters
- [ ] `FraiseClient::connect()` auto-negotiates TLS when `sslmode` is set
- [ ] Unix sockets ignore `sslmode` (no TLS negotiation)
- [ ] All unit tests pass, clippy clean

## TDD Cycles

### Cycle 1: Parse sslmode from query parameters
- **RED**: Test parsing `postgres://host/db?sslmode=require`
- **GREEN**: Add sslmode extraction to ConnectionInfo::parse_tcp
- **REFACTOR**: Reuse existing `parse_query_param` helper
- **CLEANUP**: clippy, fmt

### Cycle 2: Parse sslrootcert, sslcert, sslkey
- **RED**: Test parsing `postgres://host/db?sslmode=verify-ca&sslrootcert=/path/to/ca.pem`
- **GREEN**: Add fields to ConnectionInfo, extract from query params
- **REFACTOR**: Group TLS params into a sub-struct
- **CLEANUP**: clippy, fmt

### Cycle 3: Map parsed params to TlsConfig
- **RED**: Test that ConnectionInfo with sslmode=verify-full produces correct TlsConfig
- **GREEN**: Implement to_tls_config() on ConnectionInfo
- **REFACTOR**: Handle verify-ca vs verify-full hostname differences
- **CLEANUP**: clippy, fmt

### Cycle 4: FraiseClient::connect() auto-TLS
- **RED**: Test that connect("postgres://host/db?sslmode=require") sets up TLS negotiation
- **GREEN**: Wire sslmode through FraiseClient::connect
- **REFACTOR**: Consolidate connect methods
- **CLEANUP**: clippy, fmt

### Cycle 5: Unix socket sslmode handling
- **RED**: Test that unix socket ignores sslmode parameter
- **GREEN**: Skip TLS for Unix transport
- **CLEANUP**: clippy, fmt

## Dependencies
- Requires: Phase 1 complete

## Status
[ ] Not Started
