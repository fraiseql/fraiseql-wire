# Phase 1: SSLRequest Protocol Flow

## Objective
Implement the PostgreSQL SSLRequest negotiation so TLS connections use the proper wire protocol handshake.

## Success Criteria
- [ ] `SslRequest` variant in `FrontendMessage`
- [ ] Correct 8-byte encoding (length=8, code=80877103)
- [ ] `SslMode` enum: `Disable`, `Require`, `VerifyCa`, `VerifyFull`
- [ ] `sslmode` field on `ConnectionConfig` and builder
- [ ] `NegotiatingTls` state in connection state machine
- [ ] `Transport::upgrade_to_tls()` method on plain TCP
- [ ] SSLRequest exchange in connection startup (send request, read S/N response)
- [ ] `FraiseClient::connect` uses sslmode when TlsConfig is provided
- [ ] All unit tests pass, clippy clean

## TDD Cycles

### Cycle 1: SslRequest message encoding
- **RED**: Test encoding produces exactly `[0,0,0,8, 04,d2,16,2f]`
- **GREEN**: Add `SslRequest` variant and encode function
- **REFACTOR**: Extract SSL_REQUEST_CODE constant
- **CLEANUP**: clippy, fmt

### Cycle 2: SslMode enum
- **RED**: Test SslMode parsing from strings
- **GREEN**: Implement SslMode enum with FromStr
- **REFACTOR**: Add Display impl
- **CLEANUP**: clippy, fmt

### Cycle 3: ConnectionConfig sslmode field
- **RED**: Test builder accepts sslmode
- **GREEN**: Add field to ConnectionConfig and builder
- **REFACTOR**: Ensure defaults are sensible (Disable when no TLS)
- **CLEANUP**: clippy, fmt

### Cycle 4: NegotiatingTls state
- **RED**: Test state transition Initial → NegotiatingTls → AwaitingAuth
- **GREEN**: Add state and transitions
- **REFACTOR**: Review state machine completeness
- **CLEANUP**: clippy, fmt

### Cycle 5: Transport TLS upgrade
- **RED**: Test that upgrade_to_tls exists on TcpVariant::Plain
- **GREEN**: Implement upgrade method
- **REFACTOR**: Clean up error handling
- **CLEANUP**: clippy, fmt

### Cycle 6: SSLRequest exchange in Connection::startup
- **RED**: (Integration-level, may need mock) Test that startup sends SSLRequest before Startup when sslmode != Disable
- **GREEN**: Implement negotiation in startup
- **REFACTOR**: Extract negotiate_tls method
- **CLEANUP**: clippy, fmt

## Dependencies
- None (first phase)

## Status
[ ] Not Started
