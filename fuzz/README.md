# Fuzz Testing

Fuzz targets for fraiseql-wire's wire protocol decoder and SCRAM authentication parser.

## Prerequisites

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Available Targets

| Target | Description |
|--------|-------------|
| `fuzz_decode_message` | Feeds arbitrary bytes to the protocol decoder |
| `fuzz_scram_parse` | Exercises the SCRAM-SHA-256 authentication flow |
| `fuzz_streaming_decode` | Simulates chunked TCP delivery with arbitrary split points |

## Running Locally

Run a single target indefinitely (Ctrl+C to stop):

```bash
cargo +nightly fuzz run fuzz_decode_message
```

Run for a fixed duration (e.g. 60 seconds):

```bash
cargo +nightly fuzz run fuzz_decode_message -- -max_total_time=60
```

Limit memory usage (e.g. 256 MB):

```bash
cargo +nightly fuzz run fuzz_decode_message -- -rss_limit_mb=256
```

## Interpreting Crashes

When the fuzzer finds a crash, the input is saved to `fuzz/artifacts/<target>/`. To reproduce:

```bash
cargo +nightly fuzz run fuzz_decode_message fuzz/artifacts/fuzz_decode_message/<crash-file>
```

## CI

Fuzz tests run weekly via GitHub Actions (`.github/workflows/fuzz.yml`) with a 5-minute budget per target.
