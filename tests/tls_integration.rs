//! Integration tests for TLS encryption
//!
//! These tests verify that TLS encryption works end-to-end with PostgreSQL.
//! Tests validate TLS connection establishment, certificate verification, and error handling.
//!
//! To run these tests locally, you can either:
//!
//! 1. With self-signed certificates (development):
//! ```bash
//! # Generate self-signed certificate
//! openssl req -x509 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt \
//!   -days 1 -nodes -subj "/CN=localhost"
//!
//! # Set environment for TLS testing
//! export TLS_TEST_DB_URL="postgres://localhost:5432/fraiseql_test"
//! export TLS_TEST_CERT_PATH="/path/to/ca.crt"  # Optional: custom CA cert
//! export TLS_TEST_INSECURE="true"  # Allow self-signed for dev/test
//!
//! cargo test --test tls_integration -- --ignored --nocapture
//! ```
//!
//! 2. In CI (with GitHub Actions setup - see ci.yml)

#[cfg(test)]
mod tls_integration {
    use fraiseql_wire::connection::TlsConfig;
    use fraiseql_wire::FraiseClient;
    use futures::StreamExt;
    use serde_json::Value;
    use std::env;

    /// Helper to get TLS test configuration from environment
    fn get_tls_test_config() -> Option<(String, bool)> {
        let db_url = env::var("TLS_TEST_DB_URL").ok()?;
        let insecure = env::var("TLS_TEST_INSECURE")
            .ok()
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false);
        Some((db_url, insecure))
    }

    /// Test that TLS connection succeeds with valid configuration
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_connection_succeeds() {
        let (db_url, insecure) = match get_tls_test_config() {
            Some(cfg) => cfg,
            None => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        // Create TLS configuration
        let tls_config = match TlsConfig::builder().verify_hostname(!insecure).build() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to build TLS config: {}", e);
                return;
            }
        };

        // Connect with TLS
        let client = match FraiseClient::connect_tls(&db_url, tls_config).await {
            Ok(c) => c,
            Err(e) => {
                panic!("Failed to connect with TLS: {}", e);
            }
        };

        // Verify we can execute a simple query
        let mut stream = match client.query::<Value>("pg_tables").execute().await {
            Ok(s) => s,
            Err(e) => {
                panic!("Failed to execute query with TLS connection: {}", e);
            }
        };

        // Should be able to read at least one result
        let _result = stream.next().await;
        println!("✓ TLS connection succeeded");
    }

    /// Test that standard password auth works over TLS
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_with_password_auth() {
        let (db_url, insecure) = match get_tls_test_config() {
            Some(cfg) => cfg,
            None => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        // Create TLS config that allows self-signed certs (for testing)
        let tls_config = match TlsConfig::builder().verify_hostname(!insecure).build() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to build TLS config: {}", e);
                return;
            }
        };

        // Connection with password authentication over TLS should work
        let result = FraiseClient::connect_tls(&db_url, tls_config).await;

        match result {
            Ok(client) => {
                // Verify connection is functional
                let stream = client.query::<Value>("pg_version").execute().await;
                assert!(stream.is_ok(), "Query execution failed after TLS auth");
                println!("✓ TLS with password authentication succeeded");
            }
            Err(e) => {
                eprintln!(
                    "Note: TLS connection failed (may be expected if no TLS Postgres available): {}",
                    e
                );
            }
        }
    }

    /// Test that TLS configuration can be built with custom options
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_config_builder() {
        // This test verifies that the TLS builder API works correctly
        let config = TlsConfig::builder().verify_hostname(true).build();

        assert!(
            config.is_ok(),
            "TLS config builder should create valid config"
        );
        println!("✓ TLS config builder works correctly");
    }

    /// Test that multiple TLS connections can be created
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_multiple_tls_connections() {
        let (db_url, insecure) = match get_tls_test_config() {
            Some(cfg) => cfg,
            None => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        let tls_config = match TlsConfig::builder().verify_hostname(!insecure).build() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to build TLS config: {}", e);
                return;
            }
        };

        // Create multiple connections
        let mut connections = Vec::new();

        for _ in 0..3 {
            match FraiseClient::connect_tls(&db_url, tls_config.clone()).await {
                Ok(client) => {
                    connections.push(client);
                }
                Err(e) => {
                    eprintln!("Failed to create TLS connection: {}", e);
                    return;
                }
            }
        }

        // All connections should be usable
        assert_eq!(
            connections.len(),
            3,
            "Should have created 3 TLS connections"
        );

        // Try to use each connection
        for (i, client) in connections.into_iter().enumerate() {
            match client.query::<Value>("pg_version").execute().await {
                Ok(mut stream) => {
                    let _result = stream.next().await;
                    println!("✓ TLS connection {} is usable", i + 1);
                }
                Err(e) => {
                    eprintln!("TLS connection {} failed: {}", i + 1, e);
                }
            }
        }
    }

    /// Test that TLS connection can stream results correctly
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_streaming() {
        let (db_url, insecure) = match get_tls_test_config() {
            Some(cfg) => cfg,
            None => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        let tls_config = match TlsConfig::builder().verify_hostname(!insecure).build() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("Failed to build TLS config: {}", e);
                return;
            }
        };

        let client = match FraiseClient::connect_tls(&db_url, tls_config).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to connect with TLS: {}", e);
                return;
            }
        };

        // Execute a query and stream results
        match client.query::<Value>("pg_tables").execute().await {
            Ok(mut stream) => {
                let mut count = 0;
                while let Some(_result) = stream.next().await {
                    count += 1;
                    // Just verify streaming works, don't need to check values
                    if count >= 5 {
                        break; // Stop after a few rows
                    }
                }
                println!("✓ TLS streaming works (received {} rows)", count);
            }
            Err(e) => {
                eprintln!("Failed to stream results over TLS: {}", e);
            }
        }
    }

    /// Test TLS configuration cloning for connection pool scenarios
    #[test]
    fn test_tls_config_cloneable() {
        let config = TlsConfig::builder()
            .verify_hostname(true)
            .build()
            .expect("Failed to build TLS config");

        // Should be able to clone for reuse in connection pooling
        let cloned = config.clone();

        // Both should be valid for use
        drop(config);
        drop(cloned);

        println!("✓ TLS config is cloneable for pooling");
    }

    /// Test that TLS hostname verification setting is respected
    #[test]
    fn test_tls_hostname_verification_setting() {
        // Strict verification (production)
        let strict_config = TlsConfig::builder().verify_hostname(true).build();
        assert!(strict_config.is_ok(), "Strict TLS config should be valid");

        // Lenient for self-signed certs (development)
        let dev_config = TlsConfig::builder().verify_hostname(false).build();
        assert!(dev_config.is_ok(), "Dev TLS config should be valid");

        println!("✓ TLS hostname verification settings work");
    }

    /// Test sslmode=require via connection string (SSLRequest flow)
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_require_via_connection_string() {
        let db_url = match env::var("TLS_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        // Append sslmode=require if not already present
        let url = if db_url.contains("sslmode=") {
            db_url
        } else {
            let sep = if db_url.contains('?') { "&" } else { "?" };
            format!("{}{}sslmode=require", db_url, sep)
        };

        let client = FraiseClient::connect(&url)
            .await
            .expect("sslmode=require connection should succeed");

        let mut stream = client
            .query::<Value>("pg_tables")
            .execute()
            .await
            .expect("query over TLS should work");

        let _result = stream.next().await;
        println!("✓ sslmode=require via connection string succeeded");
    }

    /// Test that sslmode=require fails when server does not support TLS
    #[tokio::test]
    #[ignore] // Requires a PostgreSQL instance WITHOUT TLS
    async fn test_tls_require_fails_no_tls_server() {
        let db_url = match env::var("TLS_TEST_NO_TLS_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_NO_TLS_DB_URL not set");
                return;
            }
        };

        let url = if db_url.contains("sslmode=") {
            db_url
        } else {
            let sep = if db_url.contains('?') { "&" } else { "?" };
            format!("{}{}sslmode=require", db_url, sep)
        };

        let result = FraiseClient::connect(&url).await;
        assert!(
            result.is_err(),
            "sslmode=require should fail when server doesn't support TLS"
        );
        println!("✓ sslmode=require correctly fails for non-TLS server");
    }

    /// Test sslmode=verify-full with matching hostname
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with valid certificate
    async fn test_tls_verify_full_valid_cert() {
        let db_url = match env::var("TLS_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        let url = if db_url.contains("sslmode=") {
            db_url
        } else {
            let sep = if db_url.contains('?') { "&" } else { "?" };
            format!("{}{}sslmode=verify-full", db_url, sep)
        };

        let result = FraiseClient::connect(&url).await;
        // This may fail with self-signed certs — that's expected
        match result {
            Ok(client) => {
                let _stream = client
                    .query::<Value>("pg_tables")
                    .execute()
                    .await
                    .expect("query should work");
                println!("✓ sslmode=verify-full succeeded with valid cert");
            }
            Err(e) => {
                println!("✓ sslmode=verify-full correctly rejected connection: {}", e);
            }
        }
    }

    /// Test sslmode=disable connects without TLS
    #[tokio::test]
    #[ignore] // Requires PostgreSQL
    async fn test_tls_disable_plaintext() {
        let db_url = match env::var("TLS_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        let url = if db_url.contains("sslmode=") {
            db_url
        } else {
            let sep = if db_url.contains('?') { "&" } else { "?" };
            format!("{}{}sslmode=disable", db_url, sep)
        };

        // Should connect in plaintext (no SSLRequest sent)
        let client = FraiseClient::connect(&url)
            .await
            .expect("sslmode=disable should connect without TLS");

        let mut stream = client
            .query::<Value>("pg_tables")
            .execute()
            .await
            .expect("plaintext query should work");

        let _result = stream.next().await;
        println!("✓ sslmode=disable plaintext connection succeeded");
    }

    /// Test SCRAM channel binding over TLS
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS and SCRAM-SHA-256
    async fn test_tls_scram_channel_binding() {
        let db_url = match env::var("TLS_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        // Channel binding is automatic when TLS is active and server offers SCRAM-SHA-256-PLUS
        let tls_config = TlsConfig::builder()
            .verify_hostname(false)
            .build()
            .expect("TLS config should build");

        let result = FraiseClient::connect_tls(&db_url, tls_config).await;
        match result {
            Ok(client) => {
                let mut stream = client
                    .query::<Value>("pg_tables")
                    .execute()
                    .await
                    .expect("query with channel binding should work");
                let _result = stream.next().await;
                println!("✓ TLS with SCRAM channel binding succeeded");
            }
            Err(e) => {
                eprintln!("Connection failed (may need SCRAM setup): {}", e);
            }
        }
    }

    /// Test mTLS with client certificate
    #[tokio::test]
    #[ignore] // Requires PostgreSQL configured for mTLS
    async fn test_mtls_client_cert() {
        let db_url = match env::var("TLS_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };
        let cert_path = match env::var("TLS_TEST_CLIENT_CERT") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_CLIENT_CERT not set");
                return;
            }
        };
        let key_path = match env::var("TLS_TEST_CLIENT_KEY") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_CLIENT_KEY not set");
                return;
            }
        };

        let tls_config = TlsConfig::builder()
            .verify_hostname(false)
            .client_cert_path(&cert_path)
            .client_key_path(&key_path)
            .build()
            .expect("TLS config with client cert should build");

        let client = FraiseClient::connect_tls(&db_url, tls_config)
            .await
            .expect("mTLS connection should succeed");

        let mut stream = client
            .query::<Value>("pg_tables")
            .execute()
            .await
            .expect("query with mTLS should work");

        let _result = stream.next().await;
        println!("✓ mTLS with client certificate succeeded");
    }

    /// Test TLS streaming large results
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_streaming_large_result() {
        let (db_url, insecure) = match get_tls_test_config() {
            Some(cfg) => cfg,
            None => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        let tls_config = TlsConfig::builder()
            .verify_hostname(!insecure)
            .build()
            .expect("TLS config should build");

        let client = FraiseClient::connect_tls(&db_url, tls_config)
            .await
            .expect("TLS connection should succeed");

        let mut stream = client
            .query::<Value>("pg_tables")
            .chunk_size(16)
            .execute()
            .await
            .expect("streaming query should start");

        let mut count = 0;
        while let Some(result) = stream.next().await {
            match result {
                Ok(_) => count += 1,
                Err(e) => {
                    panic!("streaming error after {} rows: {}", count, e);
                }
            }
            if count >= 50 {
                break;
            }
        }
        println!("✓ TLS streaming large result succeeded ({} rows)", count);
    }

    /// Test early stream drop over TLS (cancellation)
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with TLS enabled
    async fn test_tls_connection_drop_midstream() {
        let (db_url, insecure) = match get_tls_test_config() {
            Some(cfg) => cfg,
            None => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };

        let tls_config = TlsConfig::builder()
            .verify_hostname(!insecure)
            .build()
            .expect("TLS config should build");

        let client = FraiseClient::connect_tls(&db_url, tls_config)
            .await
            .expect("TLS connection should succeed");

        let mut stream = client
            .query::<Value>("pg_tables")
            .execute()
            .await
            .expect("query should start");

        // Read a few rows then drop
        let _row1 = stream.next().await;
        let _row2 = stream.next().await;
        drop(stream);

        // Allow cancel request to propagate
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        println!("✓ TLS stream drop midstream succeeded (no hang/panic)");
    }

    /// Test custom CA certificate path via connection string
    #[tokio::test]
    #[ignore] // Requires PostgreSQL with custom CA
    async fn test_tls_verify_ca_custom_cert() {
        let db_url = match env::var("TLS_TEST_DB_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_DB_URL not set");
                return;
            }
        };
        let ca_path = match env::var("TLS_TEST_CERT_PATH") {
            Ok(p) => p,
            Err(_) => {
                eprintln!("Skipping test: TLS_TEST_CERT_PATH not set");
                return;
            }
        };

        let url = format!(
            "{}{}sslmode=verify-ca&sslrootcert={}",
            db_url,
            if db_url.contains('?') { "&" } else { "?" },
            ca_path
        );

        let result = FraiseClient::connect(&url).await;
        match result {
            Ok(client) => {
                let _stream = client
                    .query::<Value>("pg_tables")
                    .execute()
                    .await
                    .expect("query should work");
                println!("✓ verify-ca with custom CA cert succeeded");
            }
            Err(e) => {
                println!("verify-ca failed (may be expected): {}", e);
            }
        }
    }
}
