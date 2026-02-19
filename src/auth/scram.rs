//! SCRAM-SHA-256 authentication implementation
//!
//! Implements the SCRAM-SHA-256 (Salted Challenge Response Authentication Mechanism)
//! as defined in RFC 5802 for PostgreSQL authentication (Postgres 10+).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

/// SCRAM authentication error types
#[derive(Debug, Clone)]
pub enum ScramError {
    /// Invalid proof from server
    InvalidServerProof(String),
    /// Invalid server message format
    InvalidServerMessage(String),
    /// UTF-8 encoding/decoding error
    Utf8Error(String),
    /// Base64 decoding error
    Base64Error(String),
}

impl fmt::Display for ScramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScramError::InvalidServerProof(msg) => write!(f, "invalid server proof: {}", msg),
            ScramError::InvalidServerMessage(msg) => write!(f, "invalid server message: {}", msg),
            ScramError::Utf8Error(msg) => write!(f, "UTF-8 error: {}", msg),
            ScramError::Base64Error(msg) => write!(f, "Base64 error: {}", msg),
        }
    }
}

impl std::error::Error for ScramError {}

/// Channel binding type for SCRAM authentication
#[derive(Clone, Debug)]
pub enum ChannelBinding {
    /// No channel binding
    None,
    /// tls-server-end-point: SHA-256 hash of the server's DER-encoded certificate
    TlsServerEndPoint(Vec<u8>),
}

/// Internal state needed for SCRAM authentication
#[derive(Clone, Debug)]
pub struct ScramState {
    /// Combined authentication message (for verification)
    auth_message: Vec<u8>,
    /// Server key (for verification calculation)
    server_key: Vec<u8>,
}

/// SCRAM-SHA-256 client implementation
pub struct ScramClient {
    username: String,
    password: String,
    nonce: String,
    channel_binding: ChannelBinding,
}

impl ScramClient {
    /// Create a new SCRAM client without channel binding
    pub fn new(username: String, password: String) -> Self {
        Self::with_channel_binding(username, password, ChannelBinding::None)
    }

    /// Create a new SCRAM client with channel binding
    pub fn with_channel_binding(
        username: String,
        password: String,
        channel_binding: ChannelBinding,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let nonce_bytes: Vec<u8> = (0..24).map(|_| rng.gen()).collect();
        let nonce = BASE64.encode(&nonce_bytes);

        Self {
            username,
            password,
            nonce,
            channel_binding,
        }
    }

    /// GS2 header for the SCRAM exchange
    fn gs2_header(&self) -> &'static str {
        match self.channel_binding {
            ChannelBinding::None => "n",
            ChannelBinding::TlsServerEndPoint(_) => "p=tls-server-end-point",
        }
    }

    /// Generate client first message
    pub fn client_first(&self) -> String {
        format!("{},a={},r={}", self.gs2_header(), self.username, self.nonce)
    }

    /// Process server first message and generate client final message
    ///
    /// Returns (client_final_message, internal_state)
    pub fn client_final(&mut self, server_first: &str) -> Result<(String, ScramState), ScramError> {
        // Parse server first message: r=<client_nonce><server_nonce>,s=<salt>,i=<iterations>
        let (server_nonce, salt, iterations) = parse_server_first(server_first)?;

        // Verify server nonce starts with our client nonce
        if !server_nonce.starts_with(&self.nonce) {
            return Err(ScramError::InvalidServerMessage(
                "server nonce doesn't contain client nonce".to_string(),
            ));
        }

        // Decode salt and iterations
        let salt_bytes = BASE64
            .decode(&salt)
            .map_err(|_| ScramError::Base64Error("invalid salt encoding".to_string()))?;
        let iterations = iterations
            .parse::<u32>()
            .map_err(|_| ScramError::InvalidServerMessage("invalid iteration count".to_string()))?;

        // Build channel binding data for the c= field
        // RFC 5802: c = base64(gs2-header + channel-binding-data)
        let gs2_cbind = match &self.channel_binding {
            ChannelBinding::None => {
                // No channel binding: c = base64("n,,")
                b"n,,".to_vec()
            }
            ChannelBinding::TlsServerEndPoint(data) => {
                // tls-server-end-point: c = base64("p=tls-server-end-point,," + cb_data)
                let mut buf = b"p=tls-server-end-point,,".to_vec();
                buf.extend_from_slice(data);
                buf
            }
        };
        let channel_binding = BASE64.encode(&gs2_cbind);

        // Build client final without proof
        let client_final_without_proof = format!("c={},r={}", channel_binding, server_nonce);

        // Build auth message for signature calculation
        let client_first_bare = format!("a={},r={}", self.username, self.nonce);
        let auth_message = format!(
            "{},{},{}",
            client_first_bare, server_first, client_final_without_proof
        );

        // Calculate proof
        let proof = calculate_client_proof(
            &self.password,
            &salt_bytes,
            iterations,
            auth_message.as_bytes(),
        )?;

        // Calculate server signature for later verification
        let server_key = calculate_server_key(&self.password, &salt_bytes, iterations)?;

        // Build client final message
        let client_final = format!("{},p={}", client_final_without_proof, BASE64.encode(&proof));

        let state = ScramState {
            auth_message: auth_message.into_bytes(),
            server_key,
        };

        Ok((client_final, state))
    }

    /// Verify server final message and confirm authentication
    pub fn verify_server_final(
        &self,
        server_final: &str,
        state: &ScramState,
    ) -> Result<(), ScramError> {
        // Parse server final: v=<server_signature>
        let server_sig_encoded = server_final
            .strip_prefix("v=")
            .ok_or_else(|| ScramError::InvalidServerMessage("missing 'v=' prefix".to_string()))?;

        let server_signature = BASE64.decode(server_sig_encoded).map_err(|_| {
            ScramError::Base64Error("invalid server signature encoding".to_string())
        })?;

        // Calculate expected server signature
        let expected_signature = calculate_server_signature(&state.server_key, &state.auth_message);

        // Constant-time comparison
        if constant_time_compare(&server_signature, &expected_signature) {
            Ok(())
        } else {
            Err(ScramError::InvalidServerProof(
                "server signature verification failed".to_string(),
            ))
        }
    }
}

/// Parse server first message format: r=<nonce>,s=<salt>,i=<iterations>
fn parse_server_first(msg: &str) -> Result<(String, String, String), ScramError> {
    let mut nonce = String::new();
    let mut salt = String::new();
    let mut iterations = String::new();

    for part in msg.split(',') {
        if let Some(value) = part.strip_prefix("r=") {
            nonce = value.to_string();
        } else if let Some(value) = part.strip_prefix("s=") {
            salt = value.to_string();
        } else if let Some(value) = part.strip_prefix("i=") {
            iterations = value.to_string();
        }
    }

    if nonce.is_empty() || salt.is_empty() || iterations.is_empty() {
        return Err(ScramError::InvalidServerMessage(
            "missing required fields in server first message".to_string(),
        ));
    }

    Ok((nonce, salt, iterations))
}

/// Calculate SCRAM client proof
fn calculate_client_proof(
    password: &str,
    salt: &[u8],
    iterations: u32,
    auth_message: &[u8],
) -> Result<Vec<u8>, ScramError> {
    // SaltedPassword := PBKDF2(password, salt, iterations, HMAC-SHA256)
    let password_bytes = password.as_bytes();
    let mut salted_password = vec![0u8; 32]; // SHA256 produces 32 bytes
    let _ = pbkdf2::<HmacSha256>(password_bytes, salt, iterations, &mut salted_password);

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    let mut client_key_hmac = HmacSha256::new_from_slice(&salted_password)
        .map_err(|_| ScramError::Utf8Error("HMAC key error".to_string()))?;
    client_key_hmac.update(b"Client Key");
    let client_key = client_key_hmac.finalize().into_bytes();

    // StoredKey := SHA256(ClientKey)
    let stored_key = Sha256::digest(client_key.to_vec().as_slice());

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    let mut client_sig_hmac = HmacSha256::new_from_slice(&stored_key)
        .map_err(|_| ScramError::Utf8Error("HMAC key error".to_string()))?;
    client_sig_hmac.update(auth_message);
    let client_signature = client_sig_hmac.finalize().into_bytes();

    // ClientProof := ClientKey XOR ClientSignature
    let mut proof = client_key.to_vec();
    for (proof_byte, sig_byte) in proof.iter_mut().zip(client_signature.iter()) {
        *proof_byte ^= sig_byte;
    }

    Ok(proof.to_vec())
}

/// Calculate server key for server signature verification
fn calculate_server_key(
    password: &str,
    salt: &[u8],
    iterations: u32,
) -> Result<Vec<u8>, ScramError> {
    // SaltedPassword := PBKDF2(password, salt, iterations, HMAC-SHA256)
    let password_bytes = password.as_bytes();
    let mut salted_password = vec![0u8; 32];
    let _ = pbkdf2::<HmacSha256>(password_bytes, salt, iterations, &mut salted_password);

    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let mut server_key_hmac = HmacSha256::new_from_slice(&salted_password)
        .map_err(|_| ScramError::Utf8Error("HMAC key error".to_string()))?;
    server_key_hmac.update(b"Server Key");

    Ok(server_key_hmac.finalize().into_bytes().to_vec())
}

/// Calculate server signature for verification
fn calculate_server_signature(server_key: &[u8], auth_message: &[u8]) -> Vec<u8> {
    let mut hmac = HmacSha256::new_from_slice(server_key).expect("HMAC key should be valid");
    hmac.update(auth_message);
    hmac.finalize().into_bytes().to_vec()
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scram_client_creation() {
        let client = ScramClient::new("user".to_string(), "password".to_string());
        assert_eq!(client.username, "user");
        assert_eq!(client.password, "password");
        assert!(!client.nonce.is_empty());
    }

    #[test]
    fn test_client_first_message_format() {
        let client = ScramClient::new("alice".to_string(), "secret".to_string());
        let first = client.client_first();

        assert!(first.starts_with("n,a=alice,r="));
        assert!(first.len() > 20);
    }

    #[test]
    fn test_parse_server_first_valid() {
        let server_first = "r=client_nonce_server_nonce,s=aW1hZ2luYXJ5c2FsdA==,i=4096";
        let (nonce, salt, iterations) = parse_server_first(server_first).unwrap();

        assert_eq!(nonce, "client_nonce_server_nonce");
        assert_eq!(salt, "aW1hZ2luYXJ5c2FsdA==");
        assert_eq!(iterations, "4096");
    }

    #[test]
    fn test_parse_server_first_invalid() {
        let server_first = "r=nonce,s=salt"; // missing iterations
        assert!(parse_server_first(server_first).is_err());
    }

    #[test]
    fn test_constant_time_compare_equal() {
        let a = b"test_value";
        let b_arr = b"test_value";
        assert!(constant_time_compare(a, b_arr));
    }

    #[test]
    fn test_constant_time_compare_different() {
        let a = b"test_value";
        let b_arr = b"test_wrong";
        assert!(!constant_time_compare(a, b_arr));
    }

    #[test]
    fn test_constant_time_compare_different_length() {
        let a = b"test";
        let b_arr = b"test_longer";
        assert!(!constant_time_compare(a, b_arr));
    }

    #[test]
    fn test_client_first_with_channel_binding() {
        let client = ScramClient::with_channel_binding(
            "alice".to_string(),
            "secret".to_string(),
            ChannelBinding::TlsServerEndPoint(vec![1, 2, 3, 4]),
        );
        let first = client.client_first();
        // GS2 header should be p=tls-server-end-point
        assert!(first.starts_with("p=tls-server-end-point,a=alice,r="));
    }

    #[test]
    fn test_client_first_without_channel_binding() {
        let client = ScramClient::new("alice".to_string(), "secret".to_string());
        let first = client.client_first();
        // GS2 header should be n (no channel binding)
        assert!(first.starts_with("n,a=alice,r="));
    }

    #[test]
    fn test_client_final_with_channel_binding() {
        // Channel binding data should be included in the c= field
        let binding_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let mut client = ScramClient::with_channel_binding(
            "user".to_string(),
            "password".to_string(),
            ChannelBinding::TlsServerEndPoint(binding_data.clone()),
        );
        let _first = client.client_first();

        let server_nonce = format!("{}server_part", client.nonce);
        let server_first = format!("r={},s={},i=4096", server_nonce, BASE64.encode(b"salty"));

        let (client_final, _state) = client.client_final(&server_first).unwrap();

        // The c= field should contain base64 of the GS2 header + channel binding data
        let c_value = client_final
            .split(',')
            .find(|s| s.starts_with("c="))
            .unwrap()
            .strip_prefix("c=")
            .unwrap();
        let decoded = BASE64.decode(c_value).unwrap();
        // Should start with "p=tls-server-end-point,,"
        let header = b"p=tls-server-end-point,,";
        assert!(decoded.starts_with(header));
        // And end with the channel binding data
        assert_eq!(&decoded[header.len()..], &binding_data);
    }

    #[test]
    fn test_scram_client_final_flow() {
        let mut client = ScramClient::new("user".to_string(), "password".to_string());
        let _client_first = client.client_first();

        // Simulate server response
        let server_nonce = format!("{}server_nonce_part", client.nonce);
        let server_first = format!("r={},s={},i=4096", server_nonce, BASE64.encode(b"salty"));

        // Should succeed with valid format
        let result = client.client_final(&server_first);
        assert!(result.is_ok());

        let (client_final, state) = result.unwrap();
        assert!(client_final.starts_with("c="));
        assert!(!state.auth_message.is_empty());
    }

    // ── Server First Message Parsing Edge Cases ──────────────────────

    #[test]
    fn test_parse_server_first_missing_nonce() {
        let result = parse_server_first("s=c2FsdA==,i=4096");
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_parse_server_first_missing_salt() {
        let result = parse_server_first("r=nonce,i=4096");
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_parse_server_first_missing_iterations() {
        let result = parse_server_first("r=nonce,s=c2FsdA==");
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_parse_server_first_empty_string() {
        let result = parse_server_first("");
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_parse_server_first_empty_values() {
        let result = parse_server_first("r=,s=,i=");
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_parse_server_first_extra_fields_ignored() {
        let result = parse_server_first("r=nonce123,x=junk,s=c2FsdA==,i=4096");
        let (nonce, salt, iterations) = result.unwrap();
        assert_eq!(nonce, "nonce123");
        assert_eq!(salt, "c2FsdA==");
        assert_eq!(iterations, "4096");
    }

    #[test]
    fn test_parse_server_first_different_field_order() {
        let result = parse_server_first("s=c2FsdA==,i=4096,r=nonce123");
        let (nonce, salt, iterations) = result.unwrap();
        assert_eq!(nonce, "nonce123");
        assert_eq!(salt, "c2FsdA==");
        assert_eq!(iterations, "4096");
    }

    // ── Nonce Tampering Detection ────────────────────────────────────

    #[test]
    fn test_client_final_nonce_prefix_mismatch() {
        let mut client = ScramClient::new("user".to_string(), "pass".to_string());
        let _first = client.client_first();

        let server_first = format!(
            "r=TAMPERED_NONCE_server_ext,s={},i=4096",
            BASE64.encode(b"salty")
        );
        let result = client.client_final(&server_first);
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_client_final_nonce_identical_to_client() {
        let mut client = ScramClient::new("user".to_string(), "pass".to_string());
        let _first = client.client_first();
        let client_nonce = client.nonce.clone();

        // Server nonce == client nonce (no extension) — prefix still matches
        let server_first = format!("r={},s={},i=4096", client_nonce, BASE64.encode(b"salty"));
        let result = client.client_final(&server_first);
        assert!(result.is_ok());
    }

    // ── Invalid Salt and Iterations ──────────────────────────────────

    #[test]
    fn test_client_final_invalid_base64_salt() {
        let mut client = ScramClient::new("user".to_string(), "pass".to_string());
        let _first = client.client_first();

        let server_first = format!("r={}server_ext,s=!!!not-base64!!!,i=4096", client.nonce);
        let result = client.client_final(&server_first);
        assert!(matches!(result, Err(ScramError::Base64Error(_))));
    }

    #[test]
    fn test_client_final_non_numeric_iterations() {
        let mut client = ScramClient::new("user".to_string(), "pass".to_string());
        let _first = client.client_first();

        let server_first = format!(
            "r={}server_ext,s={},i=abc",
            client.nonce,
            BASE64.encode(b"salty")
        );
        let result = client.client_final(&server_first);
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_client_final_zero_iterations() {
        let mut client = ScramClient::new("user".to_string(), "pass".to_string());
        let _first = client.client_first();

        let server_first = format!(
            "r={}server_ext,s={},i=0",
            client.nonce,
            BASE64.encode(b"salty")
        );
        // PBKDF2 accepts 0 iterations — not our job to enforce a minimum
        let result = client.client_final(&server_first);
        assert!(result.is_ok());
    }

    // ── Server Final Message Verification ────────────────────────────

    #[test]
    fn test_verify_server_final_missing_v_prefix() {
        let client = ScramClient::new("user".to_string(), "pass".to_string());
        let state = ScramState {
            auth_message: b"dummy".to_vec(),
            server_key: vec![0; 32],
        };
        let result = client.verify_server_final("not_a_valid_response", &state);
        assert!(matches!(result, Err(ScramError::InvalidServerMessage(_))));
    }

    #[test]
    fn test_verify_server_final_empty_after_v() {
        let client = ScramClient::new("user".to_string(), "pass".to_string());
        let state = ScramState {
            auth_message: b"dummy".to_vec(),
            server_key: vec![0; 32],
        };
        // "v=" with empty value decodes to 0 bytes, which won't match the 32-byte signature
        let result = client.verify_server_final("v=", &state);
        assert!(matches!(result, Err(ScramError::InvalidServerProof(_))));
    }

    #[test]
    fn test_verify_server_final_invalid_base64() {
        let client = ScramClient::new("user".to_string(), "pass".to_string());
        let state = ScramState {
            auth_message: b"dummy".to_vec(),
            server_key: vec![0; 32],
        };
        let result = client.verify_server_final("v=!!!invalid!!!", &state);
        assert!(matches!(result, Err(ScramError::Base64Error(_))));
    }

    #[test]
    fn test_verify_server_final_wrong_signature() {
        let client = ScramClient::new("user".to_string(), "pass".to_string());
        let state = ScramState {
            auth_message: b"auth_msg".to_vec(),
            server_key: vec![0x42; 32],
        };
        // Valid base64, but wrong signature bytes
        let wrong_sig = BASE64.encode(vec![0xFF; 32]);
        let result = client.verify_server_final(&format!("v={}", wrong_sig), &state);
        assert!(matches!(result, Err(ScramError::InvalidServerProof(_))));
    }

    #[test]
    fn test_verify_server_final_correct_signature() {
        let mut client = ScramClient::new("user".to_string(), "password".to_string());
        let _first = client.client_first();

        let server_nonce = format!("{}server_ext", client.nonce);
        let server_first = format!("r={},s={},i=4096", server_nonce, BASE64.encode(b"salty"));

        let (_client_final, state) = client.client_final(&server_first).unwrap();

        // Compute the real server signature from the state
        let expected = calculate_server_signature(&state.server_key, &state.auth_message);
        let server_final = format!("v={}", BASE64.encode(&expected));

        let result = client.verify_server_final(&server_final, &state);
        assert!(result.is_ok());
    }

    // ── Constant-Time Comparison Edge Cases ──────────────────────────

    #[test]
    fn test_constant_time_compare_both_empty() {
        assert!(constant_time_compare(&[], &[]));
    }

    #[test]
    fn test_constant_time_compare_one_empty() {
        assert!(!constant_time_compare(&[], &[1]));
    }

    #[test]
    fn test_constant_time_compare_single_bit_flip() {
        let a = vec![0b1010_1010; 32];
        let mut b = a.clone();
        b[15] ^= 0b0000_0001; // flip one bit
        assert!(!constant_time_compare(&a, &b));
    }

    // ── Channel Binding Edge Case ────────────────────────────────────

    #[test]
    fn test_channel_binding_empty_data() {
        let mut client = ScramClient::with_channel_binding(
            "user".to_string(),
            "pass".to_string(),
            ChannelBinding::TlsServerEndPoint(vec![]),
        );
        let _first = client.client_first();

        let server_nonce = format!("{}server_ext", client.nonce);
        let server_first = format!("r={},s={},i=4096", server_nonce, BASE64.encode(b"salty"));

        let (client_final, _state) = client.client_final(&server_first).unwrap();

        let c_value = client_final
            .split(',')
            .find(|s| s.starts_with("c="))
            .unwrap()
            .strip_prefix("c=")
            .unwrap();
        let decoded = BASE64.decode(c_value).unwrap();
        // With empty binding data, the c= field should contain just the header
        assert_eq!(decoded, b"p=tls-server-end-point,,");
    }

    // ── Special Characters in Credentials ────────────────────────────

    #[test]
    fn test_client_final_empty_password() {
        let mut client = ScramClient::new("user".to_string(), String::new());
        let _first = client.client_first();

        let server_nonce = format!("{}server_ext", client.nonce);
        let server_first = format!("r={},s={},i=4096", server_nonce, BASE64.encode(b"salty"));

        let result = client.client_final(&server_first);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_final_unicode_credentials() {
        let mut client = ScramClient::new("héllo".to_string(), "pässwörd™".to_string());
        let _first = client.client_first();

        let server_nonce = format!("{}server_ext", client.nonce);
        let server_first = format!("r={},s={},i=4096", server_nonce, BASE64.encode(b"salty"));

        let result = client.client_final(&server_first);
        assert!(result.is_ok());
    }
}
