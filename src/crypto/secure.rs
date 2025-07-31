//! Security hardening for banking-grade cryptographic operations
//!
//! Enhanced with comprehensive token validation and management for millions of users

use crate::{crypto_error, Result};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Secure salt manager with enhanced token operations
#[derive(Clone)]
pub struct SecureSaltManager {
    voter_salt: Vec<u8>,
    token_salt: Vec<u8>,
}

impl SecureSaltManager {
    /// Create salt manager from environment variables
    ///
    /// **CRITICAL**: These must be set in production:
    /// - CRYPTO_VOTER_SALT (minimum 32 bytes, base64 encoded)
    /// - CRYPTO_TOKEN_SALT (minimum 32 bytes, base64 encoded)
    pub fn from_env() -> Result<Self> {
        let voter_salt = std::env::var("CRYPTO_VOTER_SALT")
            .map_err(|_| crypto_error!("CRYPTO_VOTER_SALT environment variable required"))?;

        let token_salt = std::env::var("CRYPTO_TOKEN_SALT")
            .map_err(|_| crypto_error!("CRYPTO_TOKEN_SALT environment variable required"))?;

        // Decode from base64 and validate length
        use base64::Engine;
        let voter_salt = base64::engine::general_purpose::STANDARD
            .decode(&voter_salt)
            .map_err(|_| crypto_error!("CRYPTO_VOTER_SALT must be valid base64"))?;

        let token_salt = base64::engine::general_purpose::STANDARD
            .decode(&token_salt)
            .map_err(|_| crypto_error!("CRYPTO_TOKEN_SALT must be valid base64"))?;

        if voter_salt.len() < 32 {
            return Err(crypto_error!("CRYPTO_VOTER_SALT must be at least 32 bytes"));
        }

        if token_salt.len() < 32 {
            return Err(crypto_error!("CRYPTO_TOKEN_SALT must be at least 32 bytes"));
        }

        Ok(Self {
            voter_salt,
            token_salt,
        })
    }

    /// Create for testing with secure random salts
    pub fn for_testing() -> Self {
        let mut rng = rand::thread_rng();
        let mut voter_salt = vec![0u8; 32];
        let mut token_salt = vec![0u8; 32];

        rng.fill_bytes(&mut voter_salt);
        rng.fill_bytes(&mut token_salt);

        Self {
            voter_salt,
            token_salt,
        }
    }

    /// Generate voter hash with timestamp for replay protection (deterministic)
    ///
    /// CRITICAL: This MUST be deterministic - same voter always gets same hash
    /// regardless of timestamp (timestamp only used for replay protection)
    pub fn hash_voter_identity_secure(
        &self,
        bank_id: &str,
        election_id: &Uuid,
        timestamp: u64,
        max_age_seconds: u64,
    ) -> Result<[u8; 32]> {
        // Check timestamp freshness (prevent replay attacks)
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        if current_time.saturating_sub(timestamp) > max_age_seconds {
            return Err(crypto_error!("Timestamp too old - possible replay attack"));
        }

        // DETERMINISTIC HASH: timestamp NOT included in hash
        // (timestamp only for replay protection, not hash generation)
        let mut hasher = blake3::Hasher::new_keyed(&self.voter_salt[..32].try_into().unwrap());
        hasher.update(bank_id.as_bytes());
        hasher.update(election_id.as_bytes());
        // NOTE: timestamp intentionally NOT included to ensure deterministic hashes

        Ok(hasher.finalize().into())
    }

    /// Generate secure voting token with expiration
    pub fn generate_voting_token_secure(
        &self,
        voter_hash: &[u8; 32],
        election_id: &Uuid,
        expires_at: u64,
    ) -> Result<([u8; 32], [u8; 16])> {
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);

        // Use keyed hash for token generation
        let mut hasher = blake3::Hasher::new_keyed(&self.token_salt[..32].try_into().unwrap());
        hasher.update(voter_hash);
        hasher.update(election_id.as_bytes());
        hasher.update(&nonce);
        hasher.update(&expires_at.to_le_bytes());

        let token_hash = hasher.finalize().into();

        Ok((token_hash, nonce))
    }

    /// Validate a voting token by regenerating and comparing
    ///
    /// This is the critical security function that prevents token forgery
    pub fn validate_voting_token_secure(
        &self,
        provided_token_hash: &[u8; 32],
        nonce: &[u8; 16],
        voter_hash: &[u8; 32],
        election_id: &Uuid,
        expires_at: u64,
        current_timestamp: u64,
    ) -> Result<bool> {
        // Check if token has expired
        if current_timestamp > expires_at {
            return Ok(false); // Expired token
        }

        // Regenerate the expected token hash
        let mut hasher = blake3::Hasher::new_keyed(&self.token_salt[..32].try_into().unwrap());
        hasher.update(voter_hash);
        hasher.update(election_id.as_bytes());
        hasher.update(nonce);
        hasher.update(&expires_at.to_le_bytes());

        let expected_token_hash = *hasher.finalize().as_bytes();

        // Constant-time comparison to prevent timing attacks
        Ok(SecureMemory::constant_time_eq(provided_token_hash, &expected_token_hash))
    }

    /// Generate a secure session token (for user sessions, not voting)
    pub fn generate_session_token(&self) -> Result<([u8; 32], u64)> {
        let mut rng = rand::thread_rng();
        let mut session_data = [0u8; 32];
        rng.fill_bytes(&mut session_data);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        // Hash with salt for additional security
        let mut hasher = blake3::Hasher::new_keyed(&self.token_salt[..32].try_into().unwrap());
        hasher.update(&session_data);
        hasher.update(&timestamp.to_le_bytes());

        let session_token = hasher.finalize().into();

        Ok((session_token, timestamp))
    }

    /// Validate voter hash format
    pub fn validate_voter_hash_format(&self, voter_hash: &str) -> Result<[u8; 32]> {
        let decoded = hex::decode(voter_hash)
            .map_err(|_| crypto_error!("Invalid voter hash hex format"))?;

        if decoded.len() != 32 {
            return Err(crypto_error!("Voter hash must be exactly 32 bytes"));
        }

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&decoded);
        Ok(hash_array)
    }
}

/// Memory-safe cryptographic key pair
#[derive(Clone, Debug)]
pub struct SecureKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    #[allow(dead_code)]
    created_at: u64,
    expires_at: Option<u64>,
}

impl Drop for SecureKeyPair {
    fn drop(&mut self) {
        // TODO: Add memory clearing in next iteration
        tracing::debug!("SecureKeyPair dropped (memory clearing to be added)");
    }
}

impl SecureKeyPair {
    /// Generate new key pair with expiration
    pub fn generate_with_expiration(expires_in_seconds: Option<u64>) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        let expires_at = expires_in_seconds.map(|exp| created_at + exp);

        Ok(Self {
            signing_key,
            verifying_key,
            created_at,
            expires_at,
        })
    }

    /// Check if key pair has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            current_time > expires_at
        } else {
            false
        }
    }

    /// Get public key
    pub fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign message with timestamp and anti-replay protection
    pub fn sign_with_timestamp(&self, message: &[u8]) -> Result<([u8; 64], u64)> {
        if self.is_expired() {
            return Err(crypto_error!("Key pair has expired"));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        // Include timestamp in signature to prevent replay
        let mut signed_data = Vec::with_capacity(message.len() + 8);
        signed_data.extend_from_slice(message);
        signed_data.extend_from_slice(&timestamp.to_le_bytes());

        let signature = self.signing_key.sign(&signed_data);

        Ok((signature.to_bytes(), timestamp))
    }

    /// Verify signature with timestamp validation
    pub fn verify_with_timestamp(
        &self,
        message: &[u8],
        signature: &[u8; 64],
        timestamp: u64,
        max_age_seconds: u64,
    ) -> Result<()> {
        // Check timestamp freshness
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        if current_time.saturating_sub(timestamp) > max_age_seconds {
            return Err(crypto_error!("Signature timestamp too old"));
        }

        // Reconstruct signed data
        let mut signed_data = Vec::with_capacity(message.len() + 8);
        signed_data.extend_from_slice(message);
        signed_data.extend_from_slice(&timestamp.to_le_bytes());

        let ed25519_sig = Ed25519Signature::from_slice(signature)
            .map_err(|_| crypto_error!("Invalid signature format"))?;

        self.verifying_key
            .verify(&signed_data, &ed25519_sig)
            .map_err(|_| crypto_error!("Signature verification failed"))
    }
}

/// Rate limiter for cryptographic operations
pub struct CryptoRateLimiter {
    max_operations_per_second: u32,
    operations: VecDeque<u64>,
}

impl CryptoRateLimiter {
    /// Create new rate limiter
    pub fn new(max_operations_per_second: u32) -> Self {
        Self {
            max_operations_per_second,
            operations: VecDeque::new(),
        }
    }

    /// Check if operation is allowed (prevents timing attacks)
    pub fn check_rate_limit(&mut self) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        // Remove operations older than 1 second
        while let Some(&front_time) = self.operations.front() {
            if current_time - front_time >= 1 {
                self.operations.pop_front();
            } else {
                break;
            }
        }

        // Check if we're within rate limit
        if self.operations.len() >= self.max_operations_per_second as usize {
            return Err(crypto_error!("Rate limit exceeded"));
        }

        // Add current operation
        self.operations.push_back(current_time);

        Ok(())
    }
}

/// Secure memory utilities
pub struct SecureMemory;

impl SecureMemory {
    /// Securely compare two byte arrays in constant time
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }

    /// Generate cryptographically secure random bytes
    pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_salt_manager() {
        let salt_manager = SecureSaltManager::for_testing();
        let bank_id = "CZ1234567890";
        let election_id = Uuid::new_v4();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hash1 = salt_manager
            .hash_voter_identity_secure(bank_id, &election_id, timestamp, 300)
            .unwrap();

        let hash2 = salt_manager
            .hash_voter_identity_secure(bank_id, &election_id, timestamp, 300)
            .unwrap();

        assert_eq!(hash1, hash2);

        // Test replay protection
        let old_timestamp = timestamp - 400; // 400 seconds ago
        assert!(
            salt_manager
                .hash_voter_identity_secure(bank_id, &election_id, old_timestamp, 300)
                .is_err()
        );
    }

    #[test]
    fn test_voting_token_generation_and_validation() {
        let salt_manager = SecureSaltManager::for_testing();
        let voter_hash = [1u8; 32];
        let election_id = Uuid::new_v4();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = current_time + 1800; // 30 minutes

        // Generate token
        let (token_hash, nonce) = salt_manager
            .generate_voting_token_secure(&voter_hash, &election_id, expires_at)
            .unwrap();

        // Validate token (should succeed)
        let is_valid = salt_manager
            .validate_voting_token_secure(
                &token_hash,
                &nonce,
                &voter_hash,
                &election_id,
                expires_at,
                current_time,
            )
            .unwrap();

        assert!(is_valid, "Token validation should succeed");

        // Test with wrong voter hash (should fail)
        let wrong_voter = [2u8; 32];
        let is_invalid = salt_manager
            .validate_voting_token_secure(
                &token_hash,
                &nonce,
                &wrong_voter,
                &election_id,
                expires_at,
                current_time,
            )
            .unwrap();

        assert!(!is_invalid, "Token validation should fail with wrong voter");

        // Test with wrong election (should fail)
        let wrong_election = Uuid::new_v4();
        let is_invalid2 = salt_manager
            .validate_voting_token_secure(
                &token_hash,
                &nonce,
                &voter_hash,
                &wrong_election,
                expires_at,
                current_time,
            )
            .unwrap();

        assert!(!is_invalid2, "Token validation should fail with wrong election");

        // Test with expired timestamp (should fail)
        let expired_time = expires_at + 1;
        let is_expired = salt_manager
            .validate_voting_token_secure(
                &token_hash,
                &nonce,
                &voter_hash,
                &election_id,
                expires_at,
                expired_time,
            )
            .unwrap();

        assert!(!is_expired, "Token validation should fail when expired");
    }

    #[test]
    fn test_deterministic_voter_hashing() {
        let salt_manager = SecureSaltManager::for_testing();
        let bank_id = "CZ1234567890";
        let election_id = Uuid::new_v4();
        let base_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Same voter with different timestamps should get same hash
        let hash1 = salt_manager
            .hash_voter_identity_secure(bank_id, &election_id, base_time, 300)
            .unwrap();

        let hash2 = salt_manager
            .hash_voter_identity_secure(bank_id, &election_id, base_time + 60, 300)
            .unwrap();

        let hash3 = salt_manager
            .hash_voter_identity_secure(bank_id, &election_id, base_time + 120, 300)
            .unwrap();

        assert_eq!(hash1, hash2, "Same voter must get same hash regardless of timestamp");
        assert_eq!(hash1, hash3, "Same voter must get same hash regardless of timestamp");
        assert_eq!(hash2, hash3, "Same voter must get same hash regardless of timestamp");

        println!("✅ Voter hash is deterministic across different timestamps");
    }

    #[test]
    fn test_secure_key_pair() {
        let key_pair = SecureKeyPair::generate_with_expiration(Some(3600)).unwrap();
        assert!(!key_pair.is_expired());

        let message = b"test message";
        let (signature, timestamp) = key_pair.sign_with_timestamp(message).unwrap();

        key_pair
            .verify_with_timestamp(message, &signature, timestamp, 300)
            .unwrap();

        // Test timestamp validation
        let old_timestamp = timestamp - 400;
        assert!(
            key_pair
                .verify_with_timestamp(message, &signature, old_timestamp, 300)
                .is_err()
        );
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = CryptoRateLimiter::new(2); // 2 ops per second

        // First two operations should succeed
        assert!(limiter.check_rate_limit().is_ok());
        assert!(limiter.check_rate_limit().is_ok());

        // Third should fail
        assert!(limiter.check_rate_limit().is_err());
    }

    #[test]
    fn test_voter_hash_format_validation() {
        let salt_manager = SecureSaltManager::for_testing();

        // Valid 32-byte hex hash
        let valid_hash = hex::encode([1u8; 32]);
        let result = salt_manager.validate_voter_hash_format(&valid_hash);
        assert!(result.is_ok());

        // Invalid hex
        let invalid_hex = "invalid_hex_string";
        let result = salt_manager.validate_voter_hash_format(invalid_hex);
        assert!(result.is_err());

        // Wrong length
        let wrong_length = hex::encode([1u8; 16]); // Only 16 bytes
        let result = salt_manager.validate_voter_hash_format(&wrong_length);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_token_generation() {
        let salt_manager = SecureSaltManager::for_testing();

        let (token1, timestamp1) = salt_manager.generate_session_token().unwrap();
        let (token2, timestamp2) = salt_manager.generate_session_token().unwrap();

        // Tokens should be different
        assert_ne!(token1, token2);
        // Timestamps should be close but potentially different
        assert!(timestamp2 >= timestamp1);
    }

    #[test]
    fn test_token_nonce_uniqueness() {
        let salt_manager = SecureSaltManager::for_testing();
        let voter_hash = [1u8; 32];
        let election_id = Uuid::new_v4();
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 1800;

        // Generate multiple tokens for same voter
        let (token1, nonce1) = salt_manager
            .generate_voting_token_secure(&voter_hash, &election_id, expires_at)
            .unwrap();

        let (token2, nonce2) = salt_manager
            .generate_voting_token_secure(&voter_hash, &election_id, expires_at)
            .unwrap();

        // Tokens should be different due to different nonces
        assert_ne!(token1, token2, "Different tokens should be generated");
        assert_ne!(nonce1, nonce2, "Different nonces should be generated");
    }
}