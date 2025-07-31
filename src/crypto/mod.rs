//! Cryptographic primitives for the voting system

pub mod secure;
pub mod voting_lock;

use crate::{Result, crypto_error};
use blake3::Hasher;
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use uuid::Uuid;

pub use crate::types::{Hash, PublicKey, Signature};

// Re-export secure crypto types
pub use secure::{CryptoRateLimiter, SecureKeyPair, SecureMemory, SecureSaltManager};

/// Salt for voter hash generation (DEPRECATED - use SecureSaltManager)
#[deprecated(note = "Use SecureSaltManager::from_env() instead for production security")]
const DEFAULT_VOTER_SALT: &[u8] = b"vote_system_salt_change_in_production_2024";

/// Basic cryptographic key pair (DEPRECATED - use SecureKeyPair)
#[deprecated(note = "Use SecureKeyPair for production security")]
#[derive(Debug, Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a key pair from a seed (for deterministic generation)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> PublicKey {
        self.verifying_key.to_bytes()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature against this key pair's public key
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        let ed25519_sig = Ed25519Signature::from_slice(signature)
            .map_err(|e| crypto_error!("Invalid signature format: {}", e))?;

        self.verifying_key
            .verify(message, &ed25519_sig)
            .map_err(|e| crypto_error!("Signature verification failed: {}", e))
    }
}

/// Voter identity hasher for anonymization (DEPRECATED)
#[deprecated(note = "Use SecureSaltManager for production security")]
pub struct VoterHasher {
    salt: Vec<u8>,
}

impl VoterHasher {
    /// Create a new voter hasher with the provided salt
    pub fn new(salt: &[u8]) -> Self {
        Self {
            salt: salt.to_vec(),
        }
    }

    /// Create a voter hasher with the default salt (for development)
    pub fn with_default_salt() -> Self {
        Self::new(DEFAULT_VOTER_SALT)
    }

    /// Generate a voter hash from bank ID and election ID
    pub fn hash_voter_identity(&self, bank_id: &str, election_id: &Uuid) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.salt);
        hasher.update(bank_id.as_bytes());
        hasher.update(election_id.as_bytes());
        hasher.finalize().into()
    }

    /// Generate a voting token hash
    pub fn hash_token(&self, voter_hash: &Hash, election_id: &Uuid, nonce: &[u8]) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.salt);
        hasher.update(voter_hash);
        hasher.update(election_id.as_bytes());
        hasher.update(nonce);
        hasher.finalize().into()
    }
}

/// Secure random token generator
pub struct TokenGenerator {
    rng: rand::rngs::ThreadRng,
}

impl TokenGenerator {
    /// Create a new token generator
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    /// Generate a random 32-byte token
    pub fn generate_token(&mut self) -> [u8; 32] {
        let mut token = [0u8; 32];
        self.rng.fill_bytes(&mut token);
        token
    }

    /// Generate a random nonce for token generation
    pub fn generate_nonce(&mut self) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        self.rng.fill_bytes(&mut nonce);
        nonce
    }
}

impl Default for TokenGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Cryptographic utilities
pub struct CryptoUtils;

impl CryptoUtils {
    /// Hash arbitrary data with Blake3
    pub fn hash(data: &[u8]) -> Hash {
        blake3::hash(data).into()
    }

    /// Verify that two hashes are equal in constant time
    pub fn constant_time_eq(a: &Hash, b: &Hash) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    /// Generate a secure random UUID
    pub fn generate_uuid() -> Uuid {
        Uuid::new_v4()
    }

    /// Convert a hex string to a hash
    pub fn hex_to_hash(hex: &str) -> Result<Hash> {
        if hex.len() != 64 {
            return Err(crypto_error!(
                "Invalid hex length for hash: expected 64, got {}",
                hex.len()
            ));
        }

        let mut hash = [0u8; 32];
        hex::decode_to_slice(hex, &mut hash)
            .map_err(|e| crypto_error!("Invalid hex string: {}", e))?;
        Ok(hash)
    }

    /// Convert a hash to a hex string
    pub fn hash_to_hex(hash: &Hash) -> String {
        hex::encode(hash)
    }

    /// Convert a signature to a hex string
    pub fn signature_to_hex(signature: &Signature) -> String {
        hex::encode(signature)
    }

    /// Convert a hex string to a signature
    pub fn hex_to_signature(hex: &str) -> Result<Signature> {
        if hex.len() != 128 {
            return Err(crypto_error!(
                "Invalid hex length for signature: expected 128, got {}",
                hex.len()
            ));
        }

        let mut signature = [0u8; 64];
        hex::decode_to_slice(hex, &mut signature)
            .map_err(|e| crypto_error!("Invalid hex string: {}", e))?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_key_pair_generation() {
        let key_pair = KeyPair::generate().unwrap();
        let message = b"test message";

        let signature = key_pair.sign(message);
        assert!(key_pair.verify(message, &signature).is_ok());

        // Wrong message should fail
        let wrong_message = b"wrong message";
        assert!(key_pair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_voter_hasher() {
        let hasher = VoterHasher::with_default_salt();
        let bank_id = "test_bank_id_123";
        let election_id = Uuid::new_v4();

        let hash1 = hasher.hash_voter_identity(bank_id, &election_id);
        let hash2 = hasher.hash_voter_identity(bank_id, &election_id);

        // Same inputs should produce same hash
        assert_eq!(hash1, hash2);

        // Different election should produce different hash
        let different_election = Uuid::new_v4();
        let hash3 = hasher.hash_voter_identity(bank_id, &different_election);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_token_generator() {
        let mut generator = TokenGenerator::new();

        let token1 = generator.generate_token();
        let token2 = generator.generate_token();

        // Should generate different tokens
        assert_ne!(token1, token2);

        let nonce1 = generator.generate_nonce();
        let nonce2 = generator.generate_nonce();

        // Should generate different nonces
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_crypto_utils() {
        let data = b"test data";
        let hash = CryptoUtils::hash(data);

        // Same data should produce same hash
        let hash2 = CryptoUtils::hash(data);
        assert_eq!(hash, hash2);

        // Constant time equality
        assert!(CryptoUtils::constant_time_eq(&hash, &hash2));

        // Different data should produce different hash
        let different_data = b"different data";
        let different_hash = CryptoUtils::hash(different_data);
        assert!(!CryptoUtils::constant_time_eq(&hash, &different_hash));
    }

    #[test]
    fn test_hex_conversions() {
        let hash = [1u8; 32];
        let hex = CryptoUtils::hash_to_hex(&hash);
        let back_to_hash = CryptoUtils::hex_to_hash(&hex).unwrap();
        assert_eq!(hash, back_to_hash);

        let signature = [2u8; 64];
        let sig_hex = CryptoUtils::signature_to_hex(&signature);
        let back_to_signature = CryptoUtils::hex_to_signature(&sig_hex).unwrap();
        assert_eq!(signature, back_to_signature);
    }
}
