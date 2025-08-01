//! Cryptographic primitives for the voting system

pub mod secure;
pub mod voting_lock;
pub mod voting_token;
pub mod key_rotation;
pub mod security_context;
pub mod audit;
pub mod security_monitoring;

use crate::{Result, crypto_error};
use rand::RngCore;
use uuid::Uuid;

pub use crate::types::{Hash, PublicKey, Signature};

// Re-export secure crypto types
pub use secure::{CryptoRateLimiter, SecureKeyPair, SecureMemory, SecureSaltManager};

// Re-export enhanced voting lock types
pub use voting_lock::{VotingCompletion, VotingStatus, LogoutResult, VotingLockService, VotingMethod};

// Re-export voting token types
pub use voting_token::{
    VotingTokenService, VotingToken, TokenConfig, TokenState, TokenResult,
    TokenCleanupService, TokenServiceStats, TokenCleanupStats
};

// Re-export key rotation types
pub use key_rotation::{KeyRotationManager, KeyRotationService, KeyRotationConfig, KeyRotationStats};

// Re-export unified security context
pub use security_context::{
    SecurityContext, SecurityEvent, SecuritySession, SecurityLevel, SecurityMetrics,
    SecurityLoginResult, SecurityVoteResult, SecurityStatus, SecurityIncidentType, SecuritySeverity
};

// Re-export enhanced audit system
pub use audit::{
    EnhancedAuditSystem, AuditRecord, AuditTrail, AuditConfig, AuditQuery,
    ComplianceLevel, AuditLevel, ComplianceReport, ComplianceAuditRecord,
    AuditIntegrityReport, AuditCleanupReport, AuditTrailStatistics
};

// Re-export security monitoring system
pub use security_monitoring::{
    SecurityPerformanceMonitor, SecurityTimer, SecurityTiming, SecurityOperation,
    SecurityPerformanceMetrics, OperationTimingStats, AuthenticationPattern,
    DoSPattern, SecurityThreatAssessment, ThreatLevel, ThreatType,
    SecurityMonitoringConfig, LayerSecurityIntegration, LayerType,
    SecurityTimingContext, ResourceUsage
};

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