//! Secure configuration management for the voting system
//!
//! Loads sensitive configuration from environment variables with validation.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Security configuration for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Voter salt for anonymization (base64 encoded, minimum 32 bytes)
    pub voter_salt: String,

    /// Token salt for voting tokens (base64 encoded, minimum 32 bytes)
    pub token_salt: String,

    /// Key expiration time in seconds (default: 24 hours)
    pub key_expiry_seconds: u64,

    /// Maximum operations per second for rate limiting
    pub max_crypto_ops_per_second: u32,

    /// Maximum age for timestamps (prevent replay attacks)
    pub max_timestamp_age_seconds: u64,

    /// Key rotation interval in seconds (default: 24 hours)
    pub key_rotation_interval_seconds: Option<u64>,

    /// Key rotation overlap period in seconds (default: 1 hour)
    pub key_rotation_overlap_seconds: Option<u64>,
}

impl SecurityConfig {
    /// Load security configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok(); // Load .env file if present

        let voter_salt = std::env::var("CRYPTO_VOTER_SALT")
            .map_err(|_| Error::internal("CRYPTO_VOTER_SALT environment variable required"))?;

        let token_salt = std::env::var("CRYPTO_TOKEN_SALT")
            .map_err(|_| Error::internal("CRYPTO_TOKEN_SALT environment variable required"))?;

        // Validate salts
        Self::validate_salt(&voter_salt, "CRYPTO_VOTER_SALT")?;
        Self::validate_salt(&token_salt, "CRYPTO_TOKEN_SALT")?;

        let key_expiry_seconds = std::env::var("CRYPTO_KEY_EXPIRY_SECONDS")
            .unwrap_or_else(|_| "86400".to_string()) // 24 hours default
            .parse()
            .map_err(|_| Error::internal("Invalid CRYPTO_KEY_EXPIRY_SECONDS"))?;

        let max_crypto_ops_per_second = std::env::var("CRYPTO_MAX_OPS_PER_SECOND")
            .unwrap_or_else(|_| "10".to_string()) // Conservative default
            .parse()
            .map_err(|_| Error::internal("Invalid CRYPTO_MAX_OPS_PER_SECOND"))?;

        let max_timestamp_age_seconds = std::env::var("CRYPTO_MAX_TIMESTAMP_AGE_SECONDS")
            .unwrap_or_else(|_| "300".to_string()) // 5 minutes default
            .parse()
            .map_err(|_| Error::internal("Invalid CRYPTO_MAX_TIMESTAMP_AGE_SECONDS"))?;

        let key_rotation_interval_seconds = std::env::var("CRYPTO_KEY_ROTATION_INTERVAL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok());

        let key_rotation_overlap_seconds = std::env::var("CRYPTO_KEY_ROTATION_OVERLAP_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok());

        Ok(Self {
            voter_salt,
            token_salt,
            key_expiry_seconds,
            max_crypto_ops_per_second,
            max_timestamp_age_seconds,
            key_rotation_interval_seconds,
            key_rotation_overlap_seconds,
        })
    }

    /// Create configuration for testing
    pub fn for_testing() -> Result<Self> {
        use base64::Engine;
        // Generate secure random salts for testing
        let voter_salt = base64::engine::general_purpose::STANDARD.encode(&rand::random::<[u8; 32]>());
        let token_salt = base64::engine::general_purpose::STANDARD.encode(&rand::random::<[u8; 32]>());

        Ok(Self {
            voter_salt,
            token_salt,
            key_expiry_seconds: 3600, // 1 hour for testing
            max_crypto_ops_per_second: 100, // Relaxed for testing
            max_timestamp_age_seconds: 300, // 5 minutes
            key_rotation_interval_seconds: Some(300), // 5 minutes for testing
            key_rotation_overlap_seconds: Some(60),   // 1 minute for testing
        })
    }

    /// Validate a base64-encoded salt
    fn validate_salt(salt: &str, name: &str) -> Result<()> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD.decode(salt)
            .map_err(|_| Error::internal(&format!("{} must be valid base64", name)))?;

        if decoded.len() < 32 {
            return Err(Error::internal(&format!("{} must be at least 32 bytes when decoded", name)));
        }

        Ok(())
    }

    /// Get voter salt as bytes
    pub fn voter_salt_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&self.voter_salt)
            .map_err(|_| Error::internal("Invalid voter salt"))
    }

    /// Get token salt as bytes
    pub fn token_salt_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(&self.token_salt)
            .map_err(|_| Error::internal("Invalid token salt"))
    }

    /// Create key rotation configuration from security config
    pub fn key_rotation_config(&self) -> crate::crypto::key_rotation::KeyRotationConfig {
        let rotation_interval = self.key_rotation_interval_seconds.unwrap_or(86400); // 24 hours default
        let overlap_period = self.key_rotation_overlap_seconds.unwrap_or(3600);     // 1 hour default

        // Calculate appropriate check interval (should be much smaller than rotation interval)
        let check_interval = std::cmp::min(3600, rotation_interval / 4); // Check every hour OR quarter of rotation, whichever is smaller

        crate::crypto::key_rotation::KeyRotationConfig {
            rotation_interval,
            overlap_period,
            check_interval,
            max_previous_keys: 3,  // Keep 3 previous keys
        }
    }
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

impl Config {
    /// Load configuration from environment
    pub fn from_env() -> Result<Self> {
        let security = SecurityConfig::from_env()?;

        let logging = LoggingConfig {
            level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            format: std::env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string()),
        };

        Ok(Self {
            security,
            logging,
        })
    }

    /// Create configuration for testing
    pub fn for_testing() -> Result<Self> {
        let security = SecurityConfig::for_testing()?;

        let logging = LoggingConfig {
            level: "debug".to_string(),
            format: "pretty".to_string(),
        };

        Ok(Self {
            security,
            logging,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_config_validation() {
        let config = SecurityConfig::for_testing().unwrap();

        // Test salt validation
        assert!(config.voter_salt_bytes().unwrap().len() >= 32);
        assert!(config.token_salt_bytes().unwrap().len() >= 32);

        // Test reasonable defaults
        assert!(config.key_expiry_seconds > 0);
        assert!(config.max_crypto_ops_per_second > 0);
        assert!(config.max_timestamp_age_seconds > 0);
    }

    #[test]
    fn test_salt_validation() {
        use base64::Engine;
        // Valid salt (32 bytes)
        let valid_salt = base64::engine::general_purpose::STANDARD.encode(&[0u8; 32]);
        assert!(SecurityConfig::validate_salt(&valid_salt, "TEST").is_ok());

        // Invalid salt (too short)
        let short_salt = base64::engine::general_purpose::STANDARD.encode(&[0u8; 16]);
        assert!(SecurityConfig::validate_salt(&short_salt, "TEST").is_err());

        // Invalid base64
        assert!(SecurityConfig::validate_salt("invalid_base64!", "TEST").is_err());
    }
}