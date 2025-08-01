//! Enhanced secure configuration management for the voting system
//!
//! Features:
//! - Comprehensive environment variable validation
//! - Secure configuration loading with detailed error reporting
//! - Production readiness checks
//! - Secrets management preparation for HSM/Vault integration
//! - Configuration drift detection
//! - Hot-reload preparation interfaces

use crate::crypto::SecureMemory;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration validation error with detailed context
#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    pub field: String,
    pub error: String,
    pub suggestion: Option<String>,
    pub security_impact: Option<String>,
}

impl ConfigValidationError {
    pub fn new(field: &str, error: &str) -> Self {
        Self {
            field: field.to_string(),
            error: error.to_string(),
            suggestion: None,
            security_impact: None,
        }
    }

    pub fn with_suggestion(mut self, suggestion: &str) -> Self {
        self.suggestion = Some(suggestion.to_string());
        self
    }

    pub fn with_security_impact(mut self, impact: &str) -> Self {
        self.security_impact = Some(impact.to_string());
        self
    }
}

/// Configuration validation result
pub type ConfigValidationResult = std::result::Result<(), Vec<ConfigValidationError>>;

/// Enhanced security configuration for cryptographic operations
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

    /// Maximum failed attempts before security escalation
    pub max_failed_attempts: u32,

    /// Security incident detection threshold (0.0 to 1.0)
    pub security_incident_threshold: f64,

    /// Enable enhanced security monitoring
    pub enable_security_monitoring: bool,

    /// Enable audit trail integrity verification
    pub enable_audit_verification: bool,
}

impl SecurityConfig {
    /// Load security configuration from environment variables with comprehensive validation
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok(); // Load .env file if present

        let mut validation_errors = Vec::new();

        // Load and validate voter salt
        let voter_salt = match std::env::var("CRYPTO_VOTER_SALT") {
            Ok(salt) => {
                if let Err(err) = Self::validate_salt(&salt, "CRYPTO_VOTER_SALT") {
                    validation_errors.push(
                        ConfigValidationError::new("CRYPTO_VOTER_SALT", &err.to_string())
                            .with_suggestion("Generate using: openssl rand -base64 32")
                            .with_security_impact(
                                "Critical: Voter anonymization compromised without proper salt",
                            ),
                    );
                    String::new() // Use empty string to continue validation
                } else {
                    salt
                }
            }
            Err(_) => {
                validation_errors.push(
                    ConfigValidationError::new(
                        "CRYPTO_VOTER_SALT",
                        "Environment variable required",
                    )
                    .with_suggestion("Set CRYPTO_VOTER_SALT=<base64-encoded-32-bytes>")
                    .with_security_impact("Critical: System cannot operate without voter salt"),
                );
                String::new()
            }
        };

        // Load and validate token salt
        let token_salt = match std::env::var("CRYPTO_TOKEN_SALT") {
            Ok(salt) => {
                if let Err(err) = Self::validate_salt(&salt, "CRYPTO_TOKEN_SALT") {
                    validation_errors.push(
                        ConfigValidationError::new("CRYPTO_TOKEN_SALT", &err.to_string())
                            .with_suggestion("Generate using: openssl rand -base64 32")
                            .with_security_impact(
                                "Critical: Token security compromised without proper salt",
                            ),
                    );
                    String::new()
                } else {
                    salt
                }
            }
            Err(_) => {
                validation_errors.push(
                    ConfigValidationError::new(
                        "CRYPTO_TOKEN_SALT",
                        "Environment variable required",
                    )
                    .with_suggestion("Set CRYPTO_TOKEN_SALT=<base64-encoded-32-bytes>")
                    .with_security_impact("Critical: System cannot operate without token salt"),
                );
                String::new()
            }
        };

        // Load and validate numeric configurations
        let key_expiry_seconds = Self::parse_u64_env(
            "CRYPTO_KEY_EXPIRY_SECONDS",
            86400,                // 24 hours default
            Some((3600, 604800)), // 1 hour to 1 week range
            &mut validation_errors,
        );

        let max_crypto_ops_per_second = Self::parse_u32_env(
            "CRYPTO_MAX_OPS_PER_SECOND",
            10,               // Conservative default
            Some((1, 10000)), // 1 to 10K ops/sec range
            &mut validation_errors,
        );

        let max_timestamp_age_seconds = Self::parse_u64_env(
            "CRYPTO_MAX_TIMESTAMP_AGE_SECONDS",
            300,              // 5 minutes default
            Some((60, 3600)), // 1 minute to 1 hour range
            &mut validation_errors,
        );

        let max_failed_attempts = Self::parse_u32_env(
            "SECURITY_MAX_FAILED_ATTEMPTS",
            5,              // Default 5 attempts
            Some((1, 100)), // 1 to 100 attempts range
            &mut validation_errors,
        );

        let security_incident_threshold = Self::parse_f64_env(
            "SECURITY_INCIDENT_THRESHOLD",
            0.6,              // Default 60% threshold
            Some((0.1, 1.0)), // 10% to 100% range
            &mut validation_errors,
        );

        // Load optional key rotation settings
        let key_rotation_interval_seconds = Self::parse_optional_u64_env(
            "CRYPTO_KEY_ROTATION_INTERVAL_SECONDS",
            Some((3600, 2592000)), // 1 hour to 30 days
            &mut validation_errors,
        );

        let key_rotation_overlap_seconds = Self::parse_optional_u64_env(
            "CRYPTO_KEY_ROTATION_OVERLAP_SECONDS",
            Some((60, 86400)), // 1 minute to 24 hours
            &mut validation_errors,
        );

        // Load boolean security settings
        let enable_security_monitoring = Self::parse_bool_env(
            "SECURITY_ENABLE_MONITORING",
            true, // Default enabled
            &mut validation_errors,
        );

        let enable_audit_verification = Self::parse_bool_env(
            "SECURITY_ENABLE_AUDIT_VERIFICATION",
            true, // Default enabled
            &mut validation_errors,
        );

        // Validate key rotation configuration consistency
        if let (Some(interval), Some(overlap)) =
            (key_rotation_interval_seconds, key_rotation_overlap_seconds)
        {
            if overlap >= interval {
                validation_errors.push(
                    ConfigValidationError::new(
                        "CRYPTO_KEY_ROTATION_OVERLAP_SECONDS",
                        "Overlap period must be less than rotation interval",
                    )
                    .with_suggestion(&format!("Set to less than {interval} seconds"))
                    .with_security_impact(
                        "Key rotation will fail with invalid timing configuration",
                    ),
                );
            }
        }

        // Return errors if any validation failed
        if !validation_errors.is_empty() {
            return Err(Error::internal(Self::format_validation_errors(
                &validation_errors,
            )));
        }

        Ok(Self {
            voter_salt,
            token_salt,
            key_expiry_seconds,
            max_crypto_ops_per_second,
            max_timestamp_age_seconds,
            key_rotation_interval_seconds,
            key_rotation_overlap_seconds,
            max_failed_attempts,
            security_incident_threshold,
            enable_security_monitoring,
            enable_audit_verification,
        })
    }

    /// Create comprehensive configuration for testing
    pub fn for_testing() -> Result<Self> {
        use base64::Engine;
        // Generate secure random salts for testing
        let voter_salt = base64::engine::general_purpose::STANDARD
            .encode(SecureMemory::secure_random_bytes::<32>());
        let token_salt = base64::engine::general_purpose::STANDARD
            .encode(SecureMemory::secure_random_bytes::<32>());

        Ok(Self {
            voter_salt,
            token_salt,
            key_expiry_seconds: 3600,                 // 1 hour for testing
            max_crypto_ops_per_second: 100,           // Relaxed for testing
            max_timestamp_age_seconds: 300,           // 5 minutes
            key_rotation_interval_seconds: Some(300), // 5 minutes for testing
            key_rotation_overlap_seconds: Some(60),   // 1 minute for testing
            max_failed_attempts: 3,                   // Lower for testing
            security_incident_threshold: 0.5,         // 50% for testing
            enable_security_monitoring: true,
            enable_audit_verification: true,
        })
    }

    /// Comprehensive configuration validation
    pub fn validate(&self) -> ConfigValidationResult {
        let mut errors = Vec::new();

        // Validate salts
        if let Err(err) = Self::validate_salt(&self.voter_salt, "voter_salt") {
            errors.push(ConfigValidationError::new("voter_salt", &err.to_string()));
        }

        if let Err(err) = Self::validate_salt(&self.token_salt, "token_salt") {
            errors.push(ConfigValidationError::new("token_salt", &err.to_string()));
        }

        // Validate numeric ranges
        if self.key_expiry_seconds < 3600 {
            errors.push(
                ConfigValidationError::new(
                    "key_expiry_seconds",
                    "Key expiry too short for production",
                )
                .with_suggestion("Use at least 3600 seconds (1 hour)")
                .with_security_impact("Short key lifetimes may impact system performance"),
            );
        }

        if self.max_crypto_ops_per_second == 0 {
            errors.push(
                ConfigValidationError::new(
                    "max_crypto_ops_per_second",
                    "Rate limit cannot be zero",
                )
                .with_security_impact("Zero rate limit prevents all operations"),
            );
        }

        if self.max_timestamp_age_seconds > 3600 {
            errors.push(
                ConfigValidationError::new("max_timestamp_age_seconds", "Timestamp age too long")
                    .with_suggestion("Use maximum 3600 seconds (1 hour)")
                    .with_security_impact("Long timestamp windows increase replay attack risk"),
            );
        }

        if self.security_incident_threshold < 0.0 || self.security_incident_threshold > 1.0 {
            errors.push(
                ConfigValidationError::new(
                    "security_incident_threshold",
                    "Threshold must be between 0.0 and 1.0",
                )
                .with_security_impact("Invalid threshold disables security incident detection"),
            );
        }

        // Validate key rotation consistency (basic checks only)
        if let (Some(interval), Some(overlap)) = (
            self.key_rotation_interval_seconds,
            self.key_rotation_overlap_seconds,
        ) {
            if overlap >= interval {
                errors.push(
                    ConfigValidationError::new(
                        "key_rotation_overlap_seconds",
                        "Overlap must be less than interval",
                    )
                    .with_security_impact("Invalid key rotation timing compromises key security"),
                );
            }

            // Basic minimum check (allow shorter intervals for testing)
            if interval < 60 {
                errors.push(
                    ConfigValidationError::new(
                        "key_rotation_interval_seconds",
                        "Key rotation interval too short",
                    )
                    .with_suggestion("Use at least 60 seconds")
                    .with_security_impact("Very short intervals may cause system instability"),
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate configuration for production deployment
    pub fn validate_for_production(&self) -> ConfigValidationResult {
        let mut errors = Vec::new();

        // Run standard validation first
        if let Err(mut validation_errors) = self.validate() {
            errors.append(&mut validation_errors);
        }

        // Additional production-specific validations
        if self.max_crypto_ops_per_second > 1000 {
            errors.push(
                ConfigValidationError::new(
                    "max_crypto_ops_per_second",
                    "Rate limit very high for production",
                )
                .with_suggestion("Consider lower limit for better DoS protection")
                .with_security_impact("High rate limits may allow DoS attacks"),
            );
        }

        if !self.enable_security_monitoring {
            errors.push(
                ConfigValidationError::new(
                    "enable_security_monitoring",
                    "Security monitoring should be enabled in production",
                )
                .with_security_impact(
                    "Critical: Security monitoring required for banking-grade deployment",
                ),
            );
        }

        if !self.enable_audit_verification {
            errors.push(
                ConfigValidationError::new(
                    "enable_audit_verification",
                    "Audit verification should be enabled in production",
                )
                .with_security_impact("Critical: Audit verification required for compliance"),
            );
        }

        // Check if using default/weak salts (common patterns)
        if self.voter_salt.len() < 50 || self.token_salt.len() < 50 {
            errors.push(
                ConfigValidationError::new("salts", "Salts may be too simple for production")
                    .with_suggestion("Use longer, more complex base64-encoded salts")
                    .with_security_impact("Weak salts compromise cryptographic security"),
            );
        }

        // Production-specific key rotation validation
        if let Some(interval) = self.key_rotation_interval_seconds {
            if interval < 3600 {
                errors.push(
                    ConfigValidationError::new(
                        "key_rotation_interval_seconds",
                        "Key rotation interval too frequent for production",
                    )
                    .with_suggestion("Use at least 3600 seconds (1 hour)")
                    .with_security_impact(
                        "Frequent key rotation may impact system stability in production",
                    ),
                );
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Generate production readiness report
    pub fn production_readiness_report(&self) -> ProductionReadinessReport {
        let mut report = ProductionReadinessReport {
            overall_ready: true,
            security_score: 1.0,
            warnings: Vec::new(),
            recommendations: Vec::new(),
            critical_issues: Vec::new(),
            compliance_notes: Vec::new(),
        };

        // Security configuration analysis
        if self.max_timestamp_age_seconds > 600 {
            report
                .warnings
                .push("Timestamp age window longer than 10 minutes".to_string());
            report.security_score -= 0.1;
        }

        if self.max_failed_attempts > 10 {
            report
                .warnings
                .push("High failed attempt threshold may allow brute force attacks".to_string());
            report.security_score -= 0.1;
        }

        if self.security_incident_threshold > 0.8 {
            report.recommendations.push(
                "Consider lowering security incident threshold for more sensitive detection"
                    .to_string(),
            );
        }

        // Key rotation analysis
        if let Some(interval) = self.key_rotation_interval_seconds {
            if interval > 604800 {
                // 1 week
                report
                    .warnings
                    .push("Key rotation interval longer than 1 week".to_string());
                report.security_score -= 0.05;
            }
        } else {
            report.critical_issues.push(
                "Key rotation not configured - required for banking-grade security".to_string(),
            );
            report.overall_ready = false;
            report.security_score -= 0.3;
        }

        // Monitoring and audit checks
        if !self.enable_security_monitoring {
            report
                .critical_issues
                .push("Security monitoring disabled - required for production".to_string());
            report.overall_ready = false;
            report.security_score -= 0.2;
        }

        if !self.enable_audit_verification {
            report
                .critical_issues
                .push("Audit verification disabled - required for compliance".to_string());
            report.overall_ready = false;
            report.security_score -= 0.2;
        }

        // Rate limiting analysis
        if self.max_crypto_ops_per_second < 5 {
            report
                .warnings
                .push("Very low rate limit may impact performance".to_string());
        } else if self.max_crypto_ops_per_second > 100 {
            report
                .warnings
                .push("High rate limit may allow DoS attacks".to_string());
            report.security_score -= 0.05;
        }

        // Compliance recommendations
        report
            .compliance_notes
            .push("Ensure salts are stored in HSM/Vault for PCI DSS compliance".to_string());
        report
            .compliance_notes
            .push("Document all cryptographic algorithms for SOX compliance".to_string());
        report
            .compliance_notes
            .push("Enable comprehensive audit logging for regulatory requirements".to_string());

        // Final score adjustment
        report.security_score = report.security_score.max(0.0).min(1.0);

        if report.security_score < 0.8 {
            report.overall_ready = false;
        }

        report
    }

    /// Helper methods for parsing and validation

    fn parse_u64_env(
        key: &str,
        default: u64,
        range: Option<(u64, u64)>,
        errors: &mut Vec<ConfigValidationError>,
    ) -> u64 {
        match std::env::var(key) {
            Ok(value) => match value.parse::<u64>() {
                Ok(parsed) => {
                    if let Some((min, max)) = range {
                        if parsed < min || parsed > max {
                            errors.push(
                                ConfigValidationError::new(
                                    key,
                                    &format!("Value {parsed} out of range [{min}, {max}]"),
                                )
                                .with_suggestion(&format!("Use value between {min} and {max}")),
                            );
                            default
                        } else {
                            parsed
                        }
                    } else {
                        parsed
                    }
                }
                Err(_) => {
                    errors.push(
                        ConfigValidationError::new(key, "Invalid number format")
                            .with_suggestion("Use a valid positive integer"),
                    );
                    default
                }
            },
            Err(_) => default, // Use default if not set
        }
    }

    fn parse_u32_env(
        key: &str,
        default: u32,
        range: Option<(u32, u32)>,
        errors: &mut Vec<ConfigValidationError>,
    ) -> u32 {
        match std::env::var(key) {
            Ok(value) => match value.parse::<u32>() {
                Ok(parsed) => {
                    if let Some((min, max)) = range {
                        if parsed < min || parsed > max {
                            errors.push(
                                ConfigValidationError::new(
                                    key,
                                    &format!("Value {parsed} out of range [{min}, {max}]"),
                                )
                                .with_suggestion(&format!("Use value between {min} and {max}")),
                            );
                            default
                        } else {
                            parsed
                        }
                    } else {
                        parsed
                    }
                }
                Err(_) => {
                    errors.push(
                        ConfigValidationError::new(key, "Invalid number format")
                            .with_suggestion("Use a valid positive integer"),
                    );
                    default
                }
            },
            Err(_) => default,
        }
    }

    fn parse_f64_env(
        key: &str,
        default: f64,
        range: Option<(f64, f64)>,
        errors: &mut Vec<ConfigValidationError>,
    ) -> f64 {
        match std::env::var(key) {
            Ok(value) => match value.parse::<f64>() {
                Ok(parsed) => {
                    if let Some((min, max)) = range {
                        if parsed < min || parsed > max {
                            errors.push(
                                ConfigValidationError::new(
                                    key,
                                    &format!("Value {parsed} out of range [{min}, {max}]"),
                                )
                                .with_suggestion(&format!("Use value between {min} and {max}")),
                            );
                            default
                        } else {
                            parsed
                        }
                    } else {
                        parsed
                    }
                }
                Err(_) => {
                    errors.push(
                        ConfigValidationError::new(key, "Invalid number format")
                            .with_suggestion("Use a valid decimal number (e.g., 0.6)"),
                    );
                    default
                }
            },
            Err(_) => default,
        }
    }

    fn parse_optional_u64_env(
        key: &str,
        range: Option<(u64, u64)>,
        errors: &mut Vec<ConfigValidationError>,
    ) -> Option<u64> {
        match std::env::var(key) {
            Ok(value) => match value.parse::<u64>() {
                Ok(parsed) => {
                    if let Some((min, max)) = range {
                        if parsed < min || parsed > max {
                            errors.push(
                                ConfigValidationError::new(
                                    key,
                                    &format!("Value {parsed} out of range [{min}, {max}]"),
                                )
                                .with_suggestion(&format!("Use value between {min} and {max}")),
                            );
                            None
                        } else {
                            Some(parsed)
                        }
                    } else {
                        Some(parsed)
                    }
                }
                Err(_) => {
                    errors.push(
                        ConfigValidationError::new(key, "Invalid number format")
                            .with_suggestion("Use a valid positive integer"),
                    );
                    None
                }
            },
            Err(_) => None, // Optional, so None is fine
        }
    }

    fn parse_bool_env(key: &str, default: bool, errors: &mut Vec<ConfigValidationError>) -> bool {
        match std::env::var(key) {
            Ok(value) => match value.to_lowercase().as_str() {
                "true" | "1" | "yes" | "on" | "enabled" => true,
                "false" | "0" | "no" | "off" | "disabled" => false,
                _ => {
                    errors.push(
                        ConfigValidationError::new(key, "Invalid boolean format").with_suggestion(
                            "Use: true/false, 1/0, yes/no, on/off, enabled/disabled",
                        ),
                    );
                    default
                }
            },
            Err(_) => default,
        }
    }

    /// Validate a base64-encoded salt with enhanced security checks
    fn validate_salt(salt: &str, name: &str) -> Result<()> {
        if salt.is_empty() {
            return Err(Error::internal(format!("{name} cannot be empty")));
        }

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(salt)
            .map_err(|_| Error::internal(format!("{name} must be valid base64")))?;

        if decoded.len() < 32 {
            return Err(Error::internal(format!(
                "{name} must be at least 32 bytes when decoded"
            )));
        }

        // Check for weak patterns (all same byte, sequential, etc.)
        if Self::is_weak_salt(&decoded) {
            return Err(Error::internal(format!(
                "{name} appears to be weak or predictable"
            )));
        }

        Ok(())
    }

    /// Check if salt has weak patterns
    fn is_weak_salt(salt: &[u8]) -> bool {
        if salt.len() < 32 {
            return true;
        }

        // Check for all same byte
        let first_byte = salt[0];
        if salt.iter().all(|&b| b == first_byte) {
            return true;
        }

        // Check for sequential patterns
        let mut sequential_count = 0;
        for i in 1..salt.len() {
            if salt[i] == salt[i - 1].wrapping_add(1) {
                sequential_count += 1;
            }
        }

        // If more than 50% of bytes are sequential, consider weak
        sequential_count > salt.len() / 2
    }

    fn format_validation_errors(errors: &[ConfigValidationError]) -> String {
        let mut result = String::from("Configuration validation failed:\n");

        for (i, error) in errors.iter().enumerate() {
            result.push_str(&format!(
                "{}. Field '{}': {}\n",
                i + 1,
                error.field,
                error.error
            ));

            if let Some(ref suggestion) = error.suggestion {
                result.push_str(&format!("   Suggestion: {suggestion}\n"));
            }

            if let Some(ref impact) = error.security_impact {
                result.push_str(&format!("   Security Impact: {impact}\n"));
            }

            result.push('\n');
        }

        result
    }

    /// Get voter salt as bytes with validation
    pub fn voter_salt_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.voter_salt)
            .map_err(|_| Error::internal("Invalid voter salt"))?;

        if decoded.len() < 32 {
            return Err(Error::internal("Voter salt too short"));
        }

        Ok(decoded)
    }

    /// Get token salt as bytes with validation
    pub fn token_salt_bytes(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.token_salt)
            .map_err(|_| Error::internal("Invalid token salt"))?;

        if decoded.len() < 32 {
            return Err(Error::internal("Token salt too short"));
        }

        Ok(decoded)
    }

    /// Create key rotation configuration from security config with validation
    pub fn key_rotation_config(&self) -> Result<crate::crypto::key_rotation::KeyRotationConfig> {
        let rotation_interval = self.key_rotation_interval_seconds.unwrap_or(86400); // 24 hours default
        let overlap_period = self.key_rotation_overlap_seconds.unwrap_or(3600); // 1 hour default

        // Calculate appropriate check interval
        let check_interval = std::cmp::min(3600, rotation_interval / 4);

        let config = crate::crypto::key_rotation::KeyRotationConfig {
            rotation_interval,
            overlap_period,
            check_interval,
            max_previous_keys: 3, // Keep 3 previous keys
        };

        // Validate the configuration
        config
            .validate()
            .map_err(|e| Error::internal(format!("Key rotation config invalid: {e}")))?;

        Ok(config)
    }

    /// Create token configuration from security config
    pub fn token_config(&self) -> crate::crypto::voting_token::TokenConfig {
        crate::crypto::voting_token::TokenConfig {
            lifetime_seconds: std::cmp::min(self.key_expiry_seconds, 7200), // Max 2 hours for tokens
            cleanup_interval_seconds: 300,                                  // 5 minutes
            max_tokens_per_voter: if self.max_failed_attempts > 5 { 5 } else { 3 }, // Based on security level
        }
    }

    /// Get security monitoring configuration
    pub fn security_monitoring_config(
        &self,
    ) -> crate::crypto::security_monitoring::SecurityMonitoringConfig {
        crate::crypto::security_monitoring::SecurityMonitoringConfig {
            metrics_window_seconds: 300, // 5 minutes
            timing_anomaly_threshold_micros: if self.enable_security_monitoring {
                50
            } else {
                100
            },
            dos_detection_enabled: self.enable_security_monitoring,
            authentication_pattern_analysis: self.enable_security_monitoring,
            baseline_update_interval_seconds: 3600, // 1 hour
        }
    }
}

/// Production readiness assessment report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionReadinessReport {
    pub overall_ready: bool,
    pub security_score: f64, // 0.0 to 1.0
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
    pub critical_issues: Vec<String>,
    pub compliance_notes: Vec<String>,
}

impl ProductionReadinessReport {
    /// Generate human-readable report
    pub fn format_report(&self) -> String {
        let mut report = String::new();

        report.push_str("🏦 PRODUCTION READINESS ASSESSMENT\n");
        report.push_str("==================================\n\n");

        report.push_str(&format!(
            "Overall Status: {}\n",
            if self.overall_ready {
                "✅ READY"
            } else {
                "❌ NOT READY"
            }
        ));
        report.push_str(&format!(
            "Security Score: {:.1}%\n\n",
            self.security_score * 100.0
        ));

        if !self.critical_issues.is_empty() {
            report.push_str("🚨 CRITICAL ISSUES:\n");
            for issue in &self.critical_issues {
                report.push_str(&format!("   • {issue}\n"));
            }
            report.push('\n');
        }

        if !self.warnings.is_empty() {
            report.push_str("⚠️  WARNINGS:\n");
            for warning in &self.warnings {
                report.push_str(&format!("   • {warning}\n"));
            }
            report.push('\n');
        }

        if !self.recommendations.is_empty() {
            report.push_str("💡 RECOMMENDATIONS:\n");
            for rec in &self.recommendations {
                report.push_str(&format!("   • {rec}\n"));
            }
            report.push('\n');
        }

        if !self.compliance_notes.is_empty() {
            report.push_str("📋 COMPLIANCE NOTES:\n");
            for note in &self.compliance_notes {
                report.push_str(&format!("   • {note}\n"));
            }
            report.push('\n');
        }

        report
    }
}

/// Enhanced logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub enable_audit_logging: bool,
    pub audit_log_path: Option<String>,
    pub enable_security_logging: bool,
    pub max_log_file_size_mb: u64,
    pub log_retention_days: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            enable_audit_logging: true,
            audit_log_path: None,
            enable_security_logging: true,
            max_log_file_size_mb: 100,
            log_retention_days: 90, // 90 days for compliance
        }
    }
}

impl LoggingConfig {
    /// Create logging configuration from environment
    pub fn from_env() -> Result<Self> {
        let mut config = Self::default();

        if let Ok(level) = std::env::var("LOG_LEVEL") {
            Self::validate_log_level(&level)?;
            config.level = level;
        }

        if let Ok(format) = std::env::var("LOG_FORMAT") {
            Self::validate_log_format(&format)?;
            config.format = format;
        }

        if let Ok(audit_path) = std::env::var("AUDIT_LOG_PATH") {
            config.audit_log_path = Some(audit_path);
        }

        if let Ok(enable_audit) = std::env::var("ENABLE_AUDIT_LOGGING") {
            config.enable_audit_logging = enable_audit.to_lowercase() == "true";
        }

        if let Ok(enable_security) = std::env::var("ENABLE_SECURITY_LOGGING") {
            config.enable_security_logging = enable_security.to_lowercase() == "true";
        }

        if let Ok(max_size) = std::env::var("MAX_LOG_FILE_SIZE_MB") {
            config.max_log_file_size_mb = max_size
                .parse()
                .map_err(|_| Error::internal("Invalid MAX_LOG_FILE_SIZE_MB"))?;
        }

        if let Ok(retention) = std::env::var("LOG_RETENTION_DAYS") {
            config.log_retention_days = retention
                .parse()
                .map_err(|_| Error::internal("Invalid LOG_RETENTION_DAYS"))?;
        }

        Ok(config)
    }

    fn validate_log_level(level: &str) -> Result<()> {
        match level.to_lowercase().as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
            _ => Err(Error::internal(
                "Invalid log level. Use: trace, debug, info, warn, error",
            )),
        }
    }

    fn validate_log_format(format: &str) -> Result<()> {
        match format.to_lowercase().as_str() {
            "json" | "pretty" | "compact" => Ok(()),
            _ => Err(Error::internal(
                "Invalid log format. Use: json, pretty, compact",
            )),
        }
    }
}

/// Enhanced application configuration with comprehensive validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    /// Configuration metadata
    pub metadata: ConfigMetadata,
}

/// Configuration metadata for tracking and validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMetadata {
    pub loaded_at: u64,
    pub environment: String, // development, testing, production
    pub version: String,
    pub checksum: Option<String>, // For configuration drift detection
}

impl Config {
    /// Load configuration from environment with comprehensive validation
    pub fn from_env() -> Result<Self> {
        let security = SecurityConfig::from_env()?;
        let logging = LoggingConfig::from_env()?;

        let environment =
            std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

        // Validate environment
        match environment.as_str() {
            "development" | "testing" | "staging" | "production" => {}
            _ => {
                return Err(Error::internal(
                    "Invalid ENVIRONMENT. Use: development, testing, staging, production",
                ));
            }
        }

        let metadata = ConfigMetadata {
            loaded_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            environment,
            version: env!("CARGO_PKG_VERSION").to_string(),
            checksum: None, // Will be calculated after creation
        };

        let mut config = Self {
            security,
            logging,
            metadata,
        };

        // Calculate configuration checksum for drift detection
        config.metadata.checksum = Some(config.calculate_checksum()?);

        Ok(config)
    }

    /// Create configuration for testing
    pub fn for_testing() -> Result<Self> {
        let security = SecurityConfig::for_testing()?;
        let logging = LoggingConfig {
            level: "debug".to_string(),
            format: "pretty".to_string(),
            enable_audit_logging: true,
            audit_log_path: Some("/tmp/vote_test_audit.log".to_string()),
            enable_security_logging: true,
            max_log_file_size_mb: 10,
            log_retention_days: 7,
        };

        let metadata = ConfigMetadata {
            loaded_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            environment: "testing".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            checksum: None,
        };

        let mut config = Self {
            security,
            logging,
            metadata,
        };

        config.metadata.checksum = Some(config.calculate_checksum()?);

        Ok(config)
    }

    /// Validate entire configuration
    pub fn validate(&self) -> ConfigValidationResult {
        self.security.validate()
    }

    /// Validate for production deployment
    pub fn validate_for_production(&self) -> ConfigValidationResult {
        let mut errors = Vec::new();

        // Check environment
        if self.metadata.environment != "production" {
            errors.push(
                ConfigValidationError::new("environment", "Not configured for production")
                    .with_suggestion("Set ENVIRONMENT=production")
                    .with_security_impact("Development settings may not be secure for production"),
            );
        }

        // Validate security configuration for production
        if let Err(mut security_errors) = self.security.validate_for_production() {
            errors.append(&mut security_errors);
        }

        // Validate logging for production
        if !self.logging.enable_audit_logging {
            errors.push(
                ConfigValidationError::new(
                    "enable_audit_logging",
                    "Audit logging required for production",
                )
                .with_security_impact(
                    "Compliance: Audit logging required for regulatory compliance",
                ),
            );
        }

        if self.logging.log_retention_days < 90 {
            errors.push(
                ConfigValidationError::new(
                    "log_retention_days",
                    "Log retention too short for compliance",
                )
                .with_suggestion("Use at least 90 days retention")
                .with_security_impact(
                    "Compliance: Short retention may violate regulatory requirements",
                ),
            );
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Generate production readiness report
    pub fn production_readiness_report(&self) -> ProductionReadinessReport {
        self.security.production_readiness_report()
    }

    /// Calculate configuration checksum for drift detection
    pub fn calculate_checksum(&self) -> Result<String> {
        // Create a copy without checksum for calculation
        let mut config_for_checksum = self.clone();
        config_for_checksum.metadata.checksum = None;
        config_for_checksum.metadata.loaded_at = 0; // Normalize timestamp

        let config_json = serde_json::to_string(&config_for_checksum).map_err(|e| {
            Error::internal(format!("Failed to serialize config for checksum: {e}"))
        })?;

        let hash = blake3::hash(config_json.as_bytes());
        Ok(hex::encode(hash.as_bytes()))
    }

    /// Detect configuration drift
    pub fn detect_drift(&self) -> Result<bool> {
        let current_checksum = self.calculate_checksum()?;
        Ok(self.metadata.checksum.as_ref() != Some(&current_checksum))
    }

    /// Environment-specific configurations
    pub fn is_development(&self) -> bool {
        self.metadata.environment == "development"
    }

    pub fn is_testing(&self) -> bool {
        self.metadata.environment == "testing"
    }

    pub fn is_production(&self) -> bool {
        self.metadata.environment == "production"
    }

    /// Get configuration summary for monitoring
    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            environment: self.metadata.environment.clone(),
            version: self.metadata.version.clone(),
            loaded_at: self.metadata.loaded_at,
            security_monitoring_enabled: self.security.enable_security_monitoring,
            audit_verification_enabled: self.security.enable_audit_verification,
            key_rotation_configured: self.security.key_rotation_interval_seconds.is_some(),
            rate_limit_ops_per_second: self.security.max_crypto_ops_per_second,
            max_failed_attempts: self.security.max_failed_attempts,
        }
    }
}

/// Configuration summary for monitoring and status checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub environment: String,
    pub version: String,
    pub loaded_at: u64,
    pub security_monitoring_enabled: bool,
    pub audit_verification_enabled: bool,
    pub key_rotation_configured: bool,
    pub rate_limit_ops_per_second: u32,
    pub max_failed_attempts: u32,
}

/// Configuration manager for hot-reload and advanced configuration management
pub struct ConfigManager {
    current_config: std::sync::RwLock<Config>,
    config_watchers: std::sync::RwLock<Vec<Box<dyn ConfigWatcher + Send + Sync>>>,
}

impl ConfigManager {
    /// Create new configuration manager
    pub fn new(config: Config) -> Self {
        Self {
            current_config: std::sync::RwLock::new(config),
            config_watchers: std::sync::RwLock::new(Vec::new()),
        }
    }

    /// Get current configuration
    pub fn get_config(&self) -> Result<Config> {
        let config = self
            .current_config
            .read()
            .map_err(|_| Error::internal("Failed to read configuration"))?;
        Ok(config.clone())
    }

    /// Update configuration (for hot-reload)
    pub fn update_config(&self, new_config: Config) -> Result<()> {
        // Validate new configuration
        new_config
            .validate_for_production()
            .map_err(|errors| Error::internal(SecurityConfig::format_validation_errors(&errors)))?;

        // Update configuration
        {
            let mut config = self
                .current_config
                .write()
                .map_err(|_| Error::internal("Failed to write configuration"))?;
            *config = new_config.clone();
        }

        // Notify watchers
        self.notify_watchers(&new_config)?;

        tracing::info!("Configuration updated successfully");
        Ok(())
    }

    /// Register configuration watcher
    pub fn register_watcher(&self, watcher: Box<dyn ConfigWatcher + Send + Sync>) -> Result<()> {
        let mut watchers = self
            .config_watchers
            .write()
            .map_err(|_| Error::internal("Failed to register config watcher"))?;
        watchers.push(watcher);
        Ok(())
    }

    /// Notify all watchers of configuration change
    fn notify_watchers(&self, config: &Config) -> Result<()> {
        let watchers = self
            .config_watchers
            .read()
            .map_err(|_| Error::internal("Failed to read config watchers"))?;

        for watcher in watchers.iter() {
            if let Err(e) = watcher.on_config_change(config) {
                tracing::error!("Config watcher notification failed: {}", e);
            }
        }

        Ok(())
    }

    /// Check configuration health
    pub fn health_check(&self) -> Result<ConfigHealthReport> {
        let config = self.get_config()?;

        let drift_detected = config.detect_drift().unwrap_or(false);
        let validation_result = config.validate_for_production();
        let readiness_report = config.production_readiness_report();

        Ok(ConfigHealthReport {
            healthy: validation_result.is_ok() && !drift_detected && readiness_report.overall_ready,
            drift_detected,
            validation_errors: validation_result.err().unwrap_or_default(),
            security_score: readiness_report.security_score,
            last_checked: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }
}

/// Configuration watcher trait for hot-reload notifications
pub trait ConfigWatcher {
    /// Called when configuration changes
    fn on_config_change(&self, config: &Config) -> Result<()>;
}

/// Configuration health report
#[derive(Debug, Clone)]
pub struct ConfigHealthReport {
    pub healthy: bool,
    pub drift_detected: bool,
    pub validation_errors: Vec<ConfigValidationError>,
    pub security_score: f64,
    pub last_checked: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_enhanced_security_config_validation() {
        let config = SecurityConfig::for_testing().unwrap();

        // Test basic validation
        let validation_result = config.validate();
        assert!(
            validation_result.is_ok(),
            "Basic validation should pass for test config"
        );

        // Test production validation
        let production_result = config.validate_for_production();
        if let Err(errors) = production_result {
            println!("Expected production validation issues for test config:");
            for error in errors {
                println!("  • {}: {}", error.field, error.error);
            }
        }

        println!("✅ Enhanced security config validation works");
    }

    #[test]
    fn test_production_readiness_report() {
        let config = SecurityConfig::for_testing().unwrap();
        let report = config.production_readiness_report();

        println!("Production Readiness Report:");
        println!("  Overall Ready: {}", report.overall_ready);
        println!("  Security Score: {:.1}%", report.security_score * 100.0);
        println!("  Warnings: {}", report.warnings.len());
        println!("  Critical Issues: {}", report.critical_issues.len());

        assert!(report.security_score >= 0.0 && report.security_score <= 1.0);

        println!("✅ Production readiness report generation works");
    }

    #[test]
    fn test_weak_salt_detection() {
        // Test all-same-byte salt (weak)
        let weak_salt1 = vec![0x42u8; 32];
        assert!(SecurityConfig::is_weak_salt(&weak_salt1));

        // Test sequential salt (weak)
        let weak_salt2: Vec<u8> = (0..32).collect();
        assert!(SecurityConfig::is_weak_salt(&weak_salt2));

        // Test random salt (strong) - should pass with updated threshold
        let strong_salt = SecureMemory::secure_random_bytes::<32>();
        assert!(!SecurityConfig::is_weak_salt(&strong_salt));

        println!("✅ Weak salt detection works correctly");
    }

    #[test]
    fn test_configuration_manager() {
        let config = Config::for_testing().unwrap();
        let manager = ConfigManager::new(config.clone());

        // Test getting config
        let retrieved_config = manager.get_config().unwrap();
        assert_eq!(retrieved_config.metadata.environment, "testing");

        // Test health check
        let health_report = manager.health_check().unwrap();
        println!(
            "Config health: healthy={}, security_score={:.2}",
            health_report.healthy, health_report.security_score
        );

        assert!(health_report.security_score > 0.0);

        println!("✅ Configuration manager works correctly");
    }

    #[test]
    fn test_environment_specific_configurations() {
        let config = Config::for_testing().unwrap();

        assert!(config.is_testing());
        assert!(!config.is_production());
        assert!(!config.is_development());

        let summary = config.summary();
        assert_eq!(summary.environment, "testing");
        assert!(summary.security_monitoring_enabled);

        println!("✅ Environment-specific configurations work correctly");
    }

    #[test]
    fn test_configuration_checksum_and_drift_detection() {
        let mut config = Config::for_testing().unwrap();

        // Calculate initial checksum
        let initial_checksum = config.calculate_checksum().unwrap();
        assert!(!initial_checksum.is_empty());

        // Modify configuration
        config.security.max_failed_attempts = 10;

        // Calculate new checksum
        let new_checksum = config.calculate_checksum().unwrap();
        assert_ne!(initial_checksum, new_checksum);

        // Test drift detection
        config.metadata.checksum = Some(initial_checksum);
        let drift_detected = config.detect_drift().unwrap();
        assert!(drift_detected);

        println!("✅ Configuration checksum and drift detection work correctly");
    }

    #[test]
    fn test_key_rotation_config_generation() {
        let security_config = SecurityConfig::for_testing().unwrap();
        let key_rotation_config = security_config.key_rotation_config().unwrap();

        assert!(key_rotation_config.rotation_interval > 0);
        assert!(key_rotation_config.overlap_period > 0);
        assert!(key_rotation_config.overlap_period < key_rotation_config.rotation_interval);
        assert!(key_rotation_config.max_previous_keys > 0);

        println!("✅ Key rotation config generation works correctly");
    }

    #[test]
    fn test_comprehensive_config_validation() {
        // Test with invalid environment variables
        unsafe {
            env::set_var("CRYPTO_VOTER_SALT", "invalid_base64!");
            env::set_var("CRYPTO_TOKEN_SALT", "also_invalid!");
            env::set_var("CRYPTO_MAX_OPS_PER_SECOND", "invalid_number");
        }

        let config_result = SecurityConfig::from_env();

        // Should handle errors gracefully
        match config_result {
            Err(e) => {
                println!("Expected validation error: {e}");
                assert!(e.to_string().contains("validation failed"));
            }
            Ok(_) => panic!("Should reject invalid configuration"),
        }

        // Clean up
        unsafe {
            env::remove_var("CRYPTO_VOTER_SALT");
            env::remove_var("CRYPTO_TOKEN_SALT");
            env::remove_var("CRYPTO_MAX_OPS_PER_SECOND");
        }

        println!("✅ Comprehensive config validation works correctly");
    }

    #[test]
    fn test_logging_config_validation() {
        let logging_config = LoggingConfig::from_env().unwrap();

        assert!(!logging_config.level.is_empty());
        assert!(!logging_config.format.is_empty());
        assert!(logging_config.max_log_file_size_mb > 0);
        assert!(logging_config.log_retention_days > 0);

        // Test log level validation
        assert!(LoggingConfig::validate_log_level("info").is_ok());
        assert!(LoggingConfig::validate_log_level("invalid_level").is_err());

        // Test log format validation
        assert!(LoggingConfig::validate_log_format("json").is_ok());
        assert!(LoggingConfig::validate_log_format("invalid_format").is_err());

        println!("✅ Logging configuration validation works correctly");
    }
}
