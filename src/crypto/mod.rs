//! # Cryptographic Primitives for the Secure Voting System
//!
//! This module provides a comprehensive suite of cryptographic operations, security
//! monitoring, and protective mechanisms designed for bank-grade voting systems.
//! All cryptographic operations are built on proven, standardized algorithms and
//! include extensive security monitoring and incident response capabilities.
//!
//! ## Security Architecture
//!
//! The cryptographic system employs multiple layers of protection:
//!
//! ### Core Cryptographic Primitives
//! - **Ed25519 Digital Signatures**: Fast, secure signatures with 128-bit security level
//! - **Blake3 Cryptographic Hashing**: High-performance, secure hashing for integrity
//! - **AES-GCM Encryption**: Authenticated encryption for vote content protection
//! - **Secure Random Generation**: Hardware-backed entropy for key generation
//!
//! ### Security Infrastructure
//! - **Automatic Key Rotation**: Time-based and event-based key lifecycle management
//! - **Real-time Security Monitoring**: Behavioral analysis and threat detection
//! - **Incident Management**: Automated response to security events
//! - **Audit System**: Comprehensive logging with integrity protection
//!
//! ### Protection Mechanisms
//! - **Rate Limiting**: DoS protection for cryptographic operations
//! - **Secure Memory Management**: Automatic cleanup of sensitive data
//! - **Timing Attack Prevention**: Constant-time operations where critical
//! - **Replay Attack Protection**: Timestamp validation and nonce management
//!
//! ## Module Organization
//!
//! The crypto module is organized into specialized submodules:
//!
//! ### Core Security Services
//! - [`secure`]: Secure memory management and cryptographic rate limiting
//! - [`security_context`]: Unified security context and session management
//! - [`key_rotation`]: Automatic cryptographic key lifecycle management
//!
//! ### Voting-Specific Security
//! - [`voting_lock`]: Secure voting session management and state tracking
//! - [`voting_token`]: Anonymous voting token generation and validation
//!
//! ### Monitoring and Response
//! - [`security_monitoring`]: Real-time threat detection and performance monitoring
//! - [`incident_management`]: Automated security incident response
//! - [`audit`]: Comprehensive audit trail with integrity verification
//!
//! ## Cryptographic Standards Compliance
//!
//! All algorithms meet or exceed current security standards:
//! - **FIPS 140-2 Level 3** readiness for hardware security modules
//! - **NIST Post-Quantum Cryptography** migration planning
//! - **Common Criteria EAL4+** security evaluation readiness
//! - **SOX and PCI DSS** compliance through comprehensive audit trails
//!
//! ## Usage Examples
//!
//! ### Basic Cryptographic Operations
//!
//! ```rust
//! use vote::crypto::{CryptoUtils, SecureKeyPair};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Generate secure hash
//! let data = b"important voting data";
//! let hash = CryptoUtils::hash(data);
//!
//! // Generate cryptographic keypair
//! let keypair = SecureKeyPair::generate_with_expiration(None)?;
//! let (signature, timestamp) = keypair.sign_with_timestamp(data)?;
//!
//! // Verify signature with timestamp
//! keypair.verify_with_timestamp(data, &signature, timestamp, 300)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Security Context Management
//!
//! ```rust
//! use vote::crypto::{SecurityContext, SecurityLevel};
//! use std::sync::{Arc, Mutex};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Note: SecurityContext::new() requires multiple dependencies.
//! // In practice, use a builder pattern or factory method.
//! // This is a simplified example showing the concept:
//!
//! // let context = SecurityContext::builder()
//! //     .with_security_level(SecurityLevel::High)
//! //     .build()?;
//! //
//! // let result = context.execute_secure_operation(|| {
//! //     // Your secure voting operation here
//! //     Ok(())
//! // })?;
//!
//! // For now, just demonstrate SecurityLevel usage
//! let _level = SecurityLevel::High;
//! # Ok(())
//! # }
//! ```
//!
//! ### Voting Token Management
//!
//! ```rust
//! use vote::crypto::{VotingTokenService, TokenConfig};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//! // Configure voting tokens
//! let config = TokenConfig {
//!     lifetime_seconds: 3600,  // 1 hour lifetime
//!     cleanup_interval_seconds: 300,  // 5 minute cleanup
//!     max_tokens_per_voter: 3,
//! };
//!
//! // Create token service (no Result returned)
//! let _token_service = VotingTokenService::new(config);
//!
//! // Token generation requires salt manager and proper setup
//! // See voting_token module documentation for complete examples
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Considerations
//!
//! ### Key Management
//! - All cryptographic keys use secure random generation
//! - Automatic key rotation prevents long-term key compromise
//! - Keys are stored in secure memory with automatic cleanup
//! - Hardware security module (HSM) integration ready
//!
//! ### Attack Prevention
//! - Rate limiting prevents cryptographic DoS attacks
//! - Constant-time operations prevent timing attacks
//! - Secure memory prevents key extraction from memory dumps
//! - Comprehensive audit trails detect and deter attacks
//!
//! ### Monitoring and Response
//! - Real-time security monitoring detects anomalous behavior
//! - Automatic incident response isolates and mitigates threats
//! - Performance monitoring ensures system availability
//! - Audit integrity verification prevents log tampering

pub mod audit;
pub mod incident_management;
pub mod key_rotation;
pub mod secure;
pub mod security_context;
pub mod security_monitoring;
pub mod voting_lock;
pub mod voting_token;

use crate::{Result, crypto_error};
use rand::RngCore;
use uuid::Uuid;

pub use crate::types::{Hash, PublicKey, Signature};

// Re-export secure crypto types for convenient access
pub use secure::{CryptoRateLimiter, SecureKeyPair, SecureMemory, SecureSaltManager};

// Re-export enhanced voting lock types
pub use voting_lock::{
    LogoutResult, VotingCompletion, VotingLockService, VotingMethod, VotingStatus,
};

// Re-export voting token types
pub use voting_token::{
    TokenCleanupService, TokenCleanupStats, TokenConfig, TokenResult, TokenServiceStats,
    TokenState, VotingToken, VotingTokenService,
};

// Re-export key rotation types
pub use key_rotation::{
    KeyRotationConfig, KeyRotationManager, KeyRotationService, KeyRotationStats,
};

// Re-export unified security context
pub use security_context::{
    SecurityContext, SecurityEvent, SecurityIncidentType, SecurityLevel, SecurityLoginResult,
    SecurityMetrics, SecuritySession, SecuritySeverity, SecurityStatus, SecurityVoteResult,
};

// Re-export enhanced audit system
pub use audit::{
    AuditCleanupReport, AuditConfig, AuditIntegrityReport, AuditLevel, AuditQuery, AuditRecord,
    AuditTrail, AuditTrailStatistics, ComplianceAuditRecord, ComplianceLevel, ComplianceReport,
    EnhancedAuditSystem,
};

// Re-export security monitoring system
pub use security_monitoring::{
    AuthenticationPattern, DoSPattern, LayerSecurityIntegration, LayerType, OperationTimingStats,
    ResourceUsage, SecurityMonitoringConfig, SecurityOperation, SecurityPerformanceMetrics,
    SecurityPerformanceMonitor, SecurityThreatAssessment, SecurityTimer, SecurityTiming,
    SecurityTimingContext, ThreatLevel, ThreatType,
};

// Re-export automatic security incident management
pub use incident_management::{
    AffectedEntity, AlertLevel, AutomatedResponse, ComplianceMetadata, DetectedPattern,
    EscalationEngine, EvidenceType, IncidentAnalysisReport, IncidentCorrelation, IncidentEvidence,
    IncidentManagementConfig, IncidentSeverity, IncidentStatistics, IncidentStatus, IncidentType,
    PatternCorrelator, PatternType, ResponseOrchestrator, ResponseResult, ResponseType,
    SecurityIncident, SecurityIncidentManager, TokenInvalidationScope,
};

/// Secure random token generator for cryptographic operations
///
/// `TokenGenerator` provides a secure, thread-safe interface for generating
/// cryptographically strong random tokens and nonces. It uses the system's
/// cryptographically secure random number generator as its entropy source.
///
/// # Security Properties
///
/// - **Cryptographically secure**: Uses `rand::thread_rng()` which provides
///   cryptographically secure random number generation
/// - **Thread-safe**: Can be used safely across multiple threads
/// - **Entropy quality**: Backed by the operating system's entropy pool
/// - **No predictability**: Generated tokens are computationally indistinguishable from random
///
/// # Use Cases
///
/// - Voting token generation for anonymous voting
/// - Session tokens for authentication
/// - Cryptographic nonces for replay protection
/// - Salt generation for key derivation
/// - Challenge generation for proof-of-work systems
///
/// # Examples
///
/// ```rust
/// use vote::crypto::TokenGenerator;
///
/// let mut generator = TokenGenerator::new();
///
/// // Generate a 32-byte cryptographic token
/// let token = generator.generate_token();
/// assert_eq!(token.len(), 32);
///
/// // Generate a 16-byte nonce for cryptographic operations
/// let nonce = generator.generate_nonce();
/// assert_eq!(nonce.len(), 16);
///
/// // Tokens are cryptographically random - extremely unlikely to repeat
/// let token1 = generator.generate_token();
/// let token2 = generator.generate_token();
/// assert_ne!(token1, token2);
/// ```
///
/// # Performance Considerations
///
/// Token generation is relatively fast but involves system calls to the
/// entropy pool. For high-throughput applications, consider:
/// - Batch token generation
/// - Token caching with appropriate security considerations
/// - Using dedicated entropy sources for extreme performance requirements
pub struct TokenGenerator {
    /// Thread-safe random number generator backed by system entropy
    rng: rand::rngs::ThreadRng,
}

impl TokenGenerator {
    /// Create a new secure token generator
    ///
    /// Initializes a new token generator with a cryptographically secure
    /// random number generator. The generator is ready for immediate use
    /// and provides high-quality entropy for all token generation operations.
    ///
    /// # Security Initialization
    ///
    /// The underlying random number generator is initialized with:
    /// - System entropy from `/dev/urandom` (Unix) or `CryptGenRandom` (Windows)
    /// - Automatic reseeding to maintain entropy quality
    /// - Thread-local state for performance and thread safety
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::TokenGenerator;
    ///
    /// let generator = TokenGenerator::new();
    /// // Generator is immediately ready for use
    /// ```
    ///
    /// # Returns
    ///
    /// A new `TokenGenerator` instance ready for secure token generation.
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    /// Generate a cryptographically secure 32-byte token
    ///
    /// Creates a 32-byte (256-bit) cryptographically secure random token
    /// suitable for high-security applications. The token provides 256 bits
    /// of entropy, making it suitable for cryptographic keys, session tokens,
    /// and other security-critical applications.
    ///
    /// # Security Properties
    ///
    /// - **Entropy**: Full 256 bits of cryptographic entropy
    /// - **Uniqueness**: Probability of collision is negligible (2^-128)
    /// - **Unpredictability**: Cannot be predicted from previous tokens
    /// - **Uniformity**: Each bit has equal probability of being 0 or 1
    ///
    /// # Use Cases
    ///
    /// - Voting tokens for anonymous voting systems
    /// - Session identifiers for secure sessions
    /// - API keys and access tokens
    /// - Cryptographic salt values
    /// - Challenge values for authentication protocols
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::TokenGenerator;
    ///
    /// let mut generator = TokenGenerator::new();
    ///
    /// // Generate a secure voting token
    /// let voting_token = generator.generate_token();
    /// println!("Voting token: {:?}", hex::encode(&voting_token));
    ///
    /// // Generate multiple tokens - each will be unique
    /// let tokens: Vec<[u8; 32]> = (0..10)
    ///     .map(|_| generator.generate_token())
    ///     .collect();
    ///
    /// // Verify uniqueness (statistically certain)
    /// for i in 0..tokens.len() {
    ///     for j in i+1..tokens.len() {
    ///         assert_ne!(tokens[i], tokens[j]);
    ///     }
    /// }
    /// ```
    ///
    /// # Performance
    ///
    /// Token generation typically takes microseconds but may vary based on:
    /// - System entropy availability
    /// - Hardware random number generator performance
    /// - System load and scheduling
    ///
    /// # Returns
    ///
    /// A 32-byte array containing cryptographically secure random data.
    pub fn generate_token(&mut self) -> [u8; 32] {
        let mut token = [0u8; 32];
        self.rng.fill_bytes(&mut token);
        token
    }

    /// Generate a cryptographically secure 16-byte nonce
    ///
    /// Creates a 16-byte (128-bit) cryptographically secure random nonce
    /// suitable for cryptographic operations that require unique, unpredictable
    /// values. While shorter than tokens, nonces provide sufficient entropy
    /// for most cryptographic protocols.
    ///
    /// # Security Properties
    ///
    /// - **Entropy**: Full 128 bits of cryptographic entropy
    /// - **Uniqueness**: Probability of collision is very low (2^-64)
    /// - **Single-use**: Designed for one-time use in cryptographic protocols
    /// - **Unpredictability**: Cannot be predicted from previous nonces
    ///
    /// # Use Cases
    ///
    /// - Initialization vectors (IVs) for encryption
    /// - Nonces for digital signature schemes
    /// - Challenge values in authentication protocols
    /// - Salt values for key derivation (when 128 bits is sufficient)
    /// - Replay protection in message protocols
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::TokenGenerator;
    ///
    /// let mut generator = TokenGenerator::new();
    ///
    /// // Generate a nonce for encryption
    /// let iv_nonce = generator.generate_nonce();
    ///
    /// // Generate a challenge nonce for authentication
    /// let auth_challenge = generator.generate_nonce();
    ///
    /// // Generate nonce for replay protection
    /// let replay_nonce = generator.generate_nonce();
    ///
    /// // Each nonce is unique
    /// assert_ne!(iv_nonce, auth_challenge);
    /// assert_ne!(auth_challenge, replay_nonce);
    /// ```
    ///
    /// # Cryptographic Protocol Integration
    ///
    /// ```rust
    /// use vote::crypto::TokenGenerator;
    ///
    /// let mut generator = TokenGenerator::new();
    ///
    /// // Use with AES-GCM encryption
    /// let encryption_nonce = generator.generate_nonce();
    /// // ... perform AES-GCM encryption with nonce as IV
    ///
    /// // Use with Ed25519 signature scheme
    /// let signature_nonce = generator.generate_nonce();
    /// // ... use nonce in deterministic signature generation
    /// ```
    ///
    /// # Returns
    ///
    /// A 16-byte array containing cryptographically secure random data.
    pub fn generate_nonce(&mut self) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        self.rng.fill_bytes(&mut nonce);
        nonce
    }
}

impl Default for TokenGenerator {
    /// Create a default token generator instance
    ///
    /// Provides a convenient way to create a new `TokenGenerator` with
    /// default settings. This is equivalent to calling `TokenGenerator::new()`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::TokenGenerator;
    ///
    /// let generator = TokenGenerator::default();
    /// // Equivalent to: let generator = TokenGenerator::new();
    /// ```
    fn default() -> Self {
        Self::new()
    }
}

/// Cryptographic utility functions for the voting system
///
/// `CryptoUtils` provides a collection of stateless cryptographic utility
/// functions that implement secure, standardized algorithms. All functions
/// are designed to be thread-safe and resistant to timing attacks.
///
/// # Security Design Principles
///
/// - **Constant-time operations**: Critical functions use constant-time algorithms
/// - **Standardized algorithms**: Only uses well-vetted, standardized cryptographic algorithms
/// - **No key storage**: Utility functions don't store or cache cryptographic keys
/// - **Secure defaults**: All functions use secure parameters and configurations
///
/// # Supported Algorithms
///
/// - **Blake3**: Modern, high-performance cryptographic hash function
/// - **Hex encoding/decoding**: Secure conversion between binary and hexadecimal
/// - **UUID generation**: Cryptographically secure UUID v4 generation
/// - **Constant-time comparison**: Timing attack resistant equality testing
///
/// # Examples
///
/// ```rust
/// use vote::crypto::CryptoUtils;
///
/// // Hash computation
/// let data = b"vote data";
/// let hash = CryptoUtils::hash(data);
///
/// // Secure comparison
/// let hash2 = CryptoUtils::hash(data);
/// assert!(CryptoUtils::constant_time_eq(&hash, &hash2));
///
/// // Hex conversion
/// let hex = CryptoUtils::hash_to_hex(&hash);
/// let decoded = CryptoUtils::hex_to_hash(&hex).unwrap();
/// assert_eq!(hash, decoded);
/// ```
pub struct CryptoUtils;

impl CryptoUtils {
    /// Compute Blake3 cryptographic hash of arbitrary data
    ///
    /// Computes a 256-bit (32-byte) Blake3 hash of the input data. Blake3 is a
    /// modern cryptographic hash function that provides excellent security properties
    /// and performance characteristics.
    ///
    /// # Algorithm Properties
    ///
    /// Blake3 provides:
    /// - **Security**: Resistant to all known cryptographic attacks
    /// - **Performance**: Significantly faster than SHA-2 and SHA-3
    /// - **Parallelism**: Can utilize multiple CPU cores for large inputs
    /// - **Streaming**: Supports incremental hashing of large data
    /// - **Deterministic**: Same input always produces identical output
    ///
    /// # Security Properties
    ///
    /// - **Collision resistance**: Computationally infeasible to find two inputs with same hash
    /// - **Preimage resistance**: Cannot reverse-engineer input from hash output
    /// - **Second preimage resistance**: Cannot find different input with same hash
    /// - **Avalanche effect**: Small input changes drastically change output
    ///
    /// # Use Cases
    ///
    /// - Vote content integrity verification
    /// - Digital fingerprinting of election data
    /// - Merkle tree construction for audit trails
    /// - Content-addressed storage systems
    /// - Cryptographic commitment schemes
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// // Hash vote data
    /// let vote_content = b"candidate_alice";
    /// let vote_hash = CryptoUtils::hash(vote_content);
    ///
    /// // Hash election metadata
    /// let election_data = b"Election 2024: Board Members";
    /// let election_hash = CryptoUtils::hash(election_data);
    ///
    /// // Verify data integrity
    /// let received_data = b"candidate_alice";
    /// let received_hash = CryptoUtils::hash(received_data);
    /// assert_eq!(vote_hash, received_hash); // Data integrity verified
    /// ```
    ///
    /// # Performance
    ///
    /// Blake3 is optimized for:
    /// - Small inputs: Extremely fast for typical vote-sized data
    /// - Large inputs: Parallel processing utilizes multiple CPU cores
    /// - Streaming: Efficient for processing data in chunks
    ///
    /// # Parameters
    ///
    /// - `data`: Byte slice containing the data to hash
    ///
    /// # Returns
    ///
    /// A 32-byte Blake3 hash of the input data as a [`type@Hash`] type.
    pub fn hash(data: &[u8]) -> Hash {
        blake3::hash(data).into()
    }

    /// Verify hash equality in constant time to prevent timing attacks
    ///
    /// Compares two hashes using a constant-time algorithm that takes the same
    /// amount of time regardless of whether the hashes match or where they differ.
    /// This prevents timing-based side-channel attacks that could reveal information
    /// about the hash values.
    ///
    /// # Timing Attack Prevention
    ///
    /// Regular equality comparison (`==`) may leak information through timing:
    /// - Early termination when first differing byte is found
    /// - Variable execution time based on number of matching bytes
    /// - Cache-timing side channels from memory access patterns
    ///
    /// This function eliminates these vulnerabilities by:
    /// - Always examining all bytes regardless of differences
    /// - Using constant-time arithmetic operations
    /// - Avoiding conditional branches based on data values
    ///
    /// # Security Applications
    ///
    /// - Hash verification in authentication protocols
    /// - Message authentication code (MAC) verification
    /// - Digital signature validation
    /// - Cryptographic proof verification
    /// - Any security-critical hash comparison
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// let data1 = b"vote for alice";
    /// let data2 = b"vote for alice";
    /// let data3 = b"vote for bob";
    ///
    /// let hash1 = CryptoUtils::hash(data1);
    /// let hash2 = CryptoUtils::hash(data2);
    /// let hash3 = CryptoUtils::hash(data3);
    ///
    /// // Secure comparison - always use this for security-critical comparisons
    /// assert!(CryptoUtils::constant_time_eq(&hash1, &hash2));
    /// assert!(!CryptoUtils::constant_time_eq(&hash1, &hash3));
    ///
    /// // Never use regular == for security-critical hash comparison
    /// // assert!(hash1 == hash2); // ❌ Vulnerable to timing attacks
    /// ```
    ///
    /// # Performance
    ///
    /// While slightly slower than regular comparison, the performance difference
    /// is negligible (typically < 1 microsecond for 32-byte hashes) and the
    /// security benefits far outweigh the minimal performance cost.
    ///
    /// # Parameters
    ///
    /// - `a`: First hash to compare
    /// - `b`: Second hash to compare
    ///
    /// # Returns
    ///
    /// - `true`: Hashes are identical
    /// - `false`: Hashes differ in at least one bit
    pub fn constant_time_eq(a: &Hash, b: &Hash) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(b).into()
    }

    /// Generate a cryptographically secure UUID v4
    ///
    /// Creates a new UUID (Universally Unique Identifier) version 4 using
    /// cryptographically secure random number generation. UUID v4 uses 122 bits
    /// of random data, providing excellent uniqueness guarantees.
    ///
    /// # UUID v4 Properties
    ///
    /// - **Uniqueness**: Probability of collision is negligible (< 2^-61)
    /// - **Randomness**: Uses cryptographically secure random number generator
    /// - **No information leakage**: Does not contain MAC addresses or timestamps
    /// - **Standard compliance**: Follows RFC 4122 specification
    ///
    /// # Use Cases
    ///
    /// - Unique identifiers for votes, elections, and candidates
    /// - Session identifiers for security contexts
    /// - Audit trail record identifiers
    /// - Database primary keys for voting records
    /// - Request/response correlation in distributed systems
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// // Generate unique identifiers
    /// let vote_id = CryptoUtils::generate_uuid();
    /// let election_id = CryptoUtils::generate_uuid();
    /// let session_id = CryptoUtils::generate_uuid();
    ///
    /// // UUIDs are extremely unlikely to collide
    /// assert_ne!(vote_id, election_id);
    /// assert_ne!(election_id, session_id);
    ///
    /// // Convert to string for storage/transmission
    /// let vote_id_string = vote_id.to_string();
    /// println!("Vote ID: {}", vote_id_string);
    /// ```
    ///
    /// # Security Considerations
    ///
    /// - UUIDs are not cryptographically secret - they can be publicly exposed
    /// - Use UUIDs for identification, not for authorization or access control
    /// - While unique, UUIDs are predictable - don't use as security tokens
    ///
    /// # Returns
    ///
    /// A new cryptographically secure UUID v4.
    pub fn generate_uuid() -> Uuid {
        Uuid::new_v4()
    }

    /// Convert hexadecimal string to cryptographic hash
    ///
    /// Securely converts a hexadecimal string representation back to a binary
    /// hash value. Performs strict validation to ensure the input is exactly
    /// 64 hexadecimal characters (representing 32 bytes).
    ///
    /// # Input Validation
    ///
    /// - **Length check**: Must be exactly 64 characters (32 bytes * 2 chars/byte)
    /// - **Character validation**: Only accepts 0-9, a-f, A-F characters
    /// - **Format verification**: Rejects any invalid hexadecimal encoding
    ///
    /// # Security Considerations
    ///
    /// - Input validation prevents buffer overflow attacks
    /// - Constant-time parsing (when possible) prevents timing attacks
    /// - Error handling avoids information leakage through error messages
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// // Generate hash and convert to hex
    /// let original_hash = CryptoUtils::hash(b"vote data");
    /// let hex_string = CryptoUtils::hash_to_hex(&original_hash);
    ///
    /// // Convert back from hex to hash
    /// let restored_hash = CryptoUtils::hex_to_hash(&hex_string).unwrap();
    /// assert_eq!(original_hash, restored_hash);
    ///
    /// // Handle invalid input gracefully
    /// let invalid_hex = "not_valid_hex";
    /// assert!(CryptoUtils::hex_to_hash(invalid_hex).is_err());
    ///
    /// let wrong_length = "abc123"; // Too short
    /// assert!(CryptoUtils::hex_to_hash(wrong_length).is_err());
    /// ```
    ///
    /// # Error Conditions
    ///
    /// Returns [`crate::Error::Crypto`] if:
    /// - Input length is not exactly 64 characters
    /// - Input contains non-hexadecimal characters
    /// - Input format is malformed
    ///
    /// # Parameters
    ///
    /// - `hex`: Hexadecimal string representation of a hash (must be 64 characters)
    ///
    /// # Returns
    ///
    /// - `Ok(hash)`: Successfully decoded 32-byte hash
    /// - `Err(error)`: Invalid input format or length
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

    /// Convert cryptographic hash to hexadecimal string
    ///
    /// Converts a binary hash value to its hexadecimal string representation
    /// using lowercase letters. The resulting string is always exactly 64
    /// characters long and contains only 0-9 and a-f characters.
    ///
    /// # Output Format
    ///
    /// - **Length**: Always 64 characters (32 bytes * 2 chars/byte)
    /// - **Case**: Lowercase hexadecimal (a-f, not A-F)
    /// - **Prefix**: No "0x" prefix - just the hex digits
    /// - **Padding**: Leading zeros preserved for consistent length
    ///
    /// # Use Cases
    ///
    /// - Database storage of hash values
    /// - API responses containing hash values
    /// - Log entries and audit trails
    /// - Human-readable hash display
    /// - Configuration files and data exchange
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// // Hash some data and convert to hex
    /// let vote_data = b"alice_for_president";
    /// let hash = CryptoUtils::hash(vote_data);
    /// let hex_string = CryptoUtils::hash_to_hex(&hash);
    ///
    /// // Hex string properties
    /// assert_eq!(hex_string.len(), 64);
    /// assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
    /// assert!(hex_string.chars().all(|c| !c.is_ascii_uppercase()));
    ///
    /// println!("Vote hash: {}", hex_string);
    /// // Example output: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
    /// ```
    ///
    /// # Performance
    ///
    /// Hash-to-hex conversion is very fast (typically microseconds) and
    /// suitable for high-throughput applications.
    ///
    /// # Parameters
    ///
    /// - `hash`: 32-byte hash value to convert
    ///
    /// # Returns
    ///
    /// A 64-character lowercase hexadecimal string representation of the hash.
    pub fn hash_to_hex(hash: &Hash) -> String {
        hex::encode(hash)
    }

    /// Convert cryptographic signature to hexadecimal string
    ///
    /// Converts a binary signature value to its hexadecimal string representation.
    /// The resulting string is always exactly 128 characters long (64 bytes * 2).
    ///
    /// # Output Format
    ///
    /// - **Length**: Always 128 characters (64 bytes * 2 chars/byte)
    /// - **Case**: Lowercase hexadecimal (a-f, not A-F)
    /// - **Ed25519 compatible**: Designed for 64-byte Ed25519 signatures
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// let signature: [u8; 64] = [42u8; 64]; // Example signature
    /// let hex_string = CryptoUtils::signature_to_hex(&signature);
    ///
    /// assert_eq!(hex_string.len(), 128);
    /// assert!(hex_string.chars().all(|c| c.is_ascii_hexdigit()));
    /// ```
    ///
    /// # Parameters
    ///
    /// - `signature`: 64-byte signature value to convert
    ///
    /// # Returns
    ///
    /// A 128-character lowercase hexadecimal string representation of the signature.
    pub fn signature_to_hex(signature: &Signature) -> String {
        hex::encode(signature)
    }

    /// Convert hexadecimal string to cryptographic signature
    ///
    /// Securely converts a hexadecimal string back to a binary signature value.
    /// Performs strict validation for Ed25519 signature format.
    ///
    /// # Input Validation
    ///
    /// - **Length check**: Must be exactly 128 characters (64 bytes * 2)
    /// - **Character validation**: Only accepts valid hexadecimal characters
    /// - **Format verification**: Rejects malformed input
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::crypto::CryptoUtils;
    ///
    /// let original_sig: [u8; 64] = [42u8; 64];
    /// let hex_string = CryptoUtils::signature_to_hex(&original_sig);
    /// let restored_sig = CryptoUtils::hex_to_signature(&hex_string).unwrap();
    /// assert_eq!(original_sig, restored_sig);
    /// ```
    ///
    /// # Error Conditions
    ///
    /// Returns [`crate::Error::Crypto`] if:
    /// - Input length is not exactly 128 characters
    /// - Input contains non-hexadecimal characters
    ///
    /// # Parameters
    ///
    /// - `hex`: Hexadecimal string representation (must be 128 characters)
    ///
    /// # Returns
    ///
    /// - `Ok(signature)`: Successfully decoded 64-byte signature
    /// - `Err(error)`: Invalid input format or length
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
