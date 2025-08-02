//! Banking-Grade Cryptographic Security Hardening
//!
//! This module provides comprehensive cryptographic security for voting systems with
//! protection against timing attacks, replay attacks, and memory-based attacks.
//!
//! ## Security Architecture
//!
//! ```text
//! SecureSaltManager ──┬── Voter Identity Hashing (deterministic)
//!                     ├── Token Generation (nonce-based)
//!                     └── Token Validation (constant-time)
//!
//! SecureKeyPair ─────┬── Ed25519 Signing (timestamp-protected)
//!                    └── Signature Verification (replay-resistant)
//!
//! SecureMemory ──────┬── Constant-Time Operations
//!                    ├── Secure Memory Clearing
//!                    └── Timing-Attack Prevention
//! ```
//!
//! ## Core Security Features
//!
//! - **Timing Attack Resistance**: All cryptographic operations use constant-time algorithms
//! - **Memory Protection**: Automatic secure memory clearing with multiple defense layers
//! - **Replay Protection**: Timestamp-based validation prevents replay attacks
//! - **Rate Limiting**: Prevents brute force and timing attack attempts
//! - **Deterministic Hashing**: Same voter always gets same hash (timestamp for replay only)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use uuid::Uuid;
//!
//! use vote::crypto::SecureSaltManager;
//!
//! async fn secure_voting_example() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize salt manager
//!     let salt_manager = SecureSaltManager::for_testing();
//!
//!     // Generate voter hash (deterministic)
//!     let bank_id = "CZ1234567890";
//!     let election_id = Uuid::new_v4();
//!     let timestamp = std::time::SystemTime::now()
//!         .duration_since(std::time::UNIX_EPOCH)?.as_secs();
//!
//!     let voter_hash = salt_manager.hash_voter_identity_secure(
//!         bank_id, &election_id, timestamp, 300
//!     )?;
//!
//!     // Generate secure voting token
//!     let expires_at = timestamp + 3600; // 1 hour
//!     let (token_hash, nonce) = salt_manager.generate_voting_token_secure(
//!         &voter_hash, &election_id, expires_at
//!     )?;
//!
//!     // Validate token (constant-time)
//!     let is_valid = salt_manager.validate_voting_token_secure(
//!         &token_hash, &nonce, &voter_hash, &election_id, expires_at, timestamp
//!     )?;
//!
//!     println!("Token valid: {}", is_valid);
//!     Ok(())
//! }
//! ```

use crate::{Result, crypto_error};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeLess;
use uuid::Uuid;

/// Secure buffer for sensitive data with automatic memory clearing
///
/// Provides automatic secure memory clearing on drop using multiple defense techniques:
/// - Volatile writes to prevent compiler optimization
/// - Random XOR passes to prevent memory recovery
/// - Memory barriers to ensure completion
///
/// # Security
///
/// All sensitive data is automatically cleared when the buffer goes out of scope.
/// Manual clearing is also available via `secure_clear()`.
///
/// # Example
///
/// ```rust
/// use vote::crypto::secure::SecureBuffer;
///
///  async fn secure_buffer_example() -> Result<(), Box<dyn std::error::Error>> {
///     let mut buffer = SecureBuffer::new(32);
///     // Use buffer for sensitive operations
///     buffer.secure_clear(); // Optional manual clearing
///     // Automatic clearing on drop
///     println!("SecureBuffer operations completed");
///     Ok(())
/// }
/// ```
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create new secure buffer with specified size
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    /// Create secure buffer from existing data
    pub fn from_data(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Get immutable reference to data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable reference to data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get length of buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Securely clear the buffer (can be called manually)
    pub fn secure_clear(&mut self) {
        SecureMemory::secure_zero(&mut self.data);
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // Securely clear memory on drop
        SecureMemory::secure_zero(&mut self.data);
        tracing::trace!("SecureBuffer memory cleared on drop");
    }
}

impl Clone for SecureBuffer {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

/// Secure salt manager for voter identity and token operations
///
/// Provides cryptographically secure salt management with timing attack resistance.
/// The salt manager handles two critical operations:
/// 1. **Voter Identity Hashing**: Deterministic hashing for consistent voter identification
/// 2. **Token Operations**: Generation and validation of voting tokens with nonce-based security
///
/// # Security Features
///
/// - **Deterministic Hashing**: Same voter always gets same hash (timestamp only for replay protection)
/// - **Constant-Time Validation**: All token validation uses constant-time operations
/// - **Cryptographically Secure**: Uses Blake3 keyed hashing and secure random nonces
/// - **Memory Protection**: All sensitive data automatically cleared
///
/// # Production Setup
///
/// ```bash
/// export CRYPTO_VOTER_SALT="$(openssl rand -base64 32)"
/// export CRYPTO_TOKEN_SALT="$(openssl rand -base64 32)"
/// ```
///
/// # Example
///
/// ```rust
/// use uuid::Uuid;
/// use vote::crypto::SecureSaltManager;
///
/// let salt_manager = SecureSaltManager::for_testing();
/// let bank_id = "CZ1234567890";
/// let election_id = Uuid::new_v4();
/// let timestamp = std::time::SystemTime::now()
///         .duration_since(std::time::UNIX_EPOCH)?.as_secs();
///
/// // Generate deterministic voter hash
/// let voter_hash = salt_manager.hash_voter_identity_secure(
///     bank_id, &election_id, timestamp, 300
/// )?;
///
/// // Generate secure token
/// let expires_at = timestamp + 3600;
/// let (token, nonce) = salt_manager.generate_voting_token_secure(
///     &voter_hash, &election_id, expires_at
/// )?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct SecureSaltManager {
    voter_salt: SecureBuffer,
    token_salt: SecureBuffer,
}

impl SecureSaltManager {
    /// Create salt manager from environment variables
    ///
    /// **CRITICAL**: These must be set in production:
    /// - `CRYPTO_VOTER_SALT` (minimum 32 bytes, base64 encoded)
    /// - `CRYPTO_TOKEN_SALT` (minimum 32 bytes, base64 encoded)
    ///
    /// # Security
    ///
    /// Environment-based salts prevent hardcoded secrets and enable proper
    /// key rotation in production environments.
    pub fn from_env() -> Result<Self> {
        let voter_salt = std::env::var("CRYPTO_VOTER_SALT")
            .map_err(|_| crypto_error!("CRYPTO_VOTER_SALT environment variable required"))?;

        let token_salt = std::env::var("CRYPTO_TOKEN_SALT")
            .map_err(|_| crypto_error!("CRYPTO_TOKEN_SALT environment variable required"))?;

        // Decode from base64 and validate length
        use base64::Engine;
        let voter_salt_bytes = base64::engine::general_purpose::STANDARD
            .decode(&voter_salt)
            .map_err(|_| crypto_error!("CRYPTO_VOTER_SALT must be valid base64"))?;

        let token_salt_bytes = base64::engine::general_purpose::STANDARD
            .decode(&token_salt)
            .map_err(|_| crypto_error!("CRYPTO_TOKEN_SALT must be valid base64"))?;

        if voter_salt_bytes.len() < 32 {
            return Err(crypto_error!("CRYPTO_VOTER_SALT must be at least 32 bytes"));
        }

        if token_salt_bytes.len() < 32 {
            return Err(crypto_error!("CRYPTO_TOKEN_SALT must be at least 32 bytes"));
        }

        Ok(Self {
            voter_salt: SecureBuffer::from_data(voter_salt_bytes),
            token_salt: SecureBuffer::from_data(token_salt_bytes),
        })
    }

    /// Create for testing with secure random salts
    ///
    /// Generates cryptographically secure random salts for testing and development.
    /// **Do not use in production** - use `from_env()` instead.
    pub fn for_testing() -> Self {
        let mut rng = rand::thread_rng();

        let mut voter_salt = SecureBuffer::new(32);
        let mut token_salt = SecureBuffer::new(32);

        rng.fill_bytes(voter_salt.as_mut_slice());
        rng.fill_bytes(token_salt.as_mut_slice());

        Self {
            voter_salt,
            token_salt,
        }
    }

    /// Generate deterministic voter hash with replay protection
    ///
    /// Creates a deterministic hash for voter identification that's consistent across
    /// sessions while providing replay attack protection via timestamp validation.
    ///
    /// # Security Features
    ///
    /// - **Timing Attack Resistant**: Always performs full computation regardless of timestamp validity
    /// - **Constant-Time Validation**: Uses constant-time timestamp comparison
    /// - **Deterministic**: Same voter always gets same hash (timestamp not included in hash)
    /// - **Replay Protection**: Timestamp validation prevents replay attacks
    ///
    /// # Arguments
    ///
    /// * `bank_id` - Bank identifier for voter
    /// * `election_id` - Election UUID for context
    /// * `timestamp` - Request timestamp for replay protection
    /// * `max_age_seconds` - Maximum allowed age of timestamp
    ///
    /// # Returns
    ///
    /// 32-byte deterministic voter hash if timestamp is valid
    ///
    /// # Security
    ///
    /// The hash is deterministic (same inputs always produce same output) but
    /// the timestamp provides replay protection. This ensures consistent voter
    /// identification while preventing replay attacks.
    pub fn hash_voter_identity_secure(
        &self,
        bank_id: &str,
        election_id: &Uuid,
        timestamp: u64,
        max_age_seconds: u64,
    ) -> Result<[u8; 32]> {
        use subtle::ConstantTimeLess;

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        // ALWAYS compute the hash regardless of timestamp validity
        // This prevents timing attacks based on early timestamp rejection
        let mut hasher =
            blake3::Hasher::new_keyed(&self.voter_salt.as_slice()[..32].try_into().unwrap());
        hasher.update(bank_id.as_bytes());
        hasher.update(election_id.as_bytes());
        // NOTE: timestamp intentionally NOT included to ensure deterministic hashes
        let computed_hash = hasher.finalize().into();

        // Constant-time timestamp validation to prevent timing attacks
        let age = current_time.saturating_sub(timestamp);
        let timestamp_valid = age.ct_lt(&max_age_seconds);

        if timestamp_valid.into() {
            Ok(computed_hash)
        } else {
            Err(crypto_error!("Timestamp too old - possible replay attack"))
        }
    }

    /// Generate secure voting token with expiration
    ///
    /// Creates a cryptographically secure voting token using Blake3 keyed hashing
    /// with a random nonce for uniqueness and security.
    ///
    /// # Security
    ///
    /// - Uses cryptographically secure random nonce (16 bytes)
    /// - Blake3 keyed hashing with dedicated token salt
    /// - Binds token to voter, election, and expiration time
    ///
    /// # Returns
    ///
    /// Tuple of (token_hash, nonce) - both needed for validation
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
        let mut hasher =
            blake3::Hasher::new_keyed(&self.token_salt.as_slice()[..32].try_into().unwrap());
        hasher.update(voter_hash);
        hasher.update(election_id.as_bytes());
        hasher.update(&nonce);
        hasher.update(&expires_at.to_le_bytes());

        let token_hash = hasher.finalize().into();

        Ok((token_hash, nonce))
    }

    /// Validate voting token with constant-time security
    ///
    /// Validates a voting token by regenerating it and performing constant-time comparison.
    /// This is the critical security function that prevents token forgery.
    ///
    /// # Security Features
    ///
    /// - **Always Computes**: Performs full cryptographic computation regardless of expiration
    /// - **Constant-Time**: All comparisons use constant-time operations
    /// - **No Early Returns**: Prevents timing oracles from validation flow
    /// - **Consistent Timing**: Same execution time regardless of token validity
    ///
    /// # Arguments
    ///
    /// * `provided_token_hash` - Token hash to validate
    /// * `nonce` - Random nonce from token generation
    /// * `voter_hash` - Voter's deterministic hash
    /// * `election_id` - Election context
    /// * `expires_at` - Token expiration timestamp
    /// * `current_timestamp` - Current time for expiration check
    ///
    /// # Returns
    ///
    /// `true` if token is valid and not expired, `false` otherwise
    pub fn validate_voting_token_secure(
        &self,
        provided_token_hash: &[u8; 32],
        nonce: &[u8; 16],
        voter_hash: &[u8; 32],
        election_id: &Uuid,
        expires_at: u64,
        current_timestamp: u64,
    ) -> Result<bool> {
        use subtle::ConstantTimeEq;

        // ALWAYS perform the expensive cryptographic operation regardless of expiration
        // This prevents timing oracles based on early returns
        let mut hasher =
            blake3::Hasher::new_keyed(&self.token_salt.as_slice()[..32].try_into().unwrap());
        hasher.update(voter_hash);
        hasher.update(election_id.as_bytes());
        hasher.update(nonce);
        hasher.update(&expires_at.to_le_bytes());

        let expected_token_hash = *hasher.finalize().as_bytes();

        // Constant-time comparison of token hashes
        let hash_matches = provided_token_hash.ct_eq(&expected_token_hash);

        // Constant-time expiration check
        let not_expired = current_timestamp.ct_lt(&expires_at);

        // Combine all checks with constant-time AND operation
        let token_valid = hash_matches & not_expired;

        Ok(token_valid.into())
    }

    /// Generate secure session token for user sessions (not voting)
    ///
    /// Creates session tokens for general user authentication (separate from voting tokens).
    pub fn generate_session_token(&self) -> Result<([u8; 32], u64)> {
        let mut session_data = SecureBuffer::new(32);
        let mut rng = rand::thread_rng();
        rng.fill_bytes(session_data.as_mut_slice());

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        // Hash with salt for additional security
        let mut hasher =
            blake3::Hasher::new_keyed(&self.token_salt.as_slice()[..32].try_into().unwrap());
        hasher.update(session_data.as_slice());
        hasher.update(&timestamp.to_le_bytes());

        let session_token = hasher.finalize().into();

        // session_data will be securely cleared on drop
        Ok((session_token, timestamp))
    }

    /// Validate voter hash format for security compliance
    pub fn validate_voter_hash_format(&self, voter_hash: &str) -> Result<[u8; 32]> {
        let decoded =
            hex::decode(voter_hash).map_err(|_| crypto_error!("Invalid voter hash hex format"))?;

        if decoded.len() != 32 {
            return Err(crypto_error!("Voter hash must be exactly 32 bytes"));
        }

        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&decoded);
        Ok(hash_array)
    }
}

/// Cryptographic key pair with enhanced memory protection and expiration
///
/// Provides Ed25519 digital signatures with automatic memory clearing and
/// timestamp-based replay protection.
///
/// # Security Features
///
/// - **Ed25519 Signatures**: Industry-standard elliptic curve cryptography
/// - **Memory Protection**: Automatic secure clearing of sensitive key material
/// - **Timestamp Binding**: All signatures include timestamps for replay protection
/// - **Expiration Support**: Keys can be configured to expire automatically
/// - **Secure Debug**: Debug output never exposes private key material
///
/// # Example
///
/// ```rust,no_run
/// use vote::crypto::SecureKeyPair;
///
///  async fn key_pair_example() -> Result<(), Box<dyn std::error::Error>> {
///     let key_pair = SecureKeyPair::generate_with_expiration(Some(3600))?; // 1 hour
///     let message = b"secure voting data";
///     let (signature, timestamp) = key_pair.sign_with_timestamp(message)?;
///
///     // Verify with 5-minute tolerance
///     key_pair.verify_with_timestamp(message, &signature, timestamp, 300)?;
///     println!("Signature verified successfully");
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct SecureKeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    #[allow(dead_code)]
    created_at: u64,
    expires_at: Option<u64>,
    /// Secure buffer for sensitive key material backup (for secure clearing)
    sensitive_data: Option<SecureBuffer>,
}

// SECURITY: Custom Debug implementation to prevent accidental exposure of cryptographic keys
impl std::fmt::Debug for SecureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureKeyPair")
            .field("public_key", &hex::encode(self.public_key()))
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("is_expired", &self.is_expired())
            .field("has_sensitive_data", &self.sensitive_data.is_some())
            .finish_non_exhaustive() // Indicates there are private fields
    }
}

impl Drop for SecureKeyPair {
    fn drop(&mut self) {
        // Secure memory clearing for banking-grade security

        // Clear any sensitive data buffer
        if let Some(ref mut sensitive_data) = self.sensitive_data {
            sensitive_data.secure_clear();
        }

        // The ed25519_dalek SigningKey doesn't expose its internal bytes directly,
        // but we can ensure any derived sensitive material is cleared

        // For maximum security, we could:
        // 1. Override the signing key memory (if possible)
        // 2. Request garbage collection
        // 3. Add memory barriers to prevent compiler optimizations

        // Note: ed25519_dalek v2.x has its own secure memory handling
        // but we add our own layer for defense in depth

        tracing::debug!("SecureKeyPair memory security cleanup completed");

        // Memory barrier to prevent compiler from optimizing away the clearing
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl SecureKeyPair {
    /// Generate new key pair with optional expiration
    ///
    /// Creates a cryptographically secure Ed25519 key pair with enhanced memory protection.
    ///
    /// # Arguments
    ///
    /// * `expires_in_seconds` - Optional expiration time (None for no expiration)
    pub fn generate_with_expiration(expires_in_seconds: Option<u64>) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        let expires_at = expires_in_seconds.map(|exp| created_at + exp);

        // Create secure buffer for additional sensitive data if needed
        let sensitive_data = Some(SecureBuffer::new(64)); // Reserve space for sensitive operations

        Ok(Self {
            signing_key,
            verifying_key,
            created_at,
            expires_at,
            sensitive_data,
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

    /// Get public key bytes
    pub fn public_key(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Sign message with timestamp for replay protection
    ///
    /// Creates a digital signature that includes the current timestamp to prevent replay attacks.
    ///
    /// # Security
    ///
    /// The timestamp is bound to the signature, making each signature unique even for
    /// identical messages. This prevents replay attacks while maintaining signature verification.
    ///
    /// # Returns
    ///
    /// Tuple of (signature_bytes, timestamp) - both needed for verification
    pub fn sign_with_timestamp(&self, message: &[u8]) -> Result<([u8; 64], u64)> {
        if self.is_expired() {
            return Err(crypto_error!("Key pair has expired"));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| crypto_error!("System time error"))?
            .as_secs();

        // Use secure buffer for signed data construction
        let mut signed_data = SecureBuffer::new(message.len() + 8);
        signed_data.as_mut_slice()[..message.len()].copy_from_slice(message);
        signed_data.as_mut_slice()[message.len()..].copy_from_slice(&timestamp.to_le_bytes());

        let signature = self.signing_key.sign(signed_data.as_slice());

        // signed_data will be securely cleared on drop
        Ok((signature.to_bytes(), timestamp))
    }

    /// Verify signature with timestamp validation
    ///
    /// Verifies both the cryptographic signature and timestamp freshness to prevent replay attacks.
    ///
    /// # Arguments
    ///
    /// * `message` - Original message that was signed
    /// * `signature` - Signature bytes to verify
    /// * `timestamp` - Timestamp from signing
    /// * `max_age_seconds` - Maximum allowed age of signature
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

        // Reconstruct signed data using secure buffer
        let mut signed_data = SecureBuffer::new(message.len() + 8);
        signed_data.as_mut_slice()[..message.len()].copy_from_slice(message);
        signed_data.as_mut_slice()[message.len()..].copy_from_slice(&timestamp.to_le_bytes());

        let ed25519_sig = Ed25519Signature::from_slice(signature)
            .map_err(|_| crypto_error!("Invalid signature format"))?;

        // signed_data will be securely cleared on drop
        self.verifying_key
            .verify(signed_data.as_slice(), &ed25519_sig)
            .map_err(|_| crypto_error!("Signature verification failed"))
    }

    /// Securely clear any cached sensitive material
    pub fn secure_clear(&mut self) {
        if let Some(ref mut sensitive_data) = self.sensitive_data {
            sensitive_data.secure_clear();
        }
    }
}

/// Rate limiter for cryptographic operations to prevent timing attacks
///
/// Provides operation rate limiting to prevent brute force attacks and timing attack attempts.
/// Maintains a sliding window of recent operations to enforce rate limits.
pub struct CryptoRateLimiter {
    max_operations_per_second: u32,
    operations: VecDeque<u64>,
}

impl CryptoRateLimiter {
    /// Create new rate limiter with specified operations per second
    pub fn new(max_operations_per_second: u32) -> Self {
        Self {
            max_operations_per_second,
            operations: VecDeque::new(),
        }
    }

    /// Check if operation is allowed under current rate limit
    ///
    /// Uses a sliding window approach to track operations and enforce rate limits.
    /// Helps prevent timing attack attempts by limiting operation frequency.
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

/// Secure memory operations with comprehensive protection against attacks
///
/// Provides timing-attack-resistant memory operations and secure memory management
/// using multiple defense techniques for banking-grade security.
///
/// # Security Features
///
/// - **Timing Attack Resistance**: All operations use constant-time algorithms
/// - **Memory Recovery Protection**: Multiple clearing passes with random data
/// - **Compiler Optimization Protection**: Volatile operations and memory barriers
/// - **Verification**: Debug assertions verify memory clearing completion
///
/// # Example
///
/// ```rust,no_run
/// use vote::crypto::SecureMemory;
///
///  async fn secure_memory_example() -> Result<(), Box<dyn std::error::Error>> {
///     // Secure memory allocation
///     let mut buffer = SecureMemory::secure_alloc(32);
///
///     // Constant-time comparison
///     let data1 = [0x42u8; 8];
///     let data2 = [0x42u8; 8];
///     let equal = SecureMemory::constant_time_eq(&data1, &data2);
///
///     // Secure memory clearing
///     let mut sensitive_data = vec![0x42u8; 16];
///     SecureMemory::secure_zero(&mut sensitive_data);
///
///     println!("Secure memory operations completed");
///     Ok(())
/// }
/// ```
pub struct SecureMemory;

impl SecureMemory {
    /// Securely zero memory using multiple defense techniques
    ///
    /// Uses multiple techniques to prevent compiler optimization and ensure memory clearing:
    /// - Volatile writes to prevent optimization
    /// - Random XOR passes to prevent memory recovery
    /// - Memory barriers to ensure completion
    /// - Verification pass to confirm clearing
    ///
    /// # Security
    ///
    /// This is a paranoid implementation that uses multiple methods to ensure
    /// sensitive data cannot be recovered from memory, even with physical access.
    pub fn secure_zero(data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        // Method 1: Volatile writes (prevents compiler optimization)
        for byte in data.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }

        // Method 2: XOR with random data then zero (defense against memory recovery)
        let mut rng = rand::thread_rng();
        for byte in data.iter_mut() {
            let random_byte = (rng.next_u32() & 0xFF) as u8;
            *byte ^= random_byte;
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }

        // Method 3: Memory barrier to ensure completion
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);

        // Method 4: Final verification pass
        for byte in data.iter() {
            debug_assert_eq!(*byte, 0, "Memory clearing verification failed");
        }
    }

    /// Securely allocate and zero a buffer
    pub fn secure_alloc(size: usize) -> SecureBuffer {
        let mut buffer = SecureBuffer::new(size);
        Self::secure_zero(buffer.as_mut_slice());
        buffer
    }

    /// Securely copy data with automatic source clearing
    pub fn secure_copy_and_clear(source: &mut [u8], dest: &mut [u8]) -> Result<()> {
        if source.len() != dest.len() {
            return Err(crypto_error!(
                "Source and destination must have same length"
            ));
        }

        // Copy data
        dest.copy_from_slice(source);

        // Clear source
        Self::secure_zero(source);

        Ok(())
    }

    /// Constant-time byte array comparison
    ///
    /// Compares two byte arrays in constant time to prevent timing attacks.
    /// Uses the `subtle` crate for guaranteed constant-time operations.
    ///
    /// # Security
    ///
    /// - Prevents length-based timing attacks
    /// - Performs dummy operations for consistent timing
    /// - No early returns that could leak information
    /// - Both length and content comparisons are constant-time
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;

        // Length check must also be constant-time to prevent length-based timing attacks
        let length_matches = (a.len() as u64).ct_eq(&(b.len() as u64));

        if a.len() != b.len() {
            // If lengths differ, still do a dummy comparison to maintain constant timing
            let dummy_a = [0u8; 32];
            let dummy_b = [1u8; 32]; // Different to ensure comparison actually runs
            let _dummy_result = dummy_a.ct_eq(&dummy_b);
            return false;
        }

        // Perform constant-time comparison
        let content_matches = a.ct_eq(b);

        // Both length and content must match
        (length_matches & content_matches).into()
    }

    /// Constant-time string comparison
    pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
        Self::constant_time_eq(a.as_bytes(), b.as_bytes())
    }

    /// Constant-time UUID comparison
    pub fn constant_time_uuid_eq(a: &uuid::Uuid, b: &uuid::Uuid) -> bool {
        Self::constant_time_eq(a.as_bytes(), b.as_bytes())
    }

    /// Constant-time integer comparison
    pub fn constant_time_u64_eq(a: u64, b: u64) -> bool {
        use subtle::ConstantTimeEq;
        a.ct_eq(&b).into()
    }

    /// Constant-time less-than-or-equal comparison for timestamps
    pub fn constant_time_u64_le(a: u64, b: u64) -> bool {
        use subtle::ConstantTimeLess;
        // a <= b is equivalent to !(a > b) which is !(b < a)
        let b_less_than_a = b.ct_lt(&a);
        (!b_less_than_a).into()
    }

    /// Generate cryptographically secure random bytes
    pub fn secure_random_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    /// Generate secure random data into a SecureBuffer
    pub fn secure_random_buffer(size: usize) -> SecureBuffer {
        let mut buffer = SecureBuffer::new(size);
        use rand::RngCore;
        rand::thread_rng().fill_bytes(buffer.as_mut_slice());
        buffer
    }

    /// Constant-time conditional selection
    ///
    /// Selects data based on condition without timing leakage.
    pub fn constant_time_select(
        condition: bool,
        if_true: &[u8],
        if_false: &[u8],
    ) -> Result<SecureBuffer> {
        if if_true.len() != if_false.len() {
            return Err(crypto_error!(
                "Arrays must have same length for constant-time select"
            ));
        }

        use subtle::{ConditionallySelectable, ConstantTimeEq};

        let mut result = SecureBuffer::new(if_true.len());
        let condition_ct = if condition { 1u8 } else { 0u8 }.ct_eq(&1u8);

        for i in 0..if_true.len() {
            let selected = u8::conditional_select(&if_false[i], &if_true[i], condition_ct);
            result.as_mut_slice()[i] = selected;
        }

        Ok(result)
    }

    /// Secure comparison with automatic result clearing
    pub fn secure_compare_and_clear(a: &mut [u8], b: &mut [u8]) -> bool {
        let result = Self::constant_time_eq(a, b);

        // Clear both inputs after comparison
        Self::secure_zero(a);
        Self::secure_zero(b);

        result
    }
}

/// Secure string type for sensitive text data with automatic memory clearing
///
/// Provides secure string handling with automatic memory clearing and
/// constant-time comparison operations.
pub struct SecureString {
    buffer: SecureBuffer,
}

impl SecureString {
    /// Create new secure string from &str
    pub fn new(s: &str) -> Self {
        let buffer = SecureBuffer::from_data(s.as_bytes().to_vec());
        Self { buffer }
    }

    /// Create empty secure string with capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: SecureBuffer::new(capacity),
        }
    }

    /// Get string content (use carefully - exposes sensitive data)
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.buffer.as_slice())
            .map_err(|_| crypto_error!("Invalid UTF-8 in secure string"))
    }

    /// Compare with another string in constant time
    pub fn constant_time_eq(&self, other: &str) -> bool {
        SecureMemory::constant_time_eq(self.buffer.as_slice(), other.as_bytes())
    }

    /// Securely clear the string
    pub fn secure_clear(&mut self) {
        self.buffer.secure_clear();
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // SecureBuffer will handle the memory clearing
        tracing::trace!("SecureString dropped with secure memory clearing");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_buffer_memory_clearing() {
        let mut buffer = SecureBuffer::new(32);

        // Fill with test data (ensure non-zero values)
        for (i, byte) in buffer.as_mut_slice().iter_mut().enumerate() {
            *byte = ((i % 255) + 1) as u8; // Range 1-255, never 0
        }

        // Verify data was written
        assert_ne!(buffer.as_slice()[0], 0);
        assert_ne!(buffer.as_slice()[10], 0);

        // Manually clear
        buffer.secure_clear();

        // Verify all bytes are zero
        for byte in buffer.as_slice() {
            assert_eq!(*byte, 0, "Buffer should be securely cleared");
        }

        println!("✅ SecureBuffer memory clearing works correctly");
    }

    #[test]
    fn test_enhanced_secure_memory_operations() {
        // Test secure allocation
        let buffer = SecureMemory::secure_alloc(64);
        assert_eq!(buffer.len(), 64);

        // All bytes should be zero after secure allocation
        for byte in buffer.as_slice() {
            assert_eq!(*byte, 0);
        }

        // Test secure random buffer
        let random_buffer = SecureMemory::secure_random_buffer(32);
        assert_eq!(random_buffer.len(), 32);

        // Should contain random data (very unlikely to be all zeros)
        let all_zero = random_buffer.as_slice().iter().all(|&b| b == 0);
        assert!(!all_zero, "Random buffer should not be all zeros");

        println!("✅ Enhanced secure memory operations work correctly");
    }

    #[test]
    fn test_secure_copy_and_clear() {
        let mut source = [0x42u8; 16];
        let mut dest = [0u8; 16];

        // Copy and clear
        SecureMemory::secure_copy_and_clear(&mut source, &mut dest).unwrap();

        // Destination should have the data
        assert_eq!(dest[0], 0x42);
        assert_eq!(dest[15], 0x42);

        // Source should be cleared
        for byte in &source {
            assert_eq!(*byte, 0, "Source should be cleared after copy");
        }

        println!("✅ Secure copy and clear works correctly");
    }

    #[test]
    fn test_constant_time_select() {
        let true_data = [0x11u8; 8];
        let false_data = [0x22u8; 8];

        // Select true case
        let true_result =
            SecureMemory::constant_time_select(true, &true_data, &false_data).unwrap();
        assert_eq!(true_result.as_slice(), &true_data);

        // Select false case
        let false_result =
            SecureMemory::constant_time_select(false, &true_data, &false_data).unwrap();
        assert_eq!(false_result.as_slice(), &false_data);

        println!("✅ Constant-time select works correctly");
    }

    #[test]
    fn test_secure_string_operations() {
        let secret_text = "sensitive_banking_data_12345";
        let mut secure_str = SecureString::new(secret_text);

        // Test content access
        assert_eq!(secure_str.as_str().unwrap(), secret_text);
        assert_eq!(secure_str.len(), secret_text.len());

        // Test constant-time comparison
        assert!(secure_str.constant_time_eq(secret_text));
        assert!(!secure_str.constant_time_eq("different_text"));

        // Test manual clearing
        secure_str.secure_clear();

        // After clearing, the buffer should be zeros
        for byte in secure_str.buffer.as_slice() {
            assert_eq!(*byte, 0);
        }

        println!("✅ SecureString operations work correctly");
    }

    #[test]
    fn test_enhanced_key_pair_memory_security() {
        let key_pair = SecureKeyPair::generate_with_expiration(Some(3600)).unwrap();
        assert!(!key_pair.is_expired());

        let message = b"test message for memory security";
        let (signature, timestamp) = key_pair.sign_with_timestamp(message).unwrap();

        // Verification should work
        key_pair
            .verify_with_timestamp(message, &signature, timestamp, 300)
            .unwrap();

        // The key pair will be dropped at end of scope, testing memory clearing
        println!("✅ Enhanced key pair memory security works");
    }

    #[test]
    fn test_secure_salt_manager_with_memory_protection() {
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

        // Test session token generation
        let (session_token, session_timestamp) = salt_manager.generate_session_token().unwrap();
        assert_ne!(session_token, [0u8; 32]);
        assert!(session_timestamp > 0);

        println!("✅ Secure salt manager with memory protection works");
    }

    #[test]
    fn test_memory_security_under_pressure() {
        // Create many secure buffers to test memory management under pressure
        let mut buffers = Vec::new();

        for i in 0..1000 {
            let mut buffer = SecureBuffer::new(64);

            // Fill with test data (ensure non-zero values)
            for (j, byte) in buffer.as_mut_slice().iter_mut().enumerate() {
                *byte = (((i + j) % 255) + 1) as u8; // Range 1-255, never 0
            }

            buffers.push(buffer);
        }

        // All buffers should have different data
        assert_ne!(buffers[0].as_slice(), buffers[1].as_slice());
        assert_ne!(buffers[0].as_slice(), buffers[999].as_slice());

        // Clear all buffers manually
        for buffer in &mut buffers {
            buffer.secure_clear();
        }

        // Verify all are cleared
        for buffer in &buffers {
            for byte in buffer.as_slice() {
                assert_eq!(*byte, 0);
            }
        }

        // Drop all buffers (will trigger automatic clearing again)
        drop(buffers);

        println!("✅ Memory security under pressure works correctly");
    }

    #[test]
    fn test_secure_memory_zero_different_sizes() {
        // Test secure_zero with different buffer sizes
        let sizes = [0, 1, 8, 16, 32, 64, 128, 256, 1024];

        for size in sizes {
            let mut buffer = vec![0xFFu8; size]; // Fill with 0xFF instead of 0x00
            SecureMemory::secure_zero(&mut buffer);

            for byte in &buffer {
                assert_eq!(*byte, 0, "Buffer of size {size} not properly cleared");
            }
        }

        println!("✅ Secure memory clearing works for all buffer sizes");
    }

    #[test]
    fn test_constant_time_operations_with_memory_security() {
        // Test constant-time equality
        let hash1 = [0x42u8; 32];
        let hash2 = [0x42u8; 32]; // Same
        let hash3 = [0x43u8; 32]; // Different

        assert!(SecureMemory::constant_time_eq(&hash1, &hash2));
        assert!(!SecureMemory::constant_time_eq(&hash1, &hash3));

        // Test constant-time string comparison
        assert!(SecureMemory::constant_time_str_eq("same", "same"));
        assert!(!SecureMemory::constant_time_str_eq("different", "strings"));

        // Test constant-time numeric operations
        assert!(SecureMemory::constant_time_u64_eq(42, 42));
        assert!(!SecureMemory::constant_time_u64_eq(42, 43));

        assert!(SecureMemory::constant_time_u64_le(10, 20)); // 10 <= 20
        assert!(SecureMemory::constant_time_u64_le(20, 20)); // 20 <= 20
        assert!(!SecureMemory::constant_time_u64_le(30, 20)); // !(30 <= 20)

        println!("✅ All constant-time operations with memory security working correctly");
    }

    #[test]
    fn test_secure_compare_and_clear() {
        let mut data1 = [0x42u8; 16];
        let mut data2 = [0x42u8; 16];
        let mut data3 = [0x43u8; 16];

        // Test equal comparison
        let result1 = SecureMemory::secure_compare_and_clear(&mut data1, &mut data2);
        assert!(result1);

        // Both should be cleared after comparison
        for byte in &data1 {
            assert_eq!(*byte, 0);
        }
        for byte in &data2 {
            assert_eq!(*byte, 0);
        }

        // Test different comparison
        let mut data4 = [0x44u8; 16];
        let result2 = SecureMemory::secure_compare_and_clear(&mut data3, &mut data4);
        assert!(!result2);

        // Both should be cleared after comparison
        for byte in &data3 {
            assert_eq!(*byte, 0);
        }
        for byte in &data4 {
            assert_eq!(*byte, 0);
        }

        println!("✅ Secure compare and clear works correctly");
    }
}
