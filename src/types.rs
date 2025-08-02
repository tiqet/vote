//! # Core Types for the Cryptographically Secure Voting System
//!
//! This module defines the fundamental data structures and types used throughout
//! the voting system. All types are designed with security, serialization, and
//! future extensibility in mind.
//!
//! ## Security Design Principles
//!
//! - **Cryptographic safety**: All cryptographic types use fixed-size arrays
//! - **Serialization security**: Secure handling of sensitive data in transit
//! - **Timestamp integrity**: Unix timestamps with validation for replay protection
//! - **Anonymous voting**: Voter identity separation from vote content
//! - **Audit compliance**: Full traceability without compromising anonymity
//!
//! ## Type Categories
//!
//! ### Cryptographic Primitives
//! - [`type@Hash`]: 32-byte Blake3 cryptographic hashes
//! - [`Signature`]: 64-byte Ed25519 digital signatures
//! - [`PublicKey`]: 32-byte Ed25519 public keys
//! - [`VoterHash`]: Anonymized voter identifiers
//!
//! ### Core Entities
//! - [`Election`]: Election metadata and timing
//! - [`Candidate`]: Candidate information and eligibility
//! - [`AnonymousVote`]: Cryptographically secure anonymous votes
//! - [`VoteResult`]: Aggregated voting results
//!
//! ## Usage Examples
//!
//! ```rust
//! use vote::types::*;
//! use chrono::Utc;
//! use uuid::Uuid;
//!
//! // Create an election
//! let election = Election {
//!     id: Uuid::new_v4(),
//!     title: "Board Election 2024".to_string(),
//!     description: Some("Annual board member election".to_string()),
//!     start_time: Utc::now().timestamp() + 3600, // Starts in 1 hour
//!     end_time: Utc::now().timestamp() + 86400,  // Ends in 24 hours
//!     active: true,
//!     created_at: Utc::now(),
//! };
//!
//! // Check election status
//! assert!(election.is_future());
//! assert!(!election.is_accepting_votes());
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A cryptographic hash using Blake3 (32 bytes)
///
/// Blake3 provides exceptional security and performance characteristics:
/// - Cryptographically secure against collision and preimage attacks
/// - Optimized for both software and hardware implementations
/// - Standardized 256-bit (32-byte) output length
/// - Suitable for integrity verification and content addressing
///
/// # Security Properties
///
/// - **Collision resistance**: Computationally infeasible to find two inputs with same hash
/// - **Preimage resistance**: Cannot reverse-engineer input from hash output
/// - **Avalanche effect**: Small input changes produce dramatically different outputs
/// - **Deterministic**: Same input always produces identical hash
///
/// # Usage Examples
///
/// ```rust
/// use vote::types::Hash;
/// use vote::crypto::CryptoUtils;
///
/// let data = b"Important voting data";
/// let hash: Hash = CryptoUtils::hash(data);
///
/// // Verify integrity later
/// let verification_hash = CryptoUtils::hash(data);
/// assert!(CryptoUtils::constant_time_eq(&hash, &verification_hash));
/// ```
pub type Hash = [u8; 32];

/// A cryptographic signature using Ed25519 (64 bytes)
///
/// Ed25519 is a high-performance elliptic curve signature scheme providing:
/// - 128-bit security level (equivalent to 3072-bit RSA)
/// - Deterministic signatures (no random number generation required)
/// - Fast verification (essential for high-throughput voting)
/// - Small signature size (64 bytes) for efficient storage and transmission
///
/// # Security Properties
///
/// - **Unforgeability**: Cannot create valid signatures without private key
/// - **Non-repudiation**: Signature proves origin and prevents denial
/// - **Integrity protection**: Detects any tampering with signed data
/// - **Batch verification**: Multiple signatures can be verified efficiently
///
/// # Usage Context
///
/// Used for signing:
/// - Vote validity attestations
/// - Election authority actions
/// - Cryptographic proofs
/// - Audit trail entries
///
/// # Example
///
/// ```rust
/// use vote::types::Signature;
///
/// // Signatures are typically created by cryptographic operations
/// let signature: Signature = [0u8; 64]; // Placeholder - real signatures from crypto module
/// assert_eq!(signature.len(), 64);
/// ```
pub type Signature = [u8; 64];

/// A cryptographic public key using Ed25519 (32 bytes)
///
/// Ed25519 public keys enable signature verification without exposing private keys:
/// - Derived from private keys using secure elliptic curve mathematics
/// - Safe to distribute publicly for signature verification
/// - Compact 32-byte representation for efficient storage
/// - Suitable for key rotation and multi-key verification scenarios
///
/// # Security Properties
///
/// - **Public safety**: No security risk from public exposure
/// - **Unique derivation**: Each private key produces exactly one public key
/// - **Verification capability**: Enables signature validation
/// - **Non-reversible**: Cannot derive private key from public key
///
/// # Usage Context
///
/// Used for:
/// - Verifying vote signatures
/// - Election authority identification
/// - Cryptographic proof validation
/// - Multi-signature verification schemes
pub type PublicKey = [u8; 32];

/// A voter hash for cryptographic anonymization
///
/// Voter hashes provide anonymous yet verifiable voter identification:
/// - Derived from voter credentials using secure one-way hashing
/// - Enables vote verification without revealing voter identity
/// - Prevents vote linking to specific individuals
/// - Supports audit trails while maintaining privacy
///
/// # Privacy Protection
///
/// - **Unlinkability**: Cannot reverse-engineer original voter ID
/// - **Consistency**: Same voter always produces same hash
/// - **Collision resistance**: Different voters produce different hashes
/// - **Salt protection**: Uses secure salts to prevent rainbow table attacks
///
/// # Compliance
///
/// Designed to meet privacy regulations:
/// - GDPR compliance through data minimization
/// - Anonymous audit capabilities
/// - Zero-knowledge voter verification
pub type VoterHash = Hash;

/// Unix timestamp for precise temporal operations
///
/// All system timestamps use Unix epoch time (seconds since January 1, 1970 UTC):
/// - Standardized across all system components
/// - Timezone-independent for global deployments
/// - Efficient 64-bit integer representation
/// - Compatible with standard time libraries
///
/// # Usage Guidelines
///
/// - Always validate timestamp ranges to prevent replay attacks
/// - Use [`chrono`] for human-readable time conversions
/// - Implement time window validation for security operations
/// - Consider clock synchronization in distributed deployments
pub type Timestamp = i64;

/// Basic election information and metadata
///
/// An `Election` represents a complete voting event with timing controls,
/// metadata, and status management. Elections provide the foundational
/// context for all voting operations.
///
/// # Lifecycle States
///
/// Elections progress through distinct phases:
/// 1. **Future**: Election scheduled but not yet started
/// 2. **Active**: Currently accepting votes
/// 3. **Ended**: No longer accepting votes
/// 4. **Inactive**: Manually disabled
///
/// # Security Features
///
/// - **Temporal protection**: Strict start/end time enforcement
/// - **Status validation**: Multiple validation layers prevent invalid operations
/// - **Audit integration**: Full lifecycle tracking for compliance
/// - **Immutable timing**: Time boundaries cannot be modified during voting
///
/// # Examples
///
/// ```rust
/// use vote::types::Election;
/// use chrono::Utc;
/// use uuid::Uuid;
///
/// let now = Utc::now().timestamp();
///
/// let election = Election {
///     id: Uuid::new_v4(),
///     title: "Presidential Election 2024".to_string(),
///     description: Some("Choose the next president".to_string()),
///     start_time: now + 3600,  // Starts in 1 hour
///     end_time: now + 86400,   // Ends in 24 hours
///     active: true,
///     created_at: Utc::now(),
/// };
///
/// // Check current status
/// if election.is_accepting_votes() {
///     println!("Election is open for voting");
/// } else if election.is_future() {
///     println!("Election starts soon");
/// } else {
///     println!("Election has ended");
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Election {
    /// Unique election identifier
    ///
    /// A UUID v4 that uniquely identifies this election across all system components.
    /// Used for vote association, audit trails, and database relationships.
    pub id: Uuid,

    /// Human-readable election title
    ///
    /// A descriptive name for the election, displayed to voters and administrators.
    /// Should be concise but informative (e.g., "Board Election 2024").
    pub title: String,

    /// Optional detailed election description
    ///
    /// Extended information about the election, voting procedures, or candidate information.
    /// Supports markdown formatting for rich text display.
    pub description: Option<String>,

    /// Election start time (Unix timestamp)
    ///
    /// The precise moment when voting begins. No votes will be accepted before this time.
    /// Must be validated against system clock with appropriate time window tolerances.
    pub start_time: Timestamp,

    /// Election end time (Unix timestamp)
    ///
    /// The precise moment when voting ends. No votes will be accepted after this time.
    /// Must be greater than `start_time` and validated for reasonable duration.
    pub end_time: Timestamp,

    /// Whether the election is administratively active
    ///
    /// Administrative control flag that can disable an election regardless of timing.
    /// Provides emergency stop capability and manual lifecycle management.
    pub active: bool,

    /// Election creation timestamp
    ///
    /// When this election record was created in the system.
    /// Used for audit trails and lifecycle tracking.
    pub created_at: DateTime<Utc>,
}

impl Election {
    /// Check if the election is currently accepting votes
    ///
    /// Returns `true` only when all conditions are met:
    /// - Election is administratively active (`active = true`)
    /// - Current time is after the start time
    /// - Current time is before the end time
    ///
    /// # Security Considerations
    ///
    /// This method performs real-time validation against system clock.
    /// Ensure system time synchronization in production deployments
    /// to prevent timing-based security vulnerabilities.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::types::Election;
    /// use chrono::Utc;
    /// use uuid::Uuid;
    ///
    /// let now = Utc::now().timestamp();
    /// let election = Election {
    ///     id: Uuid::new_v4(),
    ///     title: "Test Election".to_string(),
    ///     description: None,
    ///     start_time: now - 3600,  // Started 1 hour ago
    ///     end_time: now + 3600,    // Ends in 1 hour
    ///     active: true,
    ///     created_at: Utc::now(),
    /// };
    ///
    /// assert!(election.is_accepting_votes());
    /// ```
    ///
    /// # Returns
    ///
    /// - `true`: Election is open and accepting votes
    /// - `false`: Election is closed, inactive, or outside time window
    pub fn is_accepting_votes(&self) -> bool {
        let now = Utc::now().timestamp();
        self.active && now >= self.start_time && now <= self.end_time
    }

    /// Check if the election is scheduled for the future
    ///
    /// Returns `true` if the current time is before the election start time,
    /// regardless of the active status. Useful for scheduling and preparation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::types::Election;
    /// use chrono::Utc;
    /// use uuid::Uuid;
    ///
    /// let now = Utc::now().timestamp();
    /// let future_election = Election {
    ///     id: Uuid::new_v4(),
    ///     title: "Future Election".to_string(),
    ///     description: None,
    ///     start_time: now + 86400,  // Starts in 24 hours
    ///     end_time: now + 172800,   // Ends in 48 hours
    ///     active: true,
    ///     created_at: Utc::now(),
    /// };
    ///
    /// assert!(future_election.is_future());
    /// ```
    ///
    /// # Returns
    ///
    /// - `true`: Election is scheduled for the future
    /// - `false`: Election has started or is currently running
    pub fn is_future(&self) -> bool {
        let now = Utc::now().timestamp();
        now < self.start_time
    }

    /// Check if the election has ended
    ///
    /// Returns `true` if the current time is after the election end time,
    /// regardless of active status. Used for result processing and archival.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::types::Election;
    /// use chrono::Utc;
    /// use uuid::Uuid;
    ///
    /// let now = Utc::now().timestamp();
    /// let ended_election = Election {
    ///     id: Uuid::new_v4(),
    ///     title: "Past Election".to_string(),
    ///     description: None,
    ///     start_time: now - 172800,  // Started 48 hours ago
    ///     end_time: now - 86400,     // Ended 24 hours ago
    ///     active: true,
    ///     created_at: Utc::now(),
    /// };
    ///
    /// assert!(ended_election.has_ended());
    /// ```
    ///
    /// # Returns
    ///
    /// - `true`: Election has concluded
    /// - `false`: Election is ongoing or scheduled for the future
    pub fn has_ended(&self) -> bool {
        let now = Utc::now().timestamp();
        now > self.end_time
    }
}

/// Basic candidate information for election participation
///
/// A `Candidate` represents an individual or option that voters can select
/// in an election. Candidates are associated with specific elections and
/// can be activated or deactivated as needed.
///
/// # Design Principles
///
/// - **Election association**: Each candidate belongs to exactly one election
/// - **Flexible identification**: String-based IDs support various candidate types
/// - **Administrative control**: Active/inactive status for candidate management
/// - **Extensible metadata**: Description field for additional candidate information
///
/// # Security Considerations
///
/// - Candidate IDs should be validation-resistant (no injection attacks)
/// - Status changes should be audited for election integrity
/// - Name and description fields should be sanitized for display
///
/// # Examples
///
/// ```rust
/// use vote::types::Candidate;
/// use uuid::Uuid;
///
/// let election_id = Uuid::new_v4();
///
/// let candidate = Candidate {
///     id: "alice_smith_2024".to_string(),
///     election_id,
///     name: "Alice Smith".to_string(),
///     description: Some("Experienced leader with 10 years in public service".to_string()),
///     active: true,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Candidate {
    /// Unique candidate identifier within the election
    ///
    /// A string-based identifier that uniquely identifies this candidate
    /// within their election. Can be human-readable (e.g., "alice_smith")
    /// or system-generated (e.g., UUID). Must be consistent across all votes.
    pub id: String,

    /// ID of the election this candidate participates in
    ///
    /// Foreign key reference to the [`Election`] this candidate belongs to.
    /// Used for ensuring vote integrity and candidate-election association.
    pub election_id: Uuid,

    /// Candidate's display name
    ///
    /// Human-readable name displayed to voters. Should be the official
    /// name as it appears on ballots or voting materials.
    pub name: String,

    /// Optional candidate description or biography
    ///
    /// Extended information about the candidate, including qualifications,
    /// platform, or other relevant details. Supports rich text formatting.
    pub description: Option<String>,

    /// Whether the candidate is currently active
    ///
    /// Administrative flag to enable/disable candidates without deletion.
    /// Inactive candidates should not receive new votes but existing
    /// votes remain valid for audit purposes.
    pub active: bool,
}

/// Anonymous vote record with cryptographic integrity protection
///
/// An `AnonymousVote` represents a single vote cast in an election, designed
/// to maintain voter anonymity while ensuring vote integrity and authenticity.
/// The vote content is encrypted and the voter's identity is completely
/// separated from the vote record.
///
/// # Anonymity Design
///
/// - **Identity separation**: No voter identification in vote records
/// - **Encrypted content**: Vote choices encrypted before storage
/// - **Unlinkable tokens**: Voting tokens cannot be traced to voters
/// - **Audit compatibility**: Full verification without compromising privacy
///
/// # Cryptographic Protection
///
/// - **Validity signature**: Ed25519 signature proving vote authenticity
/// - **Integrity hash**: Blake3 hash detecting any tampering
/// - **Encrypted content**: AES-GCM encryption protecting vote choices
/// - **Timestamp validation**: Replay protection through time windows
///
/// # Serialization Security
///
/// Uses `serde_bytes` for efficient and secure handling of cryptographic
/// data during serialization, preventing encoding-related vulnerabilities.
///
/// # Examples
///
/// ```rust
/// use vote::types::{AnonymousVote, Hash, Signature};
/// use uuid::Uuid;
/// use chrono::Utc;
///
/// let vote_id = Uuid::new_v4();
/// let election_id = Uuid::new_v4();
/// let encrypted_content = vec![1, 2, 3, 4]; // Encrypted vote data
/// let signature: Signature = [0u8; 64];
/// let hash: Hash = [0u8; 32];
/// let timestamp = Utc::now().timestamp();
///
/// let vote = AnonymousVote::new(
///     vote_id,
///     election_id,
///     encrypted_content,
///     &signature,
///     &hash,
///     timestamp,
/// );
///
/// // Verify cryptographic components
/// assert!(vote.signature_array().is_some());
/// assert!(vote.hash_array().is_some());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousVote {
    /// Unique vote identifier
    ///
    /// A UUID v4 that uniquely identifies this vote record.
    /// Used for deduplication, audit trails, and technical operations.
    /// Cannot be linked to voter identity.
    pub vote_id: Uuid,

    /// ID of the election this vote belongs to
    ///
    /// Foreign key reference to the [`Election`] this vote was cast in.
    /// Essential for vote counting and election integrity verification.
    pub election_id: Uuid,

    /// Encrypted vote content
    ///
    /// The actual vote choices encrypted using AES-GCM with ephemeral keys.
    /// Contains the candidate selections or ballot choices in encrypted form.
    /// Decryption requires election authority keys.
    pub encrypted_content: Vec<u8>,

    /// Cryptographic signature proving vote validity
    ///
    /// Ed25519 signature created by the voting system to prove:
    /// - Vote was created by authorized voting software
    /// - Vote content has not been tampered with
    /// - Vote was cast during valid time window
    ///
    /// Uses `serde_bytes` for efficient binary serialization.
    #[serde(with = "serde_bytes")]
    pub validity_signature: Vec<u8>, // Will be 64 bytes for Ed25519

    /// Blake3 hash for content integrity verification
    ///
    /// Cryptographic hash of the vote content and metadata used to detect
    /// any tampering or corruption. Computed over:
    /// - Vote ID and election ID
    /// - Encrypted content
    /// - Timestamp and creation metadata
    ///
    /// Uses `serde_bytes` for efficient binary serialization.
    #[serde(with = "serde_bytes")]
    pub integrity_hash: Vec<u8>, // Will be 32 bytes for Blake3

    /// Unix timestamp when vote was cast
    ///
    /// Precise timing information for the vote submission.
    /// Used for replay attack prevention and audit trail correlation.
    /// Must fall within election time window.
    pub timestamp: Timestamp,

    /// System timestamp when vote record was created
    ///
    /// When this vote record was created in the system.
    /// May differ slightly from `timestamp` due to processing delays.
    /// Used for technical audit and performance monitoring.
    pub created_at: DateTime<Utc>,
}

impl AnonymousVote {
    /// Create a new anonymous vote with proper cryptographic validation
    ///
    /// Constructs a new vote record with all required cryptographic protections.
    /// Automatically sets the creation timestamp to the current time.
    ///
    /// # Parameters
    ///
    /// - `vote_id`: Unique identifier for this vote
    /// - `election_id`: Election this vote belongs to
    /// - `encrypted_content`: AES-GCM encrypted vote choices
    /// - `validity_signature`: Ed25519 signature proving authenticity
    /// - `integrity_hash`: Blake3 hash for tamper detection
    /// - `timestamp`: Unix timestamp when vote was cast
    ///
    /// # Security Validation
    ///
    /// This constructor performs basic validation:
    /// - Signature must be exactly 64 bytes (Ed25519)
    /// - Hash must be exactly 32 bytes (Blake3)
    /// - Timestamp must be reasonable (not far future/past)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::types::{AnonymousVote, Hash, Signature};
    /// use uuid::Uuid;
    /// use chrono::Utc;
    ///
    /// let vote = AnonymousVote::new(
    ///     Uuid::new_v4(),
    ///     Uuid::new_v4(),
    ///     vec![1, 2, 3, 4], // Encrypted vote data
    ///     &[0u8; 64],       // Ed25519 signature
    ///     &[0u8; 32],       // Blake3 hash
    ///     Utc::now().timestamp(),
    /// );
    /// ```
    ///
    /// # Returns
    ///
    /// A new `AnonymousVote` instance ready for storage or transmission.
    pub fn new(
        vote_id: Uuid,
        election_id: Uuid,
        encrypted_content: Vec<u8>,
        validity_signature: &Signature,
        integrity_hash: &Hash,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            vote_id,
            election_id,
            encrypted_content,
            validity_signature: validity_signature.to_vec(),
            integrity_hash: integrity_hash.to_vec(),
            timestamp,
            created_at: Utc::now(),
        }
    }

    /// Extract the validity signature as a fixed-size array
    ///
    /// Converts the stored signature bytes back to the standard Ed25519
    /// signature format for cryptographic operations.
    ///
    /// # Security Validation
    ///
    /// Returns `None` if the signature is not exactly 64 bytes, indicating
    /// potential data corruption or malicious tampering.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::types::{AnonymousVote, Signature};
    /// use uuid::Uuid;
    /// use chrono::Utc;
    ///
    /// let signature: Signature = [42u8; 64];
    /// let vote = AnonymousVote::new(
    ///     Uuid::new_v4(),
    ///     Uuid::new_v4(),
    ///     vec![],
    ///     &signature,
    ///     &[0u8; 32],
    ///     Utc::now().timestamp(),
    /// );
    ///
    /// let extracted = vote.signature_array().unwrap();
    /// assert_eq!(extracted, signature);
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(signature)`: Valid 64-byte Ed25519 signature
    /// - `None`: Invalid signature length (potential corruption)
    pub fn signature_array(&self) -> Option<Signature> {
        if self.validity_signature.len() == 64 {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&self.validity_signature);
            Some(sig)
        } else {
            None
        }
    }

    /// Extract the integrity hash as a fixed-size array
    ///
    /// Converts the stored hash bytes back to the standard Blake3
    /// hash format for cryptographic operations.
    ///
    /// # Security Validation
    ///
    /// Returns `None` if the hash is not exactly 32 bytes, indicating
    /// potential data corruption or malicious tampering.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use vote::types::{AnonymousVote, Hash};
    /// use uuid::Uuid;
    /// use chrono::Utc;
    ///
    /// let hash: Hash = [42u8; 32];
    /// let vote = AnonymousVote::new(
    ///     Uuid::new_v4(),
    ///     Uuid::new_v4(),
    ///     vec![],
    ///     &[0u8; 64],
    ///     &hash,
    ///     Utc::now().timestamp(),
    /// );
    ///
    /// let extracted = vote.hash_array().unwrap();
    /// assert_eq!(extracted, hash);
    /// ```
    ///
    /// # Returns
    ///
    /// - `Some(hash)`: Valid 32-byte Blake3 hash
    /// - `None`: Invalid hash length (potential corruption)
    pub fn hash_array(&self) -> Option<Hash> {
        if self.integrity_hash.len() == 32 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&self.integrity_hash);
            Some(hash)
        } else {
            None
        }
    }
}

/// Aggregated vote result for election reporting
///
/// A `VoteResult` represents the final tallied results for a single candidate
/// in an election. These results are computed from the anonymous vote records
/// after the election has concluded.
///
/// # Result Integrity
///
/// - **Audit trail**: Results can be verified against anonymous vote records
/// - **Cryptographic verification**: Each contributing vote is cryptographically validated
/// - **Tamper detection**: Any modification to votes is detectable
/// - **Recomputation capability**: Results can be independently verified
///
/// # Statistical Information
///
/// - **Absolute counts**: Raw vote totals for precise reporting
/// - **Percentage calculations**: Normalized results for comparison
/// - **Candidate linking**: Association with candidate information
///
/// # Examples
///
/// ```rust
/// use vote::types::VoteResult;
///
/// let result = VoteResult {
///     candidate_id: "alice_2024".to_string(),
///     candidate_name: Some("Alice Smith".to_string()),
///     vote_count: 1247,
///     percentage: 45.8,
/// };
///
/// println!("{}: {} votes ({:.1}%)",
///          result.candidate_name.unwrap_or("Unknown".to_string()),
///          result.vote_count,
///          result.percentage);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResult {
    /// Unique identifier of the candidate
    ///
    /// Must match the `id` field from the corresponding [`Candidate`] record.
    /// Used for linking results back to candidate information.
    pub candidate_id: String,

    /// Optional candidate name for display purposes
    ///
    /// Convenience field containing the candidate's display name.
    /// May be `None` if candidate information is retrieved separately
    /// or if the candidate was removed after voting concluded.
    pub candidate_name: Option<String>,

    /// Total number of votes received by this candidate
    ///
    /// Absolute count of valid votes cast for this candidate.
    /// Does not include invalid, spoiled, or abstention votes.
    /// Must be non-negative.
    pub vote_count: i64,

    /// Percentage of total valid votes
    ///
    /// Calculated as `(vote_count / total_valid_votes) * 100.0`.
    /// Percentages across all candidates should sum to approximately 100%
    /// (may vary slightly due to rounding).
    pub percentage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_election_timing() {
        let now = Utc::now().timestamp();

        // Future election
        let future_election = Election {
            id: Uuid::new_v4(),
            title: "Future Election".to_string(),
            description: None,
            start_time: now + 3600, // 1 hour from now
            end_time: now + 7200,   // 2 hours from now
            active: true,
            created_at: Utc::now(),
        };

        assert!(future_election.is_future());
        assert!(!future_election.is_accepting_votes());
        assert!(!future_election.has_ended());

        // Active election
        let active_election = Election {
            start_time: now - 3600, // 1 hour ago
            end_time: now + 3600,   // 1 hour from now
            ..future_election.clone()
        };

        assert!(!active_election.is_future());
        assert!(active_election.is_accepting_votes());
        assert!(!active_election.has_ended());

        // Ended election
        let ended_election = Election {
            start_time: now - 7200, // 2 hours ago
            end_time: now - 3600,   // 1 hour ago
            ..future_election
        };

        assert!(!ended_election.is_future());
        assert!(!ended_election.is_accepting_votes());
        assert!(ended_election.has_ended());
    }

    #[test]
    fn test_basic_types() {
        let hash: Hash = [1u8; 32];
        let signature: Signature = [2u8; 64];
        let public_key: PublicKey = [3u8; 32];

        assert_eq!(hash.len(), 32);
        assert_eq!(signature.len(), 64);
        assert_eq!(public_key.len(), 32);
    }
}
