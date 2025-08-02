//! Core types for the voting system

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A cryptographic hash (32 bytes)
pub type Hash = [u8; 32];

/// A cryptographic signature (64 bytes for Ed25519)
pub type Signature = [u8; 64];

/// A cryptographic public key (32 bytes for Ed25519)
pub type PublicKey = [u8; 32];

/// A voter hash for anonymization
pub type VoterHash = Hash;

/// Unix timestamp
pub type Timestamp = i64;

/// Basic election information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Election {
    pub id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub start_time: Timestamp,
    pub end_time: Timestamp,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

impl Election {
    /// Check if the election is currently active and accepting votes
    pub fn is_accepting_votes(&self) -> bool {
        let now = Utc::now().timestamp();
        self.active && now >= self.start_time && now <= self.end_time
    }

    /// Check if the election is in the future
    pub fn is_future(&self) -> bool {
        let now = Utc::now().timestamp();
        now < self.start_time
    }

    /// Check if the election has ended
    pub fn has_ended(&self) -> bool {
        let now = Utc::now().timestamp();
        now > self.end_time
    }
}

/// Basic candidate information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Candidate {
    pub id: String,
    pub election_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub active: bool,
}

/// Anonymous vote record - using Vec<u8> for serialization compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousVote {
    pub vote_id: Uuid,
    pub election_id: Uuid,
    pub encrypted_content: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub validity_signature: Vec<u8>, // Will be 64 bytes
    #[serde(with = "serde_bytes")]
    pub integrity_hash: Vec<u8>, // Will be 32 bytes
    pub timestamp: Timestamp,
    pub created_at: DateTime<Utc>,
}

impl AnonymousVote {
    /// Create a new anonymous vote with proper byte array handling
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

    /// Get the signature as a fixed array
    pub fn signature_array(&self) -> Option<Signature> {
        if self.validity_signature.len() == 64 {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&self.validity_signature);
            Some(sig)
        } else {
            None
        }
    }

    /// Get the hash as a fixed array
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

/// Simple vote result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResult {
    pub candidate_id: String,
    pub candidate_name: Option<String>,
    pub vote_count: i64,
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
