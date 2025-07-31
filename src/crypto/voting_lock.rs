//! Voting lock system to prevent double voting and race conditions
//!
//! This module implements temporal locking to ensure that:
//! 1. Only one voting process can be active per voter at a time
//! 2. Race conditions between digital and analog voting are prevented
//! 3. Locks automatically expire to prevent deadlocks

use crate::{voting_error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Duration of voting lock in seconds (10 minutes)
const VOTING_LOCK_DURATION: u64 = 600;

/// Type of voting that created the lock
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VotingMethod {
    Digital,
    Analog,
    Processing, // For internal operations
}

/// Represents an active voting lock
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoterLock {
    pub voter_hash: String,
    pub election_id: Uuid,
    pub method: VotingMethod,
    pub locked_at: u64,
    pub expires_at: u64,
    pub lock_id: Uuid,
}

impl VoterLock {
    /// Create a new voting lock
    pub fn new(
        voter_hash: String,
        election_id: Uuid,
        method: VotingMethod,
        duration_seconds: u64,
    ) -> Result<Self> {
        let locked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| voting_error!("System time error"))?
            .as_secs();

        let expires_at = locked_at + duration_seconds;

        Ok(Self {
            voter_hash,
            election_id,
            method,
            locked_at,
            expires_at,
            lock_id: Uuid::new_v4(),
        })
    }

    /// Check if this lock has expired
    pub fn is_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        current_time > self.expires_at
    }

    /// Get remaining time in seconds
    pub fn time_remaining(&self) -> u64 {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if current_time >= self.expires_at {
            0
        } else {
            self.expires_at - current_time
        }
    }

    /// Generate lock key for storage
    pub fn lock_key(&self) -> String {
        format!("voting_lock:{}:{}", self.voter_hash, self.election_id)
    }
}

/// Result of lock acquisition attempt
#[derive(Debug, PartialEq)]
pub enum LockResult {
    Acquired(VoterLock),
    AlreadyLocked {
        existing_lock: VoterLock,
        conflict_method: VotingMethod,
    },
    ExpiredLockRemoved(VoterLock), // Lock was expired and removed, new lock acquired
}

/// In-memory voting lock service
///
/// In production, this would use Redis or similar distributed store
/// for multi-server deployment. For now, we use in-memory storage
/// which is perfect for testing and single-server deployments.
pub struct VotingLockService {
    locks: RwLock<HashMap<String, VoterLock>>,
}

impl VotingLockService {
    /// Create new voting lock service
    pub fn new() -> Self {
        Self {
            locks: RwLock::new(HashMap::new()),
        }
    }

    /// Attempt to acquire a voting lock for a voter
    ///
    /// This is the core anti-double-voting mechanism:
    /// - If no lock exists: creates new lock and returns Acquired
    /// - If expired lock exists: removes it, creates new lock
    /// - If active lock exists: returns AlreadyLocked with details
    pub fn acquire_lock(
        &self,
        voter_hash: &str,
        election_id: &Uuid,
        method: VotingMethod,
    ) -> Result<LockResult> {
        let lock_key = format!("voting_lock:{}:{}", voter_hash, election_id);

        // First, try to read existing lock
        {
            let locks = self.locks.read()
                .map_err(|_| voting_error!("Lock service read error"))?;

            if let Some(existing_lock) = locks.get(&lock_key) {
                if !existing_lock.is_expired() {
                    // Active lock exists - voting conflict!
                    return Ok(LockResult::AlreadyLocked {
                        existing_lock: existing_lock.clone(),
                        conflict_method: existing_lock.method.clone(),
                    });
                }
                // Lock exists but expired - we'll remove it below
            }
        }

        // Acquire write lock to modify
        let mut locks = self.locks.write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        // Double-check pattern (expired lock might have been removed by another thread)
        let mut removed_expired = None;
        if let Some(existing_lock) = locks.get(&lock_key) {
            if existing_lock.is_expired() {
                removed_expired = Some(existing_lock.clone());
                locks.remove(&lock_key);
            } else {
                // Another thread beat us to it
                return Ok(LockResult::AlreadyLocked {
                    existing_lock: existing_lock.clone(),
                    conflict_method: existing_lock.method.clone(),
                });
            }
        }

        // Create new lock
        let new_lock = VoterLock::new(
            voter_hash.to_string(),
            *election_id,
            method,
            VOTING_LOCK_DURATION,
        )?;

        locks.insert(lock_key, new_lock.clone());

        if let Some(expired) = removed_expired {
            Ok(LockResult::ExpiredLockRemoved(new_lock))
        } else {
            Ok(LockResult::Acquired(new_lock))
        }
    }

    /// Release a voting lock
    ///
    /// This should be called when voting is completed or cancelled
    pub fn release_lock(&self, lock: &VoterLock) -> Result<bool> {
        let mut locks = self.locks.write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        let lock_key = lock.lock_key();

        if let Some(existing_lock) = locks.get(&lock_key) {
            // Verify this is the same lock (prevent releasing wrong lock)
            if existing_lock.lock_id == lock.lock_id {
                locks.remove(&lock_key);
                Ok(true)
            } else {
                Ok(false) // Different lock ID - this lock was already replaced
            }
        } else {
            Ok(false) // Lock doesn't exist (already expired/removed)
        }
    }

    /// Check if a voter currently has an active lock
    pub fn is_locked(&self, voter_hash: &str, election_id: &Uuid) -> Result<Option<VoterLock>> {
        let lock_key = format!("voting_lock:{}:{}", voter_hash, election_id);

        let locks = self.locks.read()
            .map_err(|_| voting_error!("Lock service read error"))?;

        if let Some(lock) = locks.get(&lock_key) {
            if !lock.is_expired() {
                Ok(Some(lock.clone()))
            } else {
                Ok(None) // Expired lock is considered as no lock
            }
        } else {
            Ok(None)
        }
    }

    /// Clean up expired locks (should be called periodically)
    pub fn cleanup_expired_locks(&self) -> Result<u32> {
        let mut locks = self.locks.write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        let initial_count = locks.len();

        // Remove all expired locks
        locks.retain(|_, lock| !lock.is_expired());

        let cleaned_count = initial_count - locks.len();
        Ok(cleaned_count as u32)
    }

    /// Get all active locks (for debugging/monitoring)
    pub fn get_active_locks(&self) -> Result<Vec<VoterLock>> {
        let locks = self.locks.read()
            .map_err(|_| voting_error!("Lock service read error"))?;

        let active_locks: Vec<VoterLock> = locks
            .values()
            .filter(|lock| !lock.is_expired())
            .cloned()
            .collect();

        Ok(active_locks)
    }

    /// Get statistics about the lock service
    pub fn get_stats(&self) -> Result<LockServiceStats> {
        let locks = self.locks.read()
            .map_err(|_| voting_error!("Lock service read error"))?;

        let total_locks = locks.len();
        let active_locks = locks.values().filter(|lock| !lock.is_expired()).count();
        let expired_locks = total_locks - active_locks;

        let digital_locks = locks.values()
            .filter(|lock| !lock.is_expired() && lock.method == VotingMethod::Digital)
            .count();

        let analog_locks = locks.values()
            .filter(|lock| !lock.is_expired() && lock.method == VotingMethod::Analog)
            .count();

        Ok(LockServiceStats {
            total_locks,
            active_locks,
            expired_locks,
            digital_locks,
            analog_locks,
        })
    }
}

impl Default for VotingLockService {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the lock service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockServiceStats {
    pub total_locks: usize,
    pub active_locks: usize,
    pub expired_locks: usize,
    pub digital_locks: usize,
    pub analog_locks: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voter_lock_creation() {
        let voter_hash = "test_voter_hash".to_string();
        let election_id = Uuid::new_v4();

        let lock = VoterLock::new(
            voter_hash.clone(),
            election_id,
            VotingMethod::Digital,
            600,
        ).unwrap();

        assert_eq!(lock.voter_hash, voter_hash);
        assert_eq!(lock.election_id, election_id);
        assert_eq!(lock.method, VotingMethod::Digital);
        assert!(!lock.is_expired());
        assert!(lock.time_remaining() > 590); // Should be close to 600
    }

    #[test]
    fn test_lock_expiration() {
        // Create a lock that's already expired by setting duration to 0
        let mut lock = VoterLock::new(
            "test_voter".to_string(),
            Uuid::new_v4(),
            VotingMethod::Digital,
            1, // 1 second duration
        ).unwrap();

        assert!(!lock.is_expired());

        // Manually set expiration to the past to ensure it's expired
        lock.expires_at = lock.locked_at - 1;

        assert!(lock.is_expired());
        assert_eq!(lock.time_remaining(), 0);
    }

    #[test]
    fn test_voting_lock_service_basic() {
        let service = VotingLockService::new();
        let voter_hash = "test_voter_123";
        let election_id = Uuid::new_v4();

        // First lock should succeed
        let result1 = service.acquire_lock(voter_hash, &election_id, VotingMethod::Digital).unwrap();
        assert!(matches!(result1, LockResult::Acquired(_)));

        // Second lock should fail
        let result2 = service.acquire_lock(voter_hash, &election_id, VotingMethod::Analog).unwrap();
        assert!(matches!(result2, LockResult::AlreadyLocked { .. }));

        if let LockResult::AlreadyLocked { conflict_method, .. } = result2 {
            assert_eq!(conflict_method, VotingMethod::Digital);
        }
    }

    #[test]
    fn test_lock_release() {
        let service = VotingLockService::new();
        let voter_hash = "test_voter_456";
        let election_id = Uuid::new_v4();

        // Acquire lock
        let result = service.acquire_lock(voter_hash, &election_id, VotingMethod::Digital).unwrap();
        let lock = match result {
            LockResult::Acquired(lock) => lock,
            _ => panic!("Expected lock to be acquired"),
        };

        // Verify lock exists
        assert!(service.is_locked(voter_hash, &election_id).unwrap().is_some());

        // Release lock
        assert!(service.release_lock(&lock).unwrap());

        // Verify lock is gone
        assert!(service.is_locked(voter_hash, &election_id).unwrap().is_none());

        // Should be able to acquire again
        let result2 = service.acquire_lock(voter_hash, &election_id, VotingMethod::Analog).unwrap();
        assert!(matches!(result2, LockResult::Acquired(_)));
    }

    #[test]
    fn test_expired_lock_cleanup() {
        let service = VotingLockService::new();
        let voter_hash = "test_voter_789";
        let election_id = Uuid::new_v4();

        // Create lock and manually expire it
        let mut lock = VoterLock::new(
            voter_hash.to_string(),
            election_id,
            VotingMethod::Digital,
            600, // Normal duration
        ).unwrap();

        // Manually expire the lock by setting expiration to the past
        lock.expires_at = lock.locked_at - 1;

        // Manually insert expired lock
        {
            let mut locks = service.locks.write().unwrap();
            locks.insert(lock.lock_key(), lock.clone());
        }

        // Should be able to acquire new lock (expired lock gets removed)
        let result = service.acquire_lock(voter_hash, &election_id, VotingMethod::Analog).unwrap();
        assert!(matches!(result, LockResult::ExpiredLockRemoved(_)));
    }

    #[test]
    fn test_cleanup_expired_locks() {
        let service = VotingLockService::new();

        // Create several locks and manually expire them
        let mut expired_locks = Vec::new();
        for i in 0..5 {
            let voter_hash = format!("voter_{}", i);
            let election_id = Uuid::new_v4();

            let mut lock = VoterLock::new(
                voter_hash.clone(),
                election_id,
                VotingMethod::Digital,
                600,
            ).unwrap();

            // Manually expire the lock
            lock.expires_at = lock.locked_at - 1;
            expired_locks.push((lock.lock_key(), lock));
        }

        // Insert all expired locks manually
        {
            let mut locks = service.locks.write().unwrap();
            for (key, lock) in expired_locks {
                locks.insert(key, lock);
            }
        }

        // All locks should be expired
        let stats_before = service.get_stats().unwrap();
        assert_eq!(stats_before.total_locks, 5);
        assert_eq!(stats_before.active_locks, 0); // All should be expired

        // Cleanup should remove all expired locks
        let cleaned = service.cleanup_expired_locks().unwrap();
        assert_eq!(cleaned, 5);

        let stats_after = service.get_stats().unwrap();
        assert_eq!(stats_after.active_locks, 0);
        assert_eq!(stats_after.total_locks, 0);
    }

    #[test]
    fn test_different_elections_dont_conflict() {
        let service = VotingLockService::new();
        let voter_hash = "same_voter";
        let election1 = Uuid::new_v4();
        let election2 = Uuid::new_v4();

        // Same voter can have locks for different elections
        let result1 = service.acquire_lock(voter_hash, &election1, VotingMethod::Digital).unwrap();
        assert!(matches!(result1, LockResult::Acquired(_)));

        let result2 = service.acquire_lock(voter_hash, &election2, VotingMethod::Digital).unwrap();
        assert!(matches!(result2, LockResult::Acquired(_)));

        // But not for the same election
        let result3 = service.acquire_lock(voter_hash, &election1, VotingMethod::Analog).unwrap();
        assert!(matches!(result3, LockResult::AlreadyLocked { .. }));
    }
}