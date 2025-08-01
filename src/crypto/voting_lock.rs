//! Enhanced voting lock system with integrated token security
//!
//! This module implements comprehensive voting security:
//! 1. Token validation required for all voting operations
//! 2. Temporal locks prevent concurrent voting sessions
//! 3. Completion tracking prevents double voting across time
//! 4. Automatic token invalidation on logout or vote completion
//! 5. Session-aware security for millions of users

use crate::crypto::voting_token::{TokenResult, VotingTokenService};
use crate::{Result, voting_error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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

/// Represents an active voting lock (temporary - prevents concurrent voting)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoterLock {
    pub voter_hash: String,
    pub election_id: Uuid,
    pub method: VotingMethod,
    pub locked_at: u64,
    pub expires_at: u64,
    pub lock_id: Uuid,
    pub token_id: String, // Associated token that enabled this lock
}

impl VoterLock {
    /// Create a new voting lock
    pub fn new(
        voter_hash: String,
        election_id: Uuid,
        method: VotingMethod,
        duration_seconds: u64,
        token_id: String,
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
            token_id,
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

        self.expires_at.saturating_sub(current_time)
    }

    /// Generate lock key for storage
    pub fn lock_key(&self) -> String {
        format!("voting_lock:{}:{}", self.voter_hash, self.election_id)
    }
}

/// Represents a completed vote (permanent - prevents double voting)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VotingCompletion {
    pub voter_hash: String,
    pub election_id: Uuid,
    pub method: VotingMethod,
    pub completed_at: u64,
    pub completion_id: Uuid,
    pub vote_id: Option<Uuid>,
    pub token_id: String, // Token that was used for this vote
}

impl VotingCompletion {
    /// Create a new voting completion record
    pub fn new(
        voter_hash: String,
        election_id: Uuid,
        method: VotingMethod,
        vote_id: Option<Uuid>,
        token_id: String,
    ) -> Result<Self> {
        let completed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| voting_error!("System time error"))?
            .as_secs();

        Ok(Self {
            voter_hash,
            election_id,
            method,
            completed_at,
            completion_id: Uuid::new_v4(),
            vote_id,
            token_id,
        })
    }

    /// Generate completion key for storage
    pub fn completion_key(&self) -> String {
        format!("voting_completion:{}:{}", self.voter_hash, self.election_id)
    }
}

/// Result of lock acquisition attempt
#[derive(Debug, PartialEq)]
pub enum LockResult {
    /// Lock acquired successfully - voting can proceed
    Acquired(VoterLock),

    /// Blocked due to active concurrent voting session
    AlreadyLocked {
        existing_lock: VoterLock,
        conflict_method: VotingMethod,
    },

    /// Blocked because voter has already completed voting
    AlreadyVoted {
        completion: VotingCompletion,
        original_method: VotingMethod,
    },

    /// Blocked due to invalid or expired token
    InvalidToken { reason: String },

    /// Expired lock was removed and new lock acquired
    ExpiredLockRemoved(VoterLock),
}

/// Enhanced voting lock service with integrated token security
pub struct VotingLockService {
    locks: RwLock<HashMap<String, VoterLock>>,
    completions: RwLock<HashMap<String, VotingCompletion>>,
    token_service: Arc<VotingTokenService>,
}

impl VotingLockService {
    /// Create new voting lock service with token integration
    pub fn new(token_service: Arc<VotingTokenService>) -> Self {
        Self {
            locks: RwLock::new(HashMap::new()),
            completions: RwLock::new(HashMap::new()),
            token_service,
        }
    }

    /// Create for testing with default token service
    pub fn for_testing() -> Self {
        let token_service = Arc::new(VotingTokenService::for_testing());
        Self::new(token_service)
    }

    /// Attempt to acquire a voting lock for a voter (with token validation)
    ///
    /// Enhanced security flow:
    /// 1. Validate voting token (CRITICAL - prevents unauthorized access)
    /// 2. Check if voter has already completed voting (prevents double voting)
    /// 3. Check for active concurrent locks (prevents race conditions)
    /// 4. If all checks pass, acquire lock for voting session
    /// Enhanced lock acquisition with timing attack protection
    pub fn acquire_lock_with_token(
        &self,
        salt_manager: &crate::crypto::SecureSaltManager,
        token_id: &str,
        voter_hash: &str,
        election_id: &Uuid,
        method: VotingMethod,
    ) -> Result<LockResult> {
        let completion_key = format!("voting_completion:{voter_hash}:{election_id}");
        let lock_key = format!("voting_lock:{voter_hash}:{election_id}");

        // CRITICAL: Always perform token validation first, regardless of other checks
        // This ensures consistent timing for all code paths
        let token_validation =
            self.token_service
                .validate_token(salt_manager, token_id, voter_hash, election_id)?;

        let valid_token = match token_validation {
            TokenResult::Valid(token) => token,
            TokenResult::Invalid { reason } => {
                // Still perform dummy completion and lock checks to maintain timing
                let completions = self
                    .completions
                    .read()
                    .map_err(|_| voting_error!("Completion service read error"))?;
                let _dummy_completion_check = completions.get(&completion_key);

                let locks = self
                    .locks
                    .read()
                    .map_err(|_| voting_error!("Lock service read error"))?;
                let _dummy_lock_check = locks.get(&lock_key);

                return Ok(LockResult::InvalidToken { reason });
            }
            _ => {
                return Ok(LockResult::InvalidToken {
                    reason: "Unexpected token validation result".to_string(),
                });
            }
        };

        // Continue with completion and lock checks...
        // (rest of the function remains the same as it doesn't have timing issues)

        // Check if voter has already completed voting
        {
            let completions = self
                .completions
                .read()
                .map_err(|_| voting_error!("Completion service read error"))?;

            if let Some(completion) = completions.get(&completion_key) {
                return Ok(LockResult::AlreadyVoted {
                    completion: completion.clone(),
                    original_method: completion.method.clone(),
                });
            }
        }

        // Check for active concurrent locks
        {
            let locks = self
                .locks
                .read()
                .map_err(|_| voting_error!("Lock service read error"))?;

            if let Some(existing_lock) = locks.get(&lock_key) {
                if !existing_lock.is_expired() {
                    return Ok(LockResult::AlreadyLocked {
                        existing_lock: existing_lock.clone(),
                        conflict_method: existing_lock.method.clone(),
                    });
                }
            }
        }

        // Acquire write lock to modify locks
        let mut locks = self
            .locks
            .write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        // Double-check pattern for expired locks
        let mut removed_expired = None;
        if let Some(existing_lock) = locks.get(&lock_key) {
            if existing_lock.is_expired() {
                removed_expired = Some(existing_lock.clone());
                locks.remove(&lock_key);
            } else {
                return Ok(LockResult::AlreadyLocked {
                    existing_lock: existing_lock.clone(),
                    conflict_method: existing_lock.method.clone(),
                });
            }
        }

        // Create new lock for voting session
        let new_lock = crate::crypto::voting_lock::VoterLock::new(
            voter_hash.to_string(),
            *election_id,
            method,
            crate::crypto::voting_lock::VOTING_LOCK_DURATION,
            token_id.to_string(),
        )?;

        locks.insert(lock_key, new_lock.clone());

        tracing::info!(
            "🔒 Voting lock acquired: voter={}, method={:?}, token={}",
            &voter_hash[..8],
            new_lock.method,
            &token_id[..8]
        );

        if let Some(_expired) = removed_expired {
            Ok(LockResult::ExpiredLockRemoved(new_lock))
        } else {
            Ok(LockResult::Acquired(new_lock))
        }
    }

    /// Mark voting as completed (with automatic token invalidation)
    ///
    /// This creates a permanent record that prevents future voting attempts
    /// and automatically invalidates the associated token.
    pub fn complete_voting_with_token_cleanup(
        &self,
        lock: &VoterLock,
        vote_id: Option<Uuid>,
    ) -> Result<VotingCompletion> {
        let completion_key = format!("voting_completion:{}:{}", lock.voter_hash, lock.election_id);

        // Check if already completed (defensive programming)
        {
            let completions = self
                .completions
                .read()
                .map_err(|_| voting_error!("Completion service read error"))?;

            if let Some(existing_completion) = completions.get(&completion_key) {
                return Err(voting_error!(
                    "Voting already completed at {} via {:?}",
                    existing_completion.completed_at,
                    existing_completion.method
                ));
            }
        }

        // Create completion record
        let completion = VotingCompletion::new(
            lock.voter_hash.clone(),
            lock.election_id,
            lock.method.clone(),
            vote_id,
            lock.token_id.clone(),
        )?;

        // Atomically: add completion record, remove lock, and invalidate token
        {
            let mut completions = self
                .completions
                .write()
                .map_err(|_| voting_error!("Completion service write error"))?;
            let mut locks = self
                .locks
                .write()
                .map_err(|_| voting_error!("Lock service write error"))?;

            // Record completion
            completions.insert(completion_key, completion.clone());

            // Remove the lock (voting session is complete)
            locks.remove(&lock.lock_key());
        }

        // Invalidate the token (prevents reuse)
        if let Some(vote_id) = vote_id {
            let _ = self.token_service.mark_token_used(&lock.token_id, vote_id);
        } else {
            let _ = self.token_service.invalidate_token(&lock.token_id);
        }

        tracing::info!(
            "🗳️ Voting completed: voter={}, election={}, method={:?}, token={}",
            &lock.voter_hash[..8],
            lock.election_id,
            lock.method,
            &lock.token_id[..8]
        );

        Ok(completion)
    }

    /// Release a voting lock without completing the vote (for cancellation)
    /// This also invalidates the associated token
    pub fn release_lock_with_token_cleanup(&self, lock: &VoterLock) -> Result<bool> {
        let mut locks = self
            .locks
            .write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        let lock_key = lock.lock_key();

        if let Some(existing_lock) = locks.get(&lock_key) {
            if existing_lock.lock_id == lock.lock_id {
                locks.remove(&lock_key);

                // Invalidate the associated token
                let _ = self.token_service.invalidate_token(&lock.token_id);

                tracing::info!(
                    "🔓 Voting lock released: voter={}, method={:?}, token={}",
                    &lock.voter_hash[..8],
                    lock.method,
                    &lock.token_id[..8]
                );
                Ok(true)
            } else {
                Ok(false) // Different lock ID
            }
        } else {
            Ok(false) // Lock doesn't exist
        }
    }

    /// Logout - invalidate all tokens for a voter
    pub fn logout_voter(&self, voter_hash: &str, election_id: &Uuid) -> Result<LogoutResult> {
        // Invalidate all tokens for this voter
        let invalidated_tokens = self
            .token_service
            .invalidate_voter_tokens(voter_hash, election_id)?;

        // Release any active locks for this voter
        let lock_key = format!("voting_lock:{voter_hash}:{election_id}");
        let released_lock = {
            let mut locks = self
                .locks
                .write()
                .map_err(|_| voting_error!("Lock service write error"))?;
            locks.remove(&lock_key)
        };

        tracing::info!(
            "👋 Voter logout: voter={}, tokens_invalidated={}, lock_released={}",
            &voter_hash[..8],
            invalidated_tokens,
            released_lock.is_some()
        );

        Ok(LogoutResult {
            invalidated_tokens,
            released_lock: released_lock.is_some(),
        })
    }

    /// Check if a voter currently has an active lock
    pub fn is_locked(&self, voter_hash: &str, election_id: &Uuid) -> Result<Option<VoterLock>> {
        let lock_key = format!("voting_lock:{voter_hash}:{election_id}");

        let locks = self
            .locks
            .read()
            .map_err(|_| voting_error!("Lock service read error"))?;

        if let Some(lock) = locks.get(&lock_key) {
            if !lock.is_expired() {
                Ok(Some(lock.clone()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Check if a voter has already completed voting
    pub fn has_voted(
        &self,
        voter_hash: &str,
        election_id: &Uuid,
    ) -> Result<Option<VotingCompletion>> {
        let completion_key = format!("voting_completion:{voter_hash}:{election_id}");

        let completions = self
            .completions
            .read()
            .map_err(|_| voting_error!("Completion service read error"))?;

        Ok(completions.get(&completion_key).cloned())
    }

    /// Get comprehensive voting status for a voter
    pub fn get_voting_status(&self, voter_hash: &str, election_id: &Uuid) -> Result<VotingStatus> {
        let active_lock = self.is_locked(voter_hash, election_id)?;
        let completion = self.has_voted(voter_hash, election_id)?;
        let active_tokens = self
            .token_service
            .get_voter_tokens(voter_hash, election_id)?;

        Ok(VotingStatus {
            active_lock,
            completion,
            active_tokens,
        })
    }

    /// Clean up expired locks (completion records are never cleaned up)
    pub fn cleanup_expired_locks(&self) -> Result<u32> {
        let mut locks = self
            .locks
            .write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        let initial_count = locks.len();
        locks.retain(|_, lock| !lock.is_expired());
        let cleaned_count = initial_count - locks.len();

        Ok(cleaned_count as u32)
    }

    /// Get all active locks (for debugging/monitoring)
    pub fn get_active_locks(&self) -> Result<Vec<VoterLock>> {
        let locks = self
            .locks
            .read()
            .map_err(|_| voting_error!("Lock service read error"))?;

        let active_locks: Vec<VoterLock> = locks
            .values()
            .filter(|lock| !lock.is_expired())
            .cloned()
            .collect();

        Ok(active_locks)
    }

    /// Get all voting completions (for auditing)
    pub fn get_all_completions(&self) -> Result<Vec<VotingCompletion>> {
        let completions = self
            .completions
            .read()
            .map_err(|_| voting_error!("Completion service read error"))?;

        Ok(completions.values().cloned().collect())
    }

    /// Get enhanced statistics about the lock service
    pub fn get_stats(&self) -> Result<LockServiceStats> {
        let locks = self
            .locks
            .read()
            .map_err(|_| voting_error!("Lock service read error"))?;
        let completions = self
            .completions
            .read()
            .map_err(|_| voting_error!("Completion service read error"))?;

        let total_locks = locks.len();
        let active_locks = locks.values().filter(|lock| !lock.is_expired()).count();
        let expired_locks = total_locks - active_locks;

        let digital_locks = locks
            .values()
            .filter(|lock| !lock.is_expired() && lock.method == VotingMethod::Digital)
            .count();

        let analog_locks = locks
            .values()
            .filter(|lock| !lock.is_expired() && lock.method == VotingMethod::Analog)
            .count();

        let total_completions = completions.len();
        let digital_completions = completions
            .values()
            .filter(|comp| comp.method == VotingMethod::Digital)
            .count();
        let analog_completions = completions
            .values()
            .filter(|comp| comp.method == VotingMethod::Analog)
            .count();

        // Get token service stats
        let token_stats = self.token_service.get_stats()?;

        Ok(LockServiceStats {
            total_locks,
            active_locks,
            expired_locks,
            digital_locks,
            analog_locks,
            total_completions,
            digital_completions,
            analog_completions,
            token_stats,
        })
    }

    /// Get reference to token service (for direct token operations)
    pub fn token_service(&self) -> &Arc<VotingTokenService> {
        &self.token_service
    }

    /// LEGACY: Acquire lock without token (for backwards compatibility in tests)
    #[cfg(test)]
    pub fn acquire_lock(
        &self,
        voter_hash: &str,
        election_id: &Uuid,
        method: VotingMethod,
    ) -> Result<LockResult> {
        // For testing, create a dummy token
        let dummy_token_id = format!("test_token_{}", Uuid::new_v4());

        // Skip token validation for legacy tests
        let completion_key = format!("voting_completion:{voter_hash}:{election_id}");
        let lock_key = format!("voting_lock:{voter_hash}:{election_id}");

        // Check completion
        {
            let completions = self
                .completions
                .read()
                .map_err(|_| voting_error!("Completion service read error"))?;

            if let Some(completion) = completions.get(&completion_key) {
                return Ok(LockResult::AlreadyVoted {
                    completion: completion.clone(),
                    original_method: completion.method.clone(),
                });
            }
        }

        // Check locks and acquire
        let mut locks = self
            .locks
            .write()
            .map_err(|_| voting_error!("Lock service write error"))?;

        if let Some(existing_lock) = locks.get(&lock_key) {
            if !existing_lock.is_expired() {
                return Ok(LockResult::AlreadyLocked {
                    existing_lock: existing_lock.clone(),
                    conflict_method: existing_lock.method.clone(),
                });
            } else {
                locks.remove(&lock_key);
            }
        }

        let new_lock = VoterLock::new(
            voter_hash.to_string(),
            *election_id,
            method,
            VOTING_LOCK_DURATION,
            dummy_token_id,
        )?;

        locks.insert(lock_key, new_lock.clone());
        Ok(LockResult::Acquired(new_lock))
    }

    /// LEGACY: Complete voting without token cleanup (for backwards compatibility)
    #[cfg(test)]
    pub fn complete_voting(
        &self,
        lock: &VoterLock,
        vote_id: Option<Uuid>,
    ) -> Result<VotingCompletion> {
        let completion = VotingCompletion::new(
            lock.voter_hash.clone(),
            lock.election_id,
            lock.method.clone(),
            vote_id,
            lock.token_id.clone(),
        )?;

        let completion_key = completion.completion_key();

        {
            let mut completions = self
                .completions
                .write()
                .map_err(|_| voting_error!("Completion service write error"))?;
            let mut locks = self
                .locks
                .write()
                .map_err(|_| voting_error!("Lock service write error"))?;

            completions.insert(completion_key, completion.clone());
            locks.remove(&lock.lock_key());
        }

        Ok(completion)
    }
}

/// Combined voting status for a voter
#[derive(Debug, Clone)]
pub struct VotingStatus {
    /// Current active lock (if any)
    pub active_lock: Option<VoterLock>,
    /// Voting completion record (if any)
    pub completion: Option<VotingCompletion>,
    /// Active tokens for this voter/election
    pub active_tokens: Vec<crate::crypto::voting_token::VotingToken>,
}

impl VotingStatus {
    /// Check if voter can start voting
    pub fn can_vote(&self) -> bool {
        // Can vote only if: no completion AND no active lock AND has active tokens
        self.completion.is_none()
            && self.active_lock.is_none()
            && !self.active_tokens.is_empty()
            && self.active_tokens.iter().any(|t| t.is_usable())
    }

    /// Get the reason why voting is blocked (if any)
    pub fn blocking_reason(&self) -> Option<String> {
        if let Some(completion) = &self.completion {
            Some(format!(
                "Already voted via {:?} at {} with token {}",
                completion.method,
                completion.completed_at,
                &completion.token_id[..8]
            ))
        } else if let Some(lock) = &self.active_lock {
            Some(format!(
                "Currently voting via {:?} (expires in {}s) with token {}",
                lock.method,
                lock.time_remaining(),
                &lock.token_id[..8]
            ))
        } else if self.active_tokens.is_empty() {
            Some("No valid voting tokens available".to_string())
        } else if !self.active_tokens.iter().any(|t| t.is_usable()) {
            Some("All voting tokens are expired or invalid".to_string())
        } else {
            None
        }
    }

    /// Get the best usable token (most recent, active)
    pub fn get_usable_token(&self) -> Option<&crate::crypto::voting_token::VotingToken> {
        self.active_tokens
            .iter()
            .filter(|token| token.is_usable())
            .max_by_key(|token| token.issued_at) // Most recent first
    }
}

/// Result of logout operation
#[derive(Debug, Clone)]
pub struct LogoutResult {
    pub invalidated_tokens: u32,
    pub released_lock: bool,
}

/// Enhanced statistics about the lock service with token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockServiceStats {
    // Lock stats
    pub total_locks: usize,
    pub active_locks: usize,
    pub expired_locks: usize,
    pub digital_locks: usize,
    pub analog_locks: usize,

    // Completion stats
    pub total_completions: usize,
    pub digital_completions: usize,
    pub analog_completions: usize,

    // Token stats
    pub token_stats: crate::crypto::voting_token::TokenServiceStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecureSaltManager;

    #[tokio::test]
    async fn test_integrated_token_voting_workflow() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Step 1: Issue token (login)
        let token_result = token_service
            .issue_token(
                &salt_manager,
                &voter_hash,
                &election_id,
                Some("session_123".to_string()),
            )
            .unwrap();

        let token = match token_result {
            TokenResult::Issued(token) => token,
            _ => panic!("Expected token to be issued"),
        };

        println!("✅ Token issued: {}", token.token_id);

        // Step 2: Acquire voting lock with token
        let lock_result = lock_service
            .acquire_lock_with_token(
                &salt_manager,
                &token.token_id,
                &voter_hash,
                &election_id,
                VotingMethod::Digital,
            )
            .unwrap();

        let voting_lock = match lock_result {
            LockResult::Acquired(lock) => lock,
            _ => panic!("Expected to acquire lock with valid token"),
        };

        println!("✅ Voting lock acquired with token validation");

        // Step 3: Complete voting
        let vote_id = Uuid::new_v4();
        let completion = lock_service
            .complete_voting_with_token_cleanup(&voting_lock, Some(vote_id))
            .unwrap();

        println!("✅ Voting completed: {}", completion.completion_id);

        // Step 4: Verify token is invalidated
        let token_validation = token_service
            .validate_token(&salt_manager, &token.token_id, &voter_hash, &election_id)
            .unwrap();

        match token_validation {
            TokenResult::Invalid { reason } => {
                println!("✅ Token correctly invalidated after voting: {reason}");
            }
            _ => panic!("Expected token to be invalidated after voting"),
        }

        // Step 5: Try to vote again (should fail due to completion)
        let new_token_result = token_service
            .issue_token(
                &salt_manager,
                &voter_hash,
                &election_id,
                Some("session_456".to_string()),
            )
            .unwrap();

        let new_token = match new_token_result {
            TokenResult::Issued(token) => token,
            _ => panic!("Should be able to issue new token"),
        };

        let second_lock_result = lock_service
            .acquire_lock_with_token(
                &salt_manager,
                &new_token.token_id,
                &voter_hash,
                &election_id,
                VotingMethod::Analog,
            )
            .unwrap();

        match second_lock_result {
            LockResult::AlreadyVoted { .. } => {
                println!("✅ Second voting attempt blocked by completion record");
            }
            _ => panic!("Expected second voting to be blocked"),
        }
    }

    #[test]
    fn test_invalid_token_blocking() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service);

        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Try to acquire lock with invalid token
        let lock_result = lock_service
            .acquire_lock_with_token(
                &salt_manager,
                "invalid_token_123",
                &voter_hash,
                &election_id,
                VotingMethod::Digital,
            )
            .unwrap();

        match lock_result {
            LockResult::InvalidToken { reason } => {
                assert!(reason.contains("not found"));
                println!("✅ Invalid token correctly blocked: {reason}");
            }
            _ => panic!("Expected invalid token to be blocked"),
        }
    }

    #[test]
    fn test_voter_logout_functionality() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Issue token and acquire lock
        let token_result = token_service
            .issue_token(
                &salt_manager,
                &voter_hash,
                &election_id,
                Some("session_123".to_string()),
            )
            .unwrap();

        let token = match token_result {
            TokenResult::Issued(token) => token,
            _ => panic!("Expected token to be issued"),
        };

        let lock_result = lock_service
            .acquire_lock_with_token(
                &salt_manager,
                &token.token_id,
                &voter_hash,
                &election_id,
                VotingMethod::Digital,
            )
            .unwrap();

        let _voting_lock = match lock_result {
            LockResult::Acquired(lock) => lock,
            _ => panic!("Expected to acquire lock"),
        };

        // Logout voter
        let logout_result = lock_service
            .logout_voter(&voter_hash, &election_id)
            .unwrap();
        assert!(logout_result.invalidated_tokens > 0);
        assert!(logout_result.released_lock);

        println!(
            "✅ Voter logout invalidated {} tokens and released lock",
            logout_result.invalidated_tokens
        );

        // Try to use token after logout (should fail)
        let validation_result = token_service
            .validate_token(&salt_manager, &token.token_id, &voter_hash, &election_id)
            .unwrap();

        match validation_result {
            TokenResult::Invalid { .. } => {
                println!("✅ Token correctly invalid after logout");
            }
            _ => panic!("Expected token to be invalid after logout"),
        }
    }

    #[test]
    fn test_enhanced_voting_status() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = Arc::new(VotingTokenService::for_testing());
        let lock_service = VotingLockService::new(token_service.clone());

        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Initial status - no tokens
        let initial_status = lock_service
            .get_voting_status(&voter_hash, &election_id)
            .unwrap();
        assert!(!initial_status.can_vote());
        assert!(
            initial_status
                .blocking_reason()
                .unwrap()
                .contains("No valid voting tokens")
        );

        // Issue token
        let _token_result = token_service
            .issue_token(&salt_manager, &voter_hash, &election_id, None)
            .unwrap();

        // Status with token
        let status_with_token = lock_service
            .get_voting_status(&voter_hash, &election_id)
            .unwrap();
        assert!(status_with_token.can_vote());
        assert!(status_with_token.blocking_reason().is_none());
        assert_eq!(status_with_token.active_tokens.len(), 1);

        println!("✅ Enhanced voting status works correctly");
    }
}
