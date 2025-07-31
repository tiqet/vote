//! Voting token service for session management and security
//!
//! This module provides session-aware token management for millions of concurrent users:
//! 1. Election-specific tokens with configurable expiration
//! 2. Immediate invalidation on logout or vote completion
//! 3. Automatic cleanup of expired tokens
//! 4. Integration with voting lock system
//! 5. Replay attack prevention with one-time use semantics

use crate::{voting_error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Default token lifetime in seconds (30 minutes)
const DEFAULT_TOKEN_LIFETIME: u64 = 1800;

/// Maximum number of active tokens per voter (prevents abuse)
const MAX_TOKENS_PER_VOTER: usize = 3;

/// Token configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Token lifetime in seconds
    pub lifetime_seconds: u64,
    /// How often to clean up expired tokens (seconds)
    pub cleanup_interval_seconds: u64,
    /// Maximum active tokens per voter
    pub max_tokens_per_voter: usize,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            lifetime_seconds: DEFAULT_TOKEN_LIFETIME,
            cleanup_interval_seconds: 300, // 5 minutes
            max_tokens_per_voter: MAX_TOKENS_PER_VOTER,
        }
    }
}

impl TokenConfig {
    /// Configuration for testing with shorter timeouts
    pub fn for_testing() -> Self {
        Self {
            lifetime_seconds: 300,     // 5 minutes for testing
            cleanup_interval_seconds: 30, // 30 seconds cleanup
            max_tokens_per_voter: 2,   // Reduced for testing
        }
    }
}

/// State of a voting token
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TokenState {
    /// Token is active and can be used for voting
    Active,
    /// Token was used for voting and is now invalid
    Used { vote_id: Uuid, used_at: u64 },
    /// Token was manually invalidated (logout)
    Invalidated { invalidated_at: u64 },
    /// Token expired due to timeout
    Expired,
}

/// Voting token with session management
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VotingToken {
    pub token_id: String,
    pub voter_hash: String,
    pub election_id: Uuid,
    pub token_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: TokenState,
    pub session_id: Option<String>, // Optional session tracking
}

impl VotingToken {
    /// Create a new voting token with explicit expiration timestamp
    pub fn new(
        voter_hash: String,
        election_id: Uuid,
        token_hash: [u8; 32],
        nonce: [u8; 16],
        issued_at: u64,
        expires_at: u64,
        session_id: Option<String>,
    ) -> Result<Self> {
        let token_id = format!("{}:{}", hex::encode(&token_hash[0..8]), Uuid::new_v4());

        Ok(Self {
            token_id,
            voter_hash,
            election_id,
            token_hash,
            nonce,
            issued_at,
            expires_at,
            state: TokenState::Active,
            session_id,
        })
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        current_time > self.expires_at
    }

    /// Check if token is usable for voting
    pub fn is_usable(&self) -> bool {
        match self.state {
            TokenState::Active => !self.is_expired(),
            _ => false,
        }
    }

    /// Get time remaining in seconds
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

    /// Mark token as used
    pub fn mark_used(&mut self, vote_id: Uuid) -> Result<()> {
        match self.state {
            TokenState::Active => {
                let used_at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| voting_error!("System time error"))?
                    .as_secs();

                self.state = TokenState::Used { vote_id, used_at };
                Ok(())
            }
            _ => Err(voting_error!("Token is not active and cannot be marked as used")),
        }
    }

    /// Mark token as invalidated (logout)
    pub fn mark_invalidated(&mut self) -> Result<()> {
        let invalidated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| voting_error!("System time error"))?
            .as_secs();

        self.state = TokenState::Invalidated { invalidated_at };
        Ok(())
    }

    /// Generate storage key
    pub fn storage_key(&self) -> String {
        format!("token:{}", self.token_id)
    }

    /// Generate voter index key
    pub fn voter_key(&self) -> String {
        format!("voter_tokens:{}:{}", self.voter_hash, self.election_id)
    }
}

/// Result of token operations
#[derive(Debug, PartialEq)]
pub enum TokenResult {
    /// Token issued successfully
    Issued(VotingToken),
    /// Token validation successful
    Valid(VotingToken),
    /// Token is invalid/expired/used
    Invalid { reason: String },
    /// Token invalidated successfully
    Invalidated,
    /// Voter has too many active tokens
    TooManyTokens { active_count: usize },
}

/// High-performance token service for millions of users
pub struct VotingTokenService {
    config: TokenConfig,
    /// Main token storage: token_id -> VotingToken
    tokens: RwLock<HashMap<String, VotingToken>>,
    /// Voter index: voter_hash:election_id -> Vec<token_id>
    voter_tokens: RwLock<HashMap<String, Vec<String>>>,
}

impl VotingTokenService {
    /// Create new token service
    pub fn new(config: TokenConfig) -> Self {
        Self {
            config,
            tokens: RwLock::new(HashMap::new()),
            voter_tokens: RwLock::new(HashMap::new()),
        }
    }

    /// Create token service with default configuration
    pub fn with_defaults() -> Self {
        Self::new(TokenConfig::default())
    }

    /// Create token service for testing
    pub fn for_testing() -> Self {
        Self::new(TokenConfig::for_testing())
    }

    /// Issue a new voting token (login scenario)
    pub fn issue_token(
        &self,
        salt_manager: &crate::crypto::SecureSaltManager,
        voter_hash: &str,
        election_id: &Uuid,
        session_id: Option<String>,
    ) -> Result<TokenResult> {
        let voter_key = format!("voter_tokens:{}:{}", voter_hash, election_id);

        // Check if voter already has too many active tokens
        {
            let voter_tokens = self.voter_tokens.read()
                .map_err(|_| voting_error!("Token service read error"))?;

            if let Some(token_ids) = voter_tokens.get(&voter_key) {
                let tokens = self.tokens.read()
                    .map_err(|_| voting_error!("Token service read error"))?;

                let active_count = token_ids.iter()
                    .filter_map(|id| tokens.get(id))
                    .filter(|token| token.is_usable())
                    .count();

                if active_count >= self.config.max_tokens_per_voter {
                    return Ok(TokenResult::TooManyTokens { active_count });
                }
            }
        }

        // Generate secure token
        let voter_hash_bytes = hex::decode(voter_hash)
            .map_err(|_| voting_error!("Invalid voter hash format"))?;

        if voter_hash_bytes.len() != 32 {
            return Err(voting_error!("Voter hash must be 32 bytes"));
        }

        let mut voter_hash_array = [0u8; 32];
        voter_hash_array.copy_from_slice(&voter_hash_bytes);

        // CRITICAL FIX: Calculate timestamps once and use the same values
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| voting_error!("System time error"))?
            .as_secs();

        let expires_at = issued_at + self.config.lifetime_seconds;

        let (token_hash, nonce) = salt_manager.generate_voting_token_secure(
            &voter_hash_array,
            election_id,
            expires_at,
        )?;

        // Create token using the same timestamps
        let token = VotingToken::new(
            voter_hash.to_string(),
            *election_id,
            token_hash,
            nonce,
            issued_at,
            expires_at,
            session_id,
        )?;

        // Store token atomically
        {
            let mut tokens = self.tokens.write()
                .map_err(|_| voting_error!("Token service write error"))?;
            let mut voter_tokens = self.voter_tokens.write()
                .map_err(|_| voting_error!("Token service write error"))?;

            // Add to main storage
            tokens.insert(token.token_id.clone(), token.clone());

            // Add to voter index
            voter_tokens.entry(voter_key)
                .or_insert_with(Vec::new)
                .push(token.token_id.clone());
        }

        tracing::info!(
            "🎫 Token issued: voter={}, election={}, expires_in={}s",
            &voter_hash[..8],
            election_id,
            token.time_remaining()
        );

        Ok(TokenResult::Issued(token))
    }

    /// Validate a voting token
    pub fn validate_token(
        &self,
        salt_manager: &crate::crypto::SecureSaltManager,
        token_id: &str,
        voter_hash: &str,
        election_id: &Uuid,
    ) -> Result<TokenResult> {
        let tokens = self.tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;

        let token = match tokens.get(token_id) {
            Some(token) => token,
            None => return Ok(TokenResult::Invalid { reason: "Token not found".to_string() }),
        };

        // Basic validation checks
        if token.voter_hash != voter_hash {
            return Ok(TokenResult::Invalid { reason: "Token voter mismatch".to_string() });
        }

        if token.election_id != *election_id {
            return Ok(TokenResult::Invalid { reason: "Token election mismatch".to_string() });
        }

        if !token.is_usable() {
            let reason = match &token.state {
                TokenState::Used { used_at, .. } => format!("Token already used at {}", used_at),
                TokenState::Invalidated { invalidated_at } => format!("Token invalidated at {}", invalidated_at),
                TokenState::Expired => "Token expired".to_string(),
                TokenState::Active => "Token expired".to_string(), // Must be expired if not usable
            };
            return Ok(TokenResult::Invalid { reason });
        }

        // Cryptographic validation - regenerate token using stored expires_at
        let voter_hash_bytes = hex::decode(voter_hash)
            .map_err(|_| voting_error!("Invalid voter hash format"))?;

        let mut voter_hash_array = [0u8; 32];
        voter_hash_array.copy_from_slice(&voter_hash_bytes);

        // Use the same nonce and expires_at from the stored token
        let is_valid = salt_manager.validate_voting_token_secure(
            &token.token_hash,
            &token.nonce,
            &voter_hash_array,
            election_id,
            token.expires_at,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| voting_error!("System time error"))?
                .as_secs(),
        )?;

        if !is_valid {
            return Ok(TokenResult::Invalid { reason: "Token cryptographic validation failed".to_string() });
        }

        Ok(TokenResult::Valid(token.clone()))
    }

    /// Invalidate a token (logout scenario)
    pub fn invalidate_token(&self, token_id: &str) -> Result<TokenResult> {
        let mut tokens = self.tokens.write()
            .map_err(|_| voting_error!("Token service write error"))?;

        if let Some(token) = tokens.get_mut(token_id) {
            match token.state {
                TokenState::Active => {
                    token.mark_invalidated()?;
                    tracing::info!(
                        "🎫 Token invalidated: voter={}, election={}",
                        &token.voter_hash[..8],
                        token.election_id
                    );
                    Ok(TokenResult::Invalidated)
                }
                _ => Ok(TokenResult::Invalid { reason: "Token not active".to_string() }),
            }
        } else {
            Ok(TokenResult::Invalid { reason: "Token not found".to_string() })
        }
    }

    /// Invalidate all tokens for a voter (logout all sessions)
    pub fn invalidate_voter_tokens(&self, voter_hash: &str, election_id: &Uuid) -> Result<u32> {
        let voter_key = format!("voter_tokens:{}:{}", voter_hash, election_id);
        let mut invalidated_count = 0;

        let voter_tokens = self.voter_tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;

        if let Some(token_ids) = voter_tokens.get(&voter_key) {
            let mut tokens = self.tokens.write()
                .map_err(|_| voting_error!("Token service write error"))?;

            for token_id in token_ids {
                if let Some(token) = tokens.get_mut(token_id) {
                    if matches!(token.state, TokenState::Active) {
                        token.mark_invalidated()?;
                        invalidated_count += 1;
                    }
                }
            }
        }

        if invalidated_count > 0 {
            tracing::info!(
                "🎫 Invalidated {} tokens for voter={}, election={}",
                invalidated_count,
                &voter_hash[..8],
                election_id
            );
        }

        Ok(invalidated_count)
    }

    /// Mark token as used (after successful voting)
    pub fn mark_token_used(&self, token_id: &str, vote_id: Uuid) -> Result<TokenResult> {
        let mut tokens = self.tokens.write()
            .map_err(|_| voting_error!("Token service write error"))?;

        if let Some(token) = tokens.get_mut(token_id) {
            token.mark_used(vote_id)?;
            tracing::info!(
                "🎫 Token marked as used: voter={}, vote_id={}",
                &token.voter_hash[..8],
                vote_id
            );
            Ok(TokenResult::Valid(token.clone()))
        } else {
            Ok(TokenResult::Invalid { reason: "Token not found".to_string() })
        }
    }

    /// Get all active tokens for a voter
    pub fn get_voter_tokens(&self, voter_hash: &str, election_id: &Uuid) -> Result<Vec<VotingToken>> {
        let voter_key = format!("voter_tokens:{}:{}", voter_hash, election_id);

        let voter_tokens = self.voter_tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;
        let tokens = self.tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;

        let mut result = Vec::new();

        if let Some(token_ids) = voter_tokens.get(&voter_key) {
            for token_id in token_ids {
                if let Some(token) = tokens.get(token_id) {
                    result.push(token.clone());
                }
            }
        }

        Ok(result)
    }

    /// Clean up expired and used tokens (call periodically)
    pub fn cleanup_expired_tokens(&self) -> Result<TokenCleanupStats> {
        let mut tokens = self.tokens.write()
            .map_err(|_| voting_error!("Token service write error"))?;
        let mut voter_tokens = self.voter_tokens.write()
            .map_err(|_| voting_error!("Token service write error"))?;

        let initial_count = tokens.len();
        let mut expired_count = 0;
        let mut used_count = 0;
        let mut invalidated_count = 0;

        // Collect tokens to remove
        let mut tokens_to_remove = Vec::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (token_id, token) in tokens.iter_mut() {
            let should_remove = match &token.state {
                TokenState::Active => {
                    if current_time > token.expires_at {
                        token.state = TokenState::Expired;
                        expired_count += 1;
                        true
                    } else {
                        false
                    }
                }
                TokenState::Used { used_at, .. } => {
                    // Remove used tokens after 1 hour (for audit purposes)
                    if current_time - used_at > 3600 {
                        used_count += 1;
                        true
                    } else {
                        false
                    }
                }
                TokenState::Invalidated { invalidated_at } => {
                    // Remove invalidated tokens after 1 hour
                    if current_time - invalidated_at > 3600 {
                        invalidated_count += 1;
                        true
                    } else {
                        false
                    }
                }
                TokenState::Expired => {
                    // Remove expired tokens immediately
                    true
                }
            };

            if should_remove {
                tokens_to_remove.push(token_id.clone());
            }
        }

        // Remove tokens from main storage
        for token_id in &tokens_to_remove {
            tokens.remove(token_id);
        }

        // Clean up voter index
        voter_tokens.retain(|_, token_ids| {
            token_ids.retain(|id| !tokens_to_remove.contains(id));
            !token_ids.is_empty()
        });

        let final_count = tokens.len();
        let total_removed = initial_count - final_count;

        let stats = TokenCleanupStats {
            initial_tokens: initial_count,
            final_tokens: final_count,
            total_removed,
            expired_removed: expired_count,
            used_removed: used_count,
            invalidated_removed: invalidated_count,
        };

        if total_removed > 0 {
            tracing::info!(
                "🧹 Token cleanup: removed {} tokens (expired: {}, used: {}, invalidated: {})",
                total_removed, expired_count, used_count, invalidated_count
            );
        }

        Ok(stats)
    }

    /// Get token service statistics
    pub fn get_stats(&self) -> Result<TokenServiceStats> {
        let tokens = self.tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;
        let voter_tokens = self.voter_tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;

        let total_tokens = tokens.len();
        let mut active_tokens = 0;
        let mut used_tokens = 0;
        let mut invalidated_tokens = 0;
        let mut expired_tokens = 0;

        for token in tokens.values() {
            match &token.state {
                TokenState::Active => {
                    if token.is_expired() {
                        expired_tokens += 1;
                    } else {
                        active_tokens += 1;
                    }
                }
                TokenState::Used { .. } => used_tokens += 1,
                TokenState::Invalidated { .. } => invalidated_tokens += 1,
                TokenState::Expired => expired_tokens += 1,
            }
        }

        let unique_voters = voter_tokens.len();

        Ok(TokenServiceStats {
            total_tokens,
            active_tokens,
            used_tokens,
            invalidated_tokens,
            expired_tokens,
            unique_voters,
        })
    }

    /// Get token by ID (for debugging)
    pub fn get_token(&self, token_id: &str) -> Result<Option<VotingToken>> {
        let tokens = self.tokens.read()
            .map_err(|_| voting_error!("Token service read error"))?;

        Ok(tokens.get(token_id).cloned())
    }
}

/// Token cleanup statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCleanupStats {
    pub initial_tokens: usize,
    pub final_tokens: usize,
    pub total_removed: usize,
    pub expired_removed: usize,
    pub used_removed: usize,
    pub invalidated_removed: usize,
}

/// Token service statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenServiceStats {
    pub total_tokens: usize,
    pub active_tokens: usize,
    pub used_tokens: usize,
    pub invalidated_tokens: usize,
    pub expired_tokens: usize,
    pub unique_voters: usize,
}

/// Background service for automatic token cleanup
pub struct TokenCleanupService {
    token_service: std::sync::Arc<VotingTokenService>,
    stop_signal: tokio::sync::mpsc::Receiver<()>,
    cleanup_interval: std::time::Duration,
}

impl TokenCleanupService {
    /// Create new cleanup service
    pub fn new(
        token_service: std::sync::Arc<VotingTokenService>,
        stop_signal: tokio::sync::mpsc::Receiver<()>,
    ) -> Self {
        let cleanup_interval = std::time::Duration::from_secs(
            token_service.config.cleanup_interval_seconds
        );

        Self {
            token_service,
            stop_signal,
            cleanup_interval,
        }
    }

    /// Start the background cleanup service
    pub async fn run(mut self) {
        let mut interval = tokio::time::interval(self.cleanup_interval);

        tracing::info!(
            "🧹 Token cleanup service started (interval: {:?})",
            self.cleanup_interval
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = self.token_service.cleanup_expired_tokens() {
                        tracing::error!("❌ Token cleanup failed: {}", e);
                    }
                }
                _ = self.stop_signal.recv() => {
                    tracing::info!("🛑 Token cleanup service stopping");
                    break;
                }
            }
        }

        tracing::info!("✅ Token cleanup service stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecureSaltManager;

    #[test]
    fn test_token_creation_and_lifecycle() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = VotingTokenService::for_testing();
        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Issue token
        let result = token_service.issue_token(
            &salt_manager,
            &voter_hash,
            &election_id,
            Some("session_123".to_string()),
        ).unwrap();

        let token = match result {
            TokenResult::Issued(token) => token,
            _ => panic!("Expected token to be issued"),
        };

        assert_eq!(token.voter_hash, voter_hash);
        assert_eq!(token.election_id, election_id);
        assert!(token.is_usable());

        // Validate token
        let validation_result = token_service.validate_token(
            &salt_manager,
            &token.token_id,
            &voter_hash,
            &election_id,
        ).unwrap();

        match validation_result {
            TokenResult::Valid(_) => {
                println!("✅ Token validation successful");
            }
            _ => panic!("Expected token to be valid"),
        }

        // Invalidate token
        let invalidation_result = token_service.invalidate_token(&token.token_id).unwrap();
        assert_eq!(invalidation_result, TokenResult::Invalidated);

        // Should no longer be valid
        let validation_after = token_service.validate_token(
            &salt_manager,
            &token.token_id,
            &voter_hash,
            &election_id,
        ).unwrap();

        match validation_after {
            TokenResult::Invalid { .. } => {
                println!("✅ Token correctly invalidated");
            }
            _ => panic!("Expected token to be invalid after invalidation"),
        }
    }

    #[test]
    fn test_max_tokens_per_voter() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = VotingTokenService::for_testing();
        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Issue maximum number of tokens
        for i in 0..2 { // max_tokens_per_voter = 2 for testing
            let result = token_service.issue_token(
                &salt_manager,
                &voter_hash,
                &election_id,
                Some(format!("session_{}", i)),
            ).unwrap();

            match result {
                TokenResult::Issued(_) => {
                    println!("✅ Token {} issued", i + 1);
                }
                _ => panic!("Expected token {} to be issued", i + 1),
            }
        }

        // Third token should fail
        let result = token_service.issue_token(
            &salt_manager,
            &voter_hash,
            &election_id,
            Some("session_overflow".to_string()),
        ).unwrap();

        match result {
            TokenResult::TooManyTokens { active_count } => {
                assert_eq!(active_count, 2);
                println!("✅ Too many tokens correctly prevented");
            }
            _ => panic!("Expected too many tokens error"),
        }
    }

    #[test]
    fn test_token_cleanup() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = VotingTokenService::for_testing();
        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        // Issue token
        let result = token_service.issue_token(
            &salt_manager,
            &voter_hash,
            &election_id,
            None,
        ).unwrap();

        let token = match result {
            TokenResult::Issued(token) => token,
            _ => panic!("Expected token to be issued"),
        };

        // Mark as used
        let vote_id = Uuid::new_v4();
        token_service.mark_token_used(&token.token_id, vote_id).unwrap();

        // Check stats before cleanup
        let stats_before = token_service.get_stats().unwrap();
        assert_eq!(stats_before.used_tokens, 1);

        // Cleanup should not remove recently used tokens
        let cleanup_stats = token_service.cleanup_expired_tokens().unwrap();
        assert_eq!(cleanup_stats.used_removed, 0); // Too recent to clean

        println!("✅ Token cleanup works correctly");
    }

    #[test]
    fn test_different_elections_isolated() {
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = VotingTokenService::for_testing();
        let voter_hash = hex::encode([1u8; 32]);
        let election1 = Uuid::new_v4();
        let election2 = Uuid::new_v4();

        // Issue tokens for different elections
        let result1 = token_service.issue_token(&salt_manager, &voter_hash, &election1, None).unwrap();
        let result2 = token_service.issue_token(&salt_manager, &voter_hash, &election2, None).unwrap();

        let token1 = match result1 { TokenResult::Issued(t) => t, _ => panic!() };
        let token2 = match result2 { TokenResult::Issued(t) => t, _ => panic!() };

        // Tokens should be different
        assert_ne!(token1.token_hash, token2.token_hash);

        // Token1 should not validate for election2
        let cross_validation = token_service.validate_token(
            &salt_manager,
            &token1.token_id,
            &voter_hash,
            &election2, // Wrong election
        ).unwrap();

        match cross_validation {
            TokenResult::Invalid { .. } => {
                println!("✅ Cross-election validation correctly fails");
            }
            _ => panic!("Expected cross-election validation to fail"),
        }
    }
}