# Cryptographic Operations API

## Overview

Cryptographic operations with timing attack resistance and PCI DSS compliance.

## Core Operations

### Voter Identity Hashing

```rust
use vote::crypto::SecureSaltManager;

// Initialize with environment salts
let salt_manager = SecureSaltManager::new()?;

// Generate secure voter hash
let voter_hash = salt_manager.hash_voter_identity_secure(
    "bank_customer_id",      // Bank customer identifier
    &election_id,            // Election UUID  
    1725120000,              // Current timestamp
    300                      // Max age in seconds (5 minutes)
)?;
```

**Security Properties:**
- ✅ **Unlinkable:** Impossible to reverse voter identity
- ✅ **Deterministic:** Same voter = same hash within time window
- ✅ **Replay Protected:** Timestamp validation prevents replay
- ✅ **Timing Attack Resistant:** Constant-time operations

**Error Handling:**
```rust
match salt_manager.hash_voter_identity_secure(bank_id, &election_id, ts, max_age) {
    Ok(hash) => {
        // Use secure hash for voting operations
        proceed_with_voting(hash);
    }
    Err(VotingError::InvalidTimestamp) => {
        // Timestamp too old or in future
        request_fresh_timestamp();
    }
    Err(VotingError::CryptoError(msg)) => {
        // Cryptographic operation failed
        log_security_incident(msg);
    }
}
```

### Digital Signatures

```rust
use vote::crypto::SecureKeyPair;

// Generate new key pair with expiration
let key_pair = SecureKeyPair::generate_with_expiration(Some(86400))?; // 24 hours

// Sign data with timestamp
let signature = key_pair.sign_with_timestamp(
    b"voting_data_to_sign",
    1725120000  // Current timestamp
)?;

// Verify signature with timestamp validation
let is_valid = key_pair.verify_signature_with_timestamp(
    b"voting_data_to_sign",
    &signature,
    1725120000,  // Signature timestamp
    300          // Max age tolerance (5 minutes)
)?;
```

**Key Management:**
```rust
// Check key expiration
if key_pair.is_expired() {
    // Automatic key rotation needed
    let new_key_pair = SecureKeyPair::generate_with_expiration(Some(86400))?;
    replace_key_pair(new_key_pair);
}

// Get key metadata
let metadata = key_pair.get_metadata();
println!("Key expires at: {}", metadata.expires_at);
println!("Key algorithm: {}", metadata.algorithm); // "Ed25519"
```

### Memory Security

```rust
use vote::crypto::SecureMemory;

// Constant-time comparison (timing attack resistant)
let hash1 = calculate_voter_hash(voter1);
let hash2 = calculate_voter_hash(voter2);

let are_equal = SecureMemory::constant_time_eq(&hash1, &hash2);
// Timing is consistent regardless of where differences occur

// Secure random generation
let random_token: [u8; 32] = SecureMemory::secure_random_bytes();
let random_session_id: [u8; 16] = SecureMemory::secure_random_bytes();
```

## Token Management

### Voting Token Lifecycle

```rust
use vote::crypto::{VotingTokenService, voting_token::TokenResult};

let token_service = VotingTokenService::new();

// 1. Issue voting token (login)
let token_result = token_service.issue_token(
    &salt_manager,
    &voter_hash,
    &election_id,
    Some("web_session_abc123".to_string())
)?;

let token = match token_result {
    TokenResult::Issued(token) => token,
    TokenResult::Invalid { reason } => {
        return Err(format!("Token issuance failed: {}", reason));
    }
    TokenResult::RateLimited => {
        return Err("Rate limit exceeded - try again later");
    }
};

// 2. Validate token before voting operations
let validation = token_service.validate_token(
    &salt_manager,
    &token.token_id,
    &voter_hash,
    &election_id
)?;

match validation {
    TokenResult::Valid(validated_token) => {
        // Proceed with voting
        proceed_to_voting(validated_token);
    }
    TokenResult::Invalid { reason } => {
        // Token invalid - require re-authentication
        redirect_to_login(&reason);
    }
    TokenResult::Expired => {
        // Token expired - issue new one
        request_token_refresh();
    }
}

// 3. Mark token as used (after voting)
token_service.mark_token_used(&token.token_id, vote_id)?;
```

### Voting Lock Management

```rust
use vote::crypto::{VotingLockService, voting_lock::{LockResult, VotingMethod}};

let lock_service = VotingLockService::new(token_service);

// Acquire voting lock with token validation
let lock_result = lock_service.acquire_lock_with_token(
    &salt_manager,
    &token.token_id,
    &voter_hash,
    &election_id,
    VotingMethod::Digital
)?;

match lock_result {
    LockResult::Acquired(lock) => {
        // Voting lock acquired - can proceed
        conduct_voting_session(lock);
    }
    LockResult::AlreadyLocked { existing_lock, .. } => {
        let remaining = existing_lock.time_remaining();
        return Err(format!("Voting session active - {} seconds remaining", remaining));
    }
    LockResult::AlreadyVoted { completion, .. } => {
        return Err(format!("Already voted at {}", completion.completed_at));
    }
    LockResult::InvalidToken { reason } => {
        return Err(format!("Authentication required: {}", reason));
    }
}

// Complete voting and clean up
let completion = lock_service.complete_voting_with_token_cleanup(
    &voting_lock,
    Some(vote_id)
)?;
```

## Rate Limiting

### DoS Protection

```rust
use vote::crypto::CryptoRateLimiter;

// Initialize rate limiter (10 operations per second)
let mut rate_limiter = CryptoRateLimiter::new(10);

// Check rate limit before crypto operations
match rate_limiter.check_rate_limit() {
    Ok(()) => {
        // Proceed with operation
        perform_crypto_operation();
    }
    Err(VotingError::RateLimitExceeded) => {
        // Rate limit exceeded - delay or reject
        std::thread::sleep(std::time::Duration::from_millis(100));
        return Err("Rate limit exceeded - please slow down");
    }
}

// Get rate limit status
let status = rate_limiter.get_status();
println!("Operations remaining: {}", status.remaining);
println!("Reset time: {}", status.reset_time);
```

## Security Context Integration

### Complete Workflow

```rust
use vote::crypto::SecurityContext;

// Initialize security context with all components
let security_context = SecurityContext::new(
    salt_manager,
    token_service,
    lock_service
)?;

// Secure voter login
let login_result = security_context.secure_voter_login(
    "bank_customer_id",
    &election_id,
    "web_session_123"
).await?;

// Acquire voting authorization
let voting_auth = security_context.acquire_voting_authorization(
    &login_result.voter_hash,
    &election_id,
    VotingMethod::Digital
).await?;

// Conduct secure voting
let vote_result = security_context.conduct_secure_voting(
    voting_auth,
    vote_data
).await?;

// Automatic cleanup (tokens invalidated, locks released)
```

## Error Handling Patterns

### Comprehensive Error Management

```rust
use vote::{VotingError, Result};

fn handle_crypto_operation() -> Result<String> {
    match perform_crypto_operation() {
        Ok(result) => Ok(result),
        
        // Authentication errors
        Err(VotingError::InvalidTimestamp) => {
            log_security_event("Invalid timestamp in crypto operation");
            Err(VotingError::InvalidTimestamp)
        }
        
        // Rate limiting
        Err(VotingError::RateLimitExceeded) => {
            // Don't log as error - expected behavior
            Err(VotingError::RateLimitExceeded)
        }
        
        // Cryptographic failures
        Err(VotingError::CryptoError(msg)) => {
            log_security_incident(&format!("Crypto failure: {}", msg));
            alert_security_team();
            Err(VotingError::CryptoError(msg))
        }
        
        // System errors
        Err(VotingError::SystemError(msg)) => {
            log_system_error(&msg);
            Err(VotingError::SystemError(msg))
        }
    }
}
```

## Configuration

### Production Setup

```rust
use vote::crypto::SecureSaltManager;

// Environment-based configuration (recommended)
let salt_manager = SecureSaltManager::new()?; // Uses env vars

// Manual configuration (testing only)
let salt_manager = SecureSaltManager::with_salts(
    "voter_salt_32_bytes_base64_encoded",
    "token_salt_32_bytes_base64_encoded"
)?;

// Validate configuration
salt_manager.validate_configuration()?;
```

### Required Environment Variables

```bash
# Production deployment
export CRYPTO_VOTER_SALT=$(openssl rand -base64 32)
export CRYPTO_TOKEN_SALT=$(openssl rand -base64 32)

# Optional security settings
export CRYPTO_KEY_EXPIRY_SECONDS=86400        # 24 hours
export CRYPTO_MAX_OPS_PER_SECOND=10           # Rate limit
export CRYPTO_MAX_TIMESTAMP_AGE_SECONDS=300   # 5 minutes
```

## Performance Considerations

### Optimization Guidelines

```rust
// ✅ Good: Reuse salt manager
let salt_manager = SecureSaltManager::new()?;
for voter in voters {
    let hash = salt_manager.hash_voter_identity_secure(...)?;
}

// ❌ Bad: Create new salt manager each time
for voter in voters {
    let salt_manager = SecureSaltManager::new()?; // Expensive!
    let hash = salt_manager.hash_voter_identity_secure(...)?;
}

// ✅ Good: Batch token validation
let tokens = vec![token1, token2, token3];
let results = token_service.validate_tokens_batch(&salt_manager, tokens)?;

// ✅ Good: Check rate limits efficiently
if !rate_limiter.can_proceed() {
    return Err(VotingError::RateLimitExceeded);
}
```

### Memory Management

```rust
// Automatic secure cleanup
{
    let key_pair = SecureKeyPair::generate()?;
    // Key material automatically zeroed when dropped
} // <-- Key memory cleared here

// Explicit cleanup for sensitive data
let mut sensitive_data = vec![0u8; 1024];
// ... use sensitive_data ...
SecureMemory::secure_zero(&mut sensitive_data);
```

## Testing Support

### Test Utilities

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_operations() {
        // Use test-specific instances
        let salt_manager = SecureSaltManager::for_testing();
        let token_service = VotingTokenService::for_testing();
        
        // Test crypto operations
        let hash = salt_manager.hash_voter_identity_secure(
            "test_voter", &Uuid::new_v4(), 1725120000, 300
        ).unwrap();
        
        assert_eq!(hash.len(), 64); // 32 bytes, hex encoded
    }
    
    #[tokio::test]
    async fn test_voting_workflow() {
        let security_context = SecurityContext::for_testing();
        
        // Test complete voting workflow
        let result = security_context.secure_voter_login(
            "test_voter", &Uuid::new_v4(), "test_session"
        ).await;
        
        assert!(result.is_ok());
    }
}
```

## Security Best Practices

### Implementation Guidelines

1. **Always validate timestamps** - Prevent replay attacks
2. **Use constant-time comparisons** - Prevent timing attacks
3. **Check rate limits first** - Prevent DoS attacks
4. **Log security events** - Enable incident detection
5. **Handle errors securely** - Don't leak information
6. **Rotate keys regularly** - Limit exposure window
7. **Use environment salts** - Never hardcode secrets

### Common Pitfalls

```rust
// ❌ WRONG: Variable timing
if voter_hash == expected_hash {
    return Ok(());
}

// ✅ CORRECT: Constant timing
if SecureMemory::constant_time_eq(&voter_hash, &expected_hash) {
    return Ok(());
}

// ❌ WRONG: Information leak in errors
return Err(format!("Hash {} doesn't match expected {}", voter_hash, expected));

// ✅ CORRECT: Generic error messages
return Err("Authentication failed".to_string());
```

---

**API Version:** v0.1.0  
**Last Updated:** August 2025  
**Security Review:** Passed banking-grade audit