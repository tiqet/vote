# Voting Workflow API

## Overview

Complete voting workflow with secure authentication, authorization, and audit trail.

## Quick Start

```rust
use vote::crypto::SecurityContext;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize security context
    let security_context = SecurityContext::new_from_env()?;
    
    // Conduct secure voting
    let result = conduct_voting(
        &security_context,
        "bank_customer_12345",
        &Uuid::new_v4(),
        "web_session_abc",
        b"vote_data_encrypted"
    ).await?;
    
    println!("Voting completed: {}", result.completion_id);
    Ok(())
}
```

## Complete Voting Workflow

### 1. Voter Authentication & Login

```rust
async fn secure_voter_login(
    security_context: &SecurityContext,
    bank_customer_id: &str,
    election_id: &Uuid,
    session_id: &str
) -> Result<LoginResult, VotingError> {
    
    // Step 1: Generate secure voter hash
    let voter_hash = security_context.salt_manager().hash_voter_identity_secure(
        bank_customer_id,
        election_id,
        current_timestamp(),
        300  // 5 minutes timestamp tolerance
    )?;
    
    // Step 2: Issue voting token
    let token_result = security_context.token_service().issue_token(
        security_context.salt_manager(),
        &voter_hash,
        election_id,
        Some(session_id.to_string())
    )?;
    
    let voting_token = match token_result {
        TokenResult::Issued(token) => token,
        TokenResult::Invalid { reason } => {
            return Err(VotingError::AuthenticationFailed(reason));
        }
        TokenResult::RateLimited => {
            return Err(VotingError::RateLimitExceeded);
        }
    };
    
    // Step 3: Log authentication event
    let auth_event = SecurityEvent::LoginAttempt {
        voter_hash: voter_hash.clone(),
        election_id: *election_id,
        session_id: Some(session_id.to_string()),
        success: true,
        timestamp: current_timestamp(),
        ip_address: None, // Set by web layer
    };
    
    security_context.audit_system().log_security_event(
        auth_event,
        Some(ComplianceLevel::High),
        Some(session_id.to_string())
    ).await?;
    
    Ok(LoginResult {
        voter_hash,
        voting_token,
        session_id: session_id.to_string(),
        expires_at: voting_token.expires_at,
    })
}
```

### 2. Voting Authorization

```rust
async fn acquire_voting_authorization(
    security_context: &SecurityContext,
    login_result: &LoginResult,
    voting_method: VotingMethod
) -> Result<VotingAuthorization, VotingError> {
    
    // Step 1: Validate current token
    let token_validation = security_context.token_service().validate_token(
        security_context.salt_manager(),
        &login_result.voting_token.token_id,
        &login_result.voter_hash,
        &login_result.voting_token.election_id
    )?;
    
    if !matches!(token_validation, TokenResult::Valid(_)) {
        return Err(VotingError::AuthenticationRequired);
    }
    
    // Step 2: Acquire voting lock
    let lock_result = security_context.lock_service().acquire_lock_with_token(
        security_context.salt_manager(),
        &login_result.voting_token.token_id,
        &login_result.voter_hash,
        &login_result.voting_token.election_id,
        voting_method
    )?;
    
    let voting_lock = match lock_result {
        LockResult::Acquired(lock) => lock,
        LockResult::AlreadyLocked { existing_lock, .. } => {
            return Err(VotingError::VotingInProgress {
                remaining_seconds: existing_lock.time_remaining(),
                method: existing_lock.method,
            });
        }
        LockResult::AlreadyVoted { completion, .. } => {
            return Err(VotingError::AlreadyVoted {
                completed_at: completion.completed_at,
                method: completion.method,
            });
        }
        LockResult::InvalidToken { reason } => {
            return Err(VotingError::AuthenticationFailed(reason));
        }
        LockResult::ExpiredLockRemoved(lock) => {
            // Previous expired lock was cleaned up
            lock
        }
    };
    
    // Step 3: Generate voting session key
    let session_key = SecureKeyPair::generate_with_expiration(Some(600))?; // 10 minutes
    
    Ok(VotingAuthorization {
        voting_lock,
        session_key,
        voter_hash: login_result.voter_hash.clone(),
        election_id: login_result.voting_token.election_id,
        authorized_at: current_timestamp(),
    })
}
```

### 3. Secure Voting Process

```rust
async fn conduct_secure_voting(
    security_context: &SecurityContext,
    authorization: VotingAuthorization,
    vote_data: &[u8]
) -> Result<VotingResult, VotingError> {
    
    // Step 1: Validate authorization is still active
    if authorization.voting_lock.is_expired() {
        return Err(VotingError::AuthorizationExpired);
    }
    
    // Step 2: Create cryptographic proof of vote
    let vote_id = Uuid::new_v4();
    let vote_timestamp = current_timestamp();
    
    // Create vote package with signature
    let vote_package = VotePackage {
        vote_id,
        voter_hash: authorization.voter_hash.clone(),
        election_id: authorization.election_id,
        vote_data: vote_data.to_vec(),
        timestamp: vote_timestamp,
    };
    
    // Sign the vote with session key
    let vote_signature = authorization.session_key.sign_with_timestamp(
        &vote_package.to_bytes()?,
        vote_timestamp
    )?;
    
    // Step 3: Record vote submission event
    let vote_event = SecurityEvent::VotingStarted {
        voter_hash: authorization.voter_hash.clone(),
        election_id: authorization.election_id,
        method: authorization.voting_lock.method.clone(),
        vote_id: Some(vote_id),
        timestamp: vote_timestamp,
    };
    
    security_context.audit_system().log_security_event(
        vote_event,
        Some(ComplianceLevel::Critical),
        Some(vote_id.to_string())
    ).await?;
    
    // Step 4: Process vote (placeholder - actual vote processing)
    let vote_receipt = process_vote_securely(vote_package, vote_signature).await?;
    
    // Step 5: Complete voting and cleanup
    let completion = security_context.lock_service().complete_voting_with_token_cleanup(
        &authorization.voting_lock,
        Some(vote_id)
    )?;
    
    // Step 6: Record completion event
    let completion_event = SecurityEvent::VotingCompleted {
        voter_hash: authorization.voter_hash.clone(),
        election_id: authorization.election_id,
        method: authorization.voting_lock.method.clone(),
        vote_id: Some(vote_id),
        completion_id: completion.completion_id,
        timestamp: current_timestamp(),
    };
    
    security_context.audit_system().log_security_event(
        completion_event,
        Some(ComplianceLevel::Critical),
        Some(vote_id.to_string())
    ).await?;
    
    Ok(VotingResult {
        vote_id,
        completion,
        vote_receipt,
        completed_at: current_timestamp(),
    })
}
```

### 4. Voter Logout & Cleanup

```rust
async fn secure_voter_logout(
    security_context: &SecurityContext,
    voter_hash: &str,
    election_id: &Uuid,
    session_id: &str
) -> Result<LogoutResult, VotingError> {
    
    // Step 1: Get current voting status
    let voting_status = security_context.lock_service().get_voting_status(
        voter_hash, 
        election_id
    )?;
    
    // Step 2: Handle active voting session
    if let Some(active_lock) = voting_status.active_lock {
        if !active_lock.is_expired() {
            // Release lock and invalidate tokens
            security_context.lock_service().release_lock_with_token_cleanup(&active_lock)?;
        }
    }
    
    // Step 3: Invalidate all voter tokens
    let logout_result = security_context.lock_service().logout_voter(
        voter_hash, 
        election_id
    )?;
    
    // Step 4: Log logout event
    let logout_event = SecurityEvent::LoginAttempt {
        voter_hash: voter_hash.to_string(),
        election_id: *election_id,
        session_id: Some(session_id.to_string()),
        success: false, // false = logout event
        timestamp: current_timestamp(),
        ip_address: None,
    };
    
    security_context.audit_system().log_security_event(
        logout_event,
        Some(ComplianceLevel::Standard),
        Some(session_id.to_string())
    ).await?;
    
    Ok(logout_result)
}
```

## Data Structures

### Core Types

```rust
#[derive(Debug, Clone)]
pub struct LoginResult {
    pub voter_hash: String,
    pub voting_token: VotingToken,
    pub session_id: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct VotingAuthorization {
    pub voting_lock: VoterLock,
    pub session_key: SecureKeyPair,
    pub voter_hash: String,
    pub election_id: Uuid,
    pub authorized_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotePackage {
    pub vote_id: Uuid,
    pub voter_hash: String,
    pub election_id: Uuid,
    pub vote_data: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct VotingResult {
    pub vote_id: Uuid,
    pub completion: VotingCompletion,
    pub vote_receipt: VoteReceipt,
    pub completed_at: u64,
}
```

### Status Checking

```rust
// Check voter eligibility
async fn check_voter_eligibility(
    security_context: &SecurityContext,
    voter_hash: &str,
    election_id: &Uuid
) -> Result<VoterEligibility, VotingError> {
    
    let voting_status = security_context.lock_service().get_voting_status(
        voter_hash, 
        election_id
    )?;
    
    let eligibility = VoterEligibility {
        can_vote: voting_status.can_vote(),
        blocking_reason: voting_status.blocking_reason(),
        has_active_session: voting_status.active_lock.is_some(),
        has_completed_voting: voting_status.completion.is_some(),
        active_tokens: voting_status.active_tokens.len(),
    };
    
    Ok(eligibility)
}

#[derive(Debug, Clone)]
pub struct VoterEligibility {
    pub can_vote: bool,
    pub blocking_reason: Option<String>,
    pub has_active_session: bool,
    pub has_completed_voting: bool,
    pub active_tokens: usize,
}
```

## Error Handling

### Workflow-Specific Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum VotingWorkflowError {
    #[error("Authentication required: {0}")]
    AuthenticationRequired(String),
    
    #[error("Voting already in progress: {remaining_seconds}s remaining")]
    VotingInProgress {
        remaining_seconds: u64,
        method: VotingMethod,
    },
    
    #[error("Already voted at {completed_at} via {method:?}")]
    AlreadyVoted {
        completed_at: u64,
        method: VotingMethod,
    },
    
    #[error("Authorization expired - please login again")]
    AuthorizationExpired,
    
    #[error("Vote processing failed: {0}")]
    VoteProcessingFailed(String),
}

// Error handling in workflow
async fn handle_voting_error(error: VotingWorkflowError) -> HttpResponse {
    match error {
        VotingWorkflowError::AuthenticationRequired(reason) => {
            // Redirect to login
            HttpResponse::Unauthorized().json(json!({
                "error": "authentication_required",
                "reason": reason,
                "action": "redirect_to_login"
            }))
        }
        
        VotingWorkflowError::VotingInProgress { remaining_seconds, method } => {
            // Show voting in progress page
            HttpResponse::Conflict().json(json!({
                "error": "voting_in_progress",
                "remaining_seconds": remaining_seconds,
                "method": method,
                "action": "show_voting_page"
            }))
        }
        
        VotingWorkflowError::AlreadyVoted { completed_at, method } => {
            // Show vote confirmation
            HttpResponse::Ok().json(json!({
                "status": "already_voted",
                "completed_at": completed_at,
                "method": method,
                "action": "show_confirmation"
            }))
        }
        
        _ => {
            // Generic error response
            HttpResponse::InternalServerError().json(json!({
                "error": "voting_system_error",
                "action": "contact_support"
            }))
        }
    }
}
```

## Integration Patterns

### Web Framework Integration

```rust
// Axum/Warp integration example
use axum::{extract::State, http::StatusCode, Json, response::Json as ResponseJson};

#[derive(Clone)]
struct AppState {
    security_context: Arc<SecurityContext>,
}

// Login endpoint
async fn login_voter(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>
) -> Result<ResponseJson<LoginResponse>, StatusCode> {
    
    let login_result = secure_voter_login(
        &state.security_context,
        &request.bank_customer_id,
        &request.election_id,
        &request.session_id
    ).await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    Ok(ResponseJson(LoginResponse {
        voter_hash: login_result.voter_hash,
        token_id: login_result.voting_token.token_id,
        expires_at: login_result.expires_at,
    }))
}

// Vote endpoint
async fn submit_vote(
    State(state): State<AppState>,
    Json(request): Json<VoteRequest>
) -> Result<ResponseJson<VoteResponse>, StatusCode> {
    
    // Reconstruct authorization from request
    let authorization = reconstruct_authorization(&state.security_context, &request)
        .await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    let voting_result = conduct_secure_voting(
        &state.security_context,
        authorization,
        &request.vote_data
    ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    Ok(ResponseJson(VoteResponse {
        vote_id: voting_result.vote_id,
        completion_id: voting_result.completion.completion_id,
        receipt: voting_result.vote_receipt,
    }))
}
```

### Database Integration

```rust
// Database layer integration
async fn store_voting_result(
    db: &Database,
    voting_result: &VotingResult
) -> Result<(), DatabaseError> {
    
    let mut tx = db.begin().await?;
    
    // Store vote record
    sqlx::query!(
        "INSERT INTO votes (vote_id, voter_hash, election_id, completed_at) 
         VALUES ($1, $2, $3, $4)",
        voting_result.vote_id,
        voting_result.completion.voter_hash,
        voting_result.completion.election_id,
        voting_result.completed_at as i64
    ).execute(&mut tx).await?;
    
    // Store completion record
    sqlx::query!(
        "INSERT INTO voting_completions (completion_id, vote_id, method, timestamp)
         VALUES ($1, $2, $3, $4)",
        voting_result.completion.completion_id,
        voting_result.vote_id,
        format!("{:?}", voting_result.completion.method),
        voting_result.completion.completed_at as i64
    ).execute(&mut tx).await?;
    
    tx.commit().await?;
    Ok(())
}
```

## Security Monitoring Integration

### Real-time Monitoring

```rust
async fn monitor_voting_workflow(
    security_context: &SecurityContext,
    performance_monitor: &SecurityPerformanceMonitor
) -> Result<(), MonitoringError> {
    
    // Monitor timing for security operations
    let timer = SecurityTimer::start(
        SecurityOperation::VotingLockAcquisition,
        SecurityTimingContext {
            voter_hash: Some("monitoring_voter".to_string()),
            election_id: Some(Uuid::new_v4()),
            ..Default::default()
        }
    );
    
    // Perform operation
    let result = some_voting_operation().await;
    
    // Record timing and analyze threats
    let threat_assessment = timer.finish(result.is_ok(), performance_monitor).await?;
    
    if threat_assessment.threat_level != ThreatLevel::None {
        // Alert security team
        alert_security_team(&threat_assessment).await?;
    }
    
    Ok(())
}
```

## Testing Support

### Workflow Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_complete_voting_workflow() {
        let security_context = SecurityContext::for_testing();
        let bank_customer_id = "test_customer_123";
        let election_id = Uuid::new_v4();
        let session_id = "test_session_456";
        
        // Test login
        let login_result = secure_voter_login(
            &security_context,
            bank_customer_id,
            &election_id,
            session_id
        ).await.unwrap();
        
        assert!(!login_result.voter_hash.is_empty());
        assert!(!login_result.voting_token.token_id.is_empty());
        
        // Test authorization
        let authorization = acquire_voting_authorization(
            &security_context,
            &login_result,
            VotingMethod::Digital
        ).await.unwrap();
        
        assert_eq!(authorization.election_id, election_id);
        
        // Test voting
        let vote_data = b"test_vote_data";
        let voting_result = conduct_secure_voting(
            &security_context,
            authorization,
            vote_data
        ).await.unwrap();
        
        assert!(voting_result.vote_id != Uuid::nil());
        
        // Test logout
        let logout_result = secure_voter_logout(
            &security_context,
            &login_result.voter_hash,
            &election_id,
            session_id
        ).await.unwrap();
        
        assert!(logout_result.invalidated_tokens > 0);
    }
}
```

---

[//]: # (**Workflow Version:** v0.1.0  )

[//]: # (**Security Compliance:** Banking-grade  )

[//]: # (**Last Updated:** August 2025)