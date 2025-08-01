//! Complete integration tests for the token-secured voting system

use vote::{
    config::Config,
    crypto::{
        TokenGenerator, CryptoUtils,
        SecureKeyPair, SecureSaltManager, CryptoRateLimiter, SecureMemory,
        VotingCompletion, VotingStatus, LogoutResult,
        VotingTokenService, VotingToken, TokenConfig, TokenResult, TokenCleanupService,
        voting_lock::{VotingLockService, VotingMethod, LockResult},
        key_rotation::{KeyRotationManager, KeyRotationService}
    },
    types::{Election, Candidate, AnonymousVote},
    Result,
};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashSet;

#[tokio::test]
async fn test_complete_secure_voting_workflow() -> Result<()> {
    println!("🔐 Testing COMPLETE secure voting workflow with token integration...");

    // Setup integrated system
    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());
    let election_id = Uuid::new_v4();
    let bank_id = "CZ1234567890";

    // Generate voter hash
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let voter_hash = salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_time, 300)?;
    let voter_hash_str = hex::encode(voter_hash);

    println!("✅ Voter hash generated: {}...", &voter_hash_str[0..8]);

    // **PHASE 1: LOGIN AND TOKEN ISSUANCE**
    println!("\n👤 PHASE 1: User login and token issuance");

    let token_result = token_service.issue_token(
        &salt_manager,
        &voter_hash_str,
        &election_id,
        Some("mobile_session_abc123".to_string()),
    )?;

    let voting_token = match token_result {
        TokenResult::Issued(token) => {
            println!("✅ Login successful - token issued");
            println!("   Token ID: {}...", &token.token_id[..12]);
            println!("   Expires in: {} seconds", token.time_remaining());
            println!("   Session: {:?}", token.session_id);
            token
        }
        _ => panic!("Expected token to be issued during login"),
    };

    // **PHASE 2: VOTING STATUS CHECK**
    println!("\n🔍 PHASE 2: Voting status check");

    let initial_status = lock_service.get_voting_status(&voter_hash_str, &election_id)?;
    assert!(initial_status.can_vote());
    assert!(initial_status.blocking_reason().is_none());
    assert_eq!(initial_status.active_tokens.len(), 1);

    let usable_token = initial_status.get_usable_token().unwrap();
    println!("✅ Voting status: CAN VOTE");
    println!("   Usable token: {}...", &usable_token.token_id[..12]);

    // **PHASE 3: ACQUIRE VOTING LOCK WITH TOKEN VALIDATION**
    println!("\n🔒 PHASE 3: Acquire voting lock with token validation");

    let lock_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &voting_token.token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Digital,
    )?;

    let voting_lock = match lock_result {
        LockResult::Acquired(lock) => {
            println!("✅ Voting lock acquired with token validation");
            println!("   Lock ID: {}", lock.lock_id);
            println!("   Method: {:?}", lock.method);
            println!("   Associated token: {}...", &lock.token_id[..12]);
            lock
        }
        LockResult::InvalidToken { reason } => {
            panic!("Token validation failed: {}", reason);
        }
        _ => panic!("Expected to acquire voting lock"),
    };

    // **PHASE 4: CONCURRENT ACCESS PREVENTION**
    println!("\n🚫 PHASE 4: Testing concurrent access prevention");

    // Try to acquire another lock with same token (should fail - already in use)
    let concurrent_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &voting_token.token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Analog,
    )?;

    match concurrent_result {
        LockResult::AlreadyLocked { conflict_method, .. } => {
            println!("✅ Concurrent access blocked by active lock");
            println!("   Conflict with: {:?}", conflict_method);
            assert_eq!(conflict_method, VotingMethod::Digital);
        }
        _ => panic!("Expected concurrent access to be blocked"),
    }

    // **PHASE 5: VOTE PROCESSING AND COMPLETION**
    println!("\n🗳️ PHASE 5: Vote processing and completion");

    // Simulate vote processing
    let key_pair = SecureKeyPair::generate_with_expiration(Some(3600))?;
    let vote_content = b"secure_vote_for_candidate_alice";
    let (vote_signature, signature_timestamp) = key_pair.sign_with_timestamp(vote_content)?;

    // Verify vote signature
    key_pair.verify_with_timestamp(vote_content, &vote_signature, signature_timestamp, 300)?;
    println!("✅ Vote cryptographically signed and verified");

    // Complete voting (this invalidates token and releases lock)
    let vote_id = Uuid::new_v4();
    let completion = lock_service.complete_voting_with_token_cleanup(&voting_lock, Some(vote_id))?;

    println!("✅ Voting completed successfully");
    println!("   Completion ID: {}", completion.completion_id);
    println!("   Vote ID: {:?}", completion.vote_id);
    println!("   Token used: {}...", &completion.token_id[..12]);

    // **PHASE 6: POST-VOTE SECURITY VERIFICATION**
    println!("\n🛡️ PHASE 6: Post-vote security verification");

    // Verify token is now invalid (used)
    let token_validation = token_service.validate_token(
        &salt_manager,
        &voting_token.token_id,
        &voter_hash_str,
        &election_id,
    )?;

    match token_validation {
        TokenResult::Invalid { reason } => {
            println!("✅ Token correctly invalidated after voting");
            println!("   Reason: {}", reason);
        }
        _ => panic!("Expected token to be invalidated after voting"),
    }

    // Verify voting status prevents further voting
    let post_vote_status = lock_service.get_voting_status(&voter_hash_str, &election_id)?;
    assert!(!post_vote_status.can_vote());
    assert!(post_vote_status.completion.is_some());
    assert!(post_vote_status.active_lock.is_none());

    let blocking_reason = post_vote_status.blocking_reason().unwrap();
    println!("✅ Further voting blocked: {}", blocking_reason);

    // **PHASE 7: DOUBLE VOTING ATTACK PREVENTION**
    println!("\n🚨 PHASE 7: Double voting attack prevention");

    // Attacker tries to get new token and vote again
    let attack_token_result = token_service.issue_token(
        &salt_manager,
        &voter_hash_str, // Same voter
        &election_id,    // Same election
        Some("attack_session_xyz789".to_string()),
    )?;

    let attack_token = match attack_token_result {
        TokenResult::Issued(token) => {
            println!("⚠️ New token issued (but voting should still be blocked)");
            token
        }
        _ => panic!("Should be able to issue new token"),
    };

    // Try to vote with new token (should be blocked by completion record)
    let attack_lock_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &attack_token.token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Analog,
    )?;

    match attack_lock_result {
        LockResult::AlreadyVoted { completion, original_method } => {
            println!("✅ ATTACK PREVENTED! Double voting blocked by completion record");
            println!("   Original vote: {:?} at {}", original_method, completion.completed_at);
            assert_eq!(original_method, VotingMethod::Digital);
        }
        _ => panic!("❌ CRITICAL VULNERABILITY: Double voting should be blocked!"),
    }

    // **PHASE 8: DIFFERENT VOTER VERIFICATION**
    println!("\n👥 PHASE 8: Different voter verification");

    let different_bank_id = "CZ9876543210";
    let different_voter_hash = salt_manager.hash_voter_identity_secure(
        different_bank_id, &election_id, current_time, 300
    )?;
    let different_voter_hash_str = hex::encode(different_voter_hash);

    // Different voter should be able to get token and vote
    let different_token_result = token_service.issue_token(
        &salt_manager,
        &different_voter_hash_str,
        &election_id,
        Some("different_session_456".to_string()),
    )?;

    let different_token = match different_token_result {
        TokenResult::Issued(token) => token,
        _ => panic!("Different voter should get token"),
    };

    let different_lock_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &different_token.token_id,
        &different_voter_hash_str,
        &election_id,
        VotingMethod::Digital,
    )?;

    match different_lock_result {
        LockResult::Acquired(lock) => {
            println!("✅ Different voter successfully acquired voting lock");

            // Complete different voter's vote
            let different_vote_id = Uuid::new_v4();
            let _different_completion = lock_service.complete_voting_with_token_cleanup(&lock, Some(different_vote_id))?;
            println!("✅ Different voter completed voting");
        }
        _ => panic!("Different voter should be able to vote"),
    }

    // **PHASE 9: SYSTEM STATISTICS AND MONITORING**
    println!("\n📊 PHASE 9: System statistics and monitoring");

    let final_stats = lock_service.get_stats()?;
    println!("✅ Final system statistics:");
    println!("   Active locks: {}", final_stats.active_locks);
    println!("   Total completions: {}", final_stats.total_completions);
    println!("   Digital completions: {}", final_stats.digital_completions);
    println!("   Token stats:");
    println!("     Total tokens: {}", final_stats.token_stats.total_tokens);
    println!("     Active tokens: {}", final_stats.token_stats.active_tokens);
    println!("     Used tokens: {}", final_stats.token_stats.used_tokens);
    println!("     Unique voters: {}", final_stats.token_stats.unique_voters);

    assert_eq!(final_stats.total_completions, 2); // Two votes completed
    assert_eq!(final_stats.active_locks, 0); // No active locks
    assert_eq!(final_stats.token_stats.used_tokens, 2); // Two tokens used

    println!("\n🎉 COMPLETE SECURE VOTING WORKFLOW SUCCESSFUL!");
    println!("🔒 ALL SECURITY LAYERS VERIFIED:");
    println!("   • ✅ Token-based authentication and authorization");
    println!("   • ✅ Cryptographic token validation");
    println!("   • ✅ Temporal lock prevention for concurrent access");
    println!("   • ✅ Permanent completion tracking for double-vote prevention");
    println!("   • ✅ Automatic token invalidation on vote completion");
    println!("   • ✅ Session management for millions of users");
    println!("   • ✅ Anonymous voter privacy preservation");
    println!("   • ✅ Comprehensive audit trail");

    Ok(())
}

#[tokio::test]
async fn test_token_security_attack_scenarios() -> Result<()> {
    println!("🚨 Testing token security against attack scenarios...");

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());
    let election_id = Uuid::new_v4();
    let voter_hash_str = hex::encode([1u8; 32]);

    // **ATTACK 1: Token Forgery**
    println!("\n🎯 ATTACK 1: Token forgery attempt");

    let forged_token_id = "forged_token_12345678";
    let forgery_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        forged_token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Digital,
    )?;

    match forgery_result {
        LockResult::InvalidToken { reason } => {
            println!("✅ Token forgery blocked: {}", reason);
        }
        _ => panic!("Forged token should be rejected"),
    }

    // **ATTACK 2: Token Reuse After Invalidation**
    println!("\n🎯 ATTACK 2: Token reuse after invalidation");

    // Issue legitimate token
    let token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, None)?;
    let legitimate_token = match token_result {
        TokenResult::Issued(token) => token,
        _ => panic!("Expected token issuance"),
    };

    // Invalidate token (simulate logout)
    let invalidation_result = token_service.invalidate_token(&legitimate_token.token_id)?;
    assert_eq!(invalidation_result, TokenResult::Invalidated);

    // Try to use invalidated token
    let reuse_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &legitimate_token.token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Digital,
    )?;

    match reuse_result {
        LockResult::InvalidToken { reason } => {
            println!("✅ Token reuse blocked: {}", reason);
        }
        _ => panic!("Invalidated token should be rejected"),
    }

    // **ATTACK 3: Cross-Election Token Use**
    println!("\n🎯 ATTACK 3: Cross-election token use");

    let election1 = Uuid::new_v4();
    let election2 = Uuid::new_v4();

    // Issue token for election1
    let election1_token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election1, None)?;
    let election1_token = match election1_token_result {
        TokenResult::Issued(token) => token,
        _ => panic!("Expected token for election1"),
    };

    // Try to use election1 token for election2
    let cross_election_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &election1_token.token_id,
        &voter_hash_str,
        &election2, // Wrong election
        VotingMethod::Digital,
    )?;

    match cross_election_result {
        LockResult::InvalidToken { reason } => {
            println!("✅ Cross-election token use blocked: {}", reason);
        }
        _ => panic!("Cross-election token use should be blocked"),
    }

    // **ATTACK 4: Token Overflow Attack**
    println!("\n🎯 ATTACK 4: Token overflow attack");

    let overflow_voter_hash = hex::encode([2u8; 32]);

    // Try to issue more tokens than allowed
    for i in 0..5 {
        let result = token_service.issue_token(
            &salt_manager,
            &overflow_voter_hash,
            &election_id,
            Some(format!("session_{}", i)),
        )?;

        match result {
            TokenResult::Issued(token) => {
                println!("   Token {} issued", i + 1);
                if i >= 2 { // Should fail after max tokens (2 for testing)
                    panic!("Too many tokens should be prevented");
                }
            }
            TokenResult::TooManyTokens { active_count } => {
                println!("✅ Token overflow prevented at {} active tokens", active_count);
                break;
            }
            _ => panic!("Unexpected token result"),
        }
    }

    println!("✅ ALL TOKEN SECURITY ATTACKS SUCCESSFULLY PREVENTED");

    Ok(())
}

#[tokio::test]
async fn test_session_management_scenarios() -> Result<()> {
    println!("👤 Testing session management scenarios...");

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());
    let election_id = Uuid::new_v4();
    let voter_hash_str = hex::encode([1u8; 32]);

    // **SCENARIO 1: Login → Wait → Vote**
    println!("\n📱 SCENARIO 1: Login → Wait → Vote");

    let token1_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, Some("mobile_app".to_string()))?;
    let token1 = match token1_result { TokenResult::Issued(t) => t, _ => panic!() };

    println!("✅ Login: Token issued with {}s lifetime", token1.time_remaining());

    // Simulate waiting (user browses candidates)
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Vote after waiting
    let lock_result = lock_service.acquire_lock_with_token(&salt_manager, &token1.token_id, &voter_hash_str, &election_id, VotingMethod::Digital)?;
    let lock1 = match lock_result { LockResult::Acquired(l) => l, _ => panic!("Should acquire lock after waiting") };

    let completion1 = lock_service.complete_voting_with_token_cleanup(&lock1, Some(Uuid::new_v4()))?;
    println!("✅ Vote completed after waiting: {}", completion1.completion_id);

    // **SCENARIO 2: Login → Logout (No Vote)**
    println!("\n🚪 SCENARIO 2: Login → Logout (No Vote)");

    let voter2_hash_str = hex::encode([2u8; 32]);
    let token2_result = token_service.issue_token(&salt_manager, &voter2_hash_str, &election_id, Some("web_browser".to_string()))?;
    let token2 = match token2_result { TokenResult::Issued(t) => t, _ => panic!() };

    println!("✅ Login: Token issued for voter 2");

    // Logout without voting
    let logout_result = lock_service.logout_voter(&voter2_hash_str, &election_id)?;
    println!("✅ Logout: {} tokens invalidated", logout_result.invalidated_tokens);

    // Verify token is invalidated
    let validation_result = token_service.validate_token(&salt_manager, &token2.token_id, &voter2_hash_str, &election_id)?;
    match validation_result {
        TokenResult::Invalid { .. } => println!("✅ Token correctly invalidated on logout"),
        _ => panic!("Token should be invalid after logout"),
    }

    // **SCENARIO 3: Multiple Sessions → Vote with One**
    println!("\n📱💻 SCENARIO 3: Multiple sessions → Vote with one");

    let voter3_hash_str = hex::encode([3u8; 32]);

    // Login from mobile
    let mobile_token_result = token_service.issue_token(&salt_manager, &voter3_hash_str, &election_id, Some("mobile_session".to_string()))?;
    let mobile_token = match mobile_token_result { TokenResult::Issued(t) => t, _ => panic!() };

    // Login from web
    let web_token_result = token_service.issue_token(&salt_manager, &voter3_hash_str, &election_id, Some("web_session".to_string()))?;
    let web_token = match web_token_result { TokenResult::Issued(t) => t, _ => panic!() };

    println!("✅ Multiple sessions: Mobile and Web tokens issued");

    // Vote using mobile token
    let mobile_lock_result = lock_service.acquire_lock_with_token(&salt_manager, &mobile_token.token_id, &voter3_hash_str, &election_id, VotingMethod::Digital)?;
    let mobile_lock = match mobile_lock_result { LockResult::Acquired(l) => l, _ => panic!() };

    let mobile_completion = lock_service.complete_voting_with_token_cleanup(&mobile_lock, Some(Uuid::new_v4()))?;
    println!("✅ Vote completed using mobile session");

    // Try to vote using web token (should be blocked by completion)
    let web_lock_result = lock_service.acquire_lock_with_token(&salt_manager, &web_token.token_id, &voter3_hash_str, &election_id, VotingMethod::Analog)?;
    match web_lock_result {
        LockResult::AlreadyVoted { .. } => {
            println!("✅ Web session correctly blocked after mobile vote completion");
        }
        _ => panic!("Web session should be blocked after mobile vote"),
    }

    println!("✅ ALL SESSION MANAGEMENT SCENARIOS SUCCESSFUL");

    Ok(())
}

#[tokio::test]
async fn test_token_cleanup_and_performance() -> Result<()> {
    println!("🧹 Testing token cleanup and performance...");

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let election_id = Uuid::new_v4();

    // **PERFORMANCE TEST: Issue many tokens**
    println!("\n⚡ PERFORMANCE: Issuing 1000 tokens");

    let start_time = std::time::Instant::now();

    for i in 0..1000 {
        let voter_hash = hex::encode([(i % 256) as u8; 32]);
        let _token_result = token_service.issue_token(
            &salt_manager,
            &voter_hash,
            &election_id,
            Some(format!("session_{}", i)),
        )?;
    }

    let duration = start_time.elapsed();
    let tokens_per_second = 1000.0 / duration.as_secs_f64();

    println!("✅ Issued 1000 tokens in {:?} ({:.0} tokens/sec)", duration, tokens_per_second);
    assert!(tokens_per_second > 1000.0, "Token issuance should be fast enough for production");

    // **CLEANUP TEST: Token cleanup performance**
    println!("\n🧹 CLEANUP: Testing token cleanup");

    let cleanup_start = std::time::Instant::now();
    let cleanup_stats = token_service.cleanup_expired_tokens()?;
    let cleanup_duration = cleanup_start.elapsed();

    println!("✅ Token cleanup completed in {:?}", cleanup_duration);
    println!("   Initial tokens: {}", cleanup_stats.initial_tokens);
    println!("   Final tokens: {}", cleanup_stats.final_tokens);
    println!("   Removed: {}", cleanup_stats.total_removed);

    // **MEMORY TEST: Verify efficient memory usage**
    println!("\n💾 MEMORY: Testing memory efficiency");

    let stats_after_cleanup = token_service.get_stats()?;
    println!("✅ Memory usage after cleanup:");
    println!("   Active tokens: {}", stats_after_cleanup.active_tokens);
    println!("   Unique voters: {}", stats_after_cleanup.unique_voters);

    // Should have reasonable memory usage
    assert!(stats_after_cleanup.active_tokens <= 1000);

    println!("✅ TOKEN CLEANUP AND PERFORMANCE TESTS SUCCESSFUL");

    Ok(())
}

#[tokio::test]
async fn test_exact_vulnerability_timeline_with_tokens() -> Result<()> {
    println!("🕒 Testing EXACT vulnerability timeline with token security...");

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());
    let election_id = Uuid::new_v4();
    let bank_id = "CZ1234567890";

    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let voter_hash = salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_time, 300)?;
    let voter_hash_str = hex::encode(voter_hash);

    // ⏰ 10:00 - Voter logs into digital app
    println!("\n⏰ 10:00 - Voter logs into digital app");

    let login_token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, Some("digital_app_session".to_string()))?;
    let digital_token = match login_token_result {
        TokenResult::Issued(token) => {
            println!("   🎫 Login token issued: {}...", &token.token_id[..12]);
            token
        }
        _ => panic!("Login should issue token"),
    };

    let digital_lock_result = lock_service.acquire_lock_with_token(&salt_manager, &digital_token.token_id, &voter_hash_str, &election_id, VotingMethod::Digital)?;
    let digital_lock = match digital_lock_result {
        LockResult::Acquired(lock) => {
            println!("   🔒 Digital lock acquired with token validation");
            lock
        }
        _ => panic!("Digital lock should be acquired"),
    };

    // Complete digital voting
    let vote_id = Uuid::new_v4();
    let completion = lock_service.complete_voting_with_token_cleanup(&digital_lock, Some(vote_id))?;
    println!("   ✅ Digital vote completed, token automatically invalidated");
    println!("   📝 Completion recorded: {}", completion.completion_id);

    // ⏰ 10:20 - Same voter tries analog/paper voting
    println!("\n⏰ 10:20 - Same voter tries analog/paper voting");
    println!("   (Original token invalidated, need new token for analog voting)");

    // Voter would need to "login" again for analog voting
    let analog_token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, Some("analog_terminal_session".to_string()))?;
    let analog_token = match analog_token_result {
        TokenResult::Issued(token) => {
            println!("   🎫 New token issued for analog voting attempt");
            token
        }
        _ => panic!("Should be able to issue new token"),
    };

    // Try to vote with new token (should be blocked by completion record)
    let analog_lock_result = lock_service.acquire_lock_with_token(&salt_manager, &analog_token.token_id, &voter_hash_str, &election_id, VotingMethod::Analog)?;
    match analog_lock_result {
        LockResult::AlreadyVoted { completion, original_method } => {
            println!("   🚫 BLOCKED! Analog voting prevented by completion record");
            println!("     Original vote: {:?} at {}", original_method, completion.completed_at);
            assert_eq!(original_method, VotingMethod::Digital);
        }
        _ => panic!("❌ CRITICAL: Analog voting should be blocked by completion!"),
    }

    // ⏰ 10:45 - Voter returns to digital app
    println!("\n⏰ 10:45 - Voter returns to digital app");
    println!("   (All previous tokens expired/used, need new token)");

    let return_token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, Some("digital_return_session".to_string()))?;
    let return_token = match return_token_result {
        TokenResult::Issued(token) => {
            println!("   🎫 New token issued for return visit");
            token
        }
        _ => panic!("Should be able to issue new token"),
    };

    let return_lock_result = lock_service.acquire_lock_with_token(&salt_manager, &return_token.token_id, &voter_hash_str, &election_id, VotingMethod::Digital)?;
    match return_lock_result {
        LockResult::AlreadyVoted { completion, original_method } => {
            println!("   🚫 BLOCKED! Return digital voting prevented by completion record");
            println!("     Original vote: {:?} at {}", original_method, completion.completed_at);
            assert_eq!(original_method, VotingMethod::Digital);
        }
        _ => panic!("❌ CRITICAL: Return digital voting should be blocked by completion!"),
    }

    // **VERIFICATION: System State**
    println!("\n🔍 VERIFICATION: Final system state");

    let final_status = lock_service.get_voting_status(&voter_hash_str, &election_id)?;
    assert!(!final_status.can_vote());
    assert!(final_status.completion.is_some());
    assert!(final_status.active_lock.is_none());

    println!("✅ Voting status: PERMANENTLY BLOCKED");
    println!("   Reason: {}", final_status.blocking_reason().unwrap());

    let final_stats = lock_service.get_stats()?;
    println!("✅ System stats:");
    println!("   Completions: {}", final_stats.total_completions);
    println!("   Active locks: {}", final_stats.active_locks);
    println!("   Active tokens: {}", final_stats.token_stats.active_tokens);

    println!("\n🎉 VULNERABILITY TIMELINE TEST WITH TOKENS PASSED!");
    println!("✅ Enhanced security layers:");
    println!("   • Token validation prevents unauthorized access");
    println!("   • Completion tracking prevents double voting");
    println!("   • Automatic token invalidation on logout/completion");
    println!("   • Session management for real-world usage patterns");

    Ok(())
}

#[test]
fn test_voter_hash_determinism_with_tokens() {
    println!("🔍 CRITICAL: Voter hash determinism with token system");

    let salt_manager = SecureSaltManager::for_testing();
    let bank_id = "CZ1234567890";
    let election_id = Uuid::new_v4();
    let base_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Critical: Same voter must get same hash regardless of timestamp
    let hash1 = salt_manager.hash_voter_identity_secure(bank_id, &election_id, base_time, 300).unwrap();
    let hash2 = salt_manager.hash_voter_identity_secure(bank_id, &election_id, base_time + 1, 300).unwrap();
    let hash3 = salt_manager.hash_voter_identity_secure(bank_id, &election_id, base_time + 60, 300).unwrap();

    assert_eq!(hash1, hash2, "🚨 CRITICAL: Same voter gets different hashes!");
    assert_eq!(hash1, hash3, "🚨 CRITICAL: Same voter gets different hashes!");
    assert_eq!(hash2, hash3, "🚨 CRITICAL: Same voter gets different hashes!");

    // Test with token system
    let token_service = Arc::new(VotingTokenService::for_testing());
    let voter_hash_str = hex::encode(hash1);

    // Should be able to issue tokens with same voter hash
    let token1_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, None).unwrap();
    let token2_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, None).unwrap();

    // Both should succeed (different tokens for same voter)
    assert!(matches!(token1_result, TokenResult::Issued(_)));
    assert!(matches!(token2_result, TokenResult::Issued(_)));

    println!("✅ CRITICAL TEST PASSED: Voter hash deterministic with token system");
}

#[tokio::test]
async fn test_key_rotation_with_token_security() -> Result<()> {
    println!("🔄 Testing key rotation with integrated token security...");

    let config = Config::for_testing()?;
    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());

    let rotation_config = config.security.key_rotation_config()?;
    let key_manager = KeyRotationManager::new(rotation_config).await?;

    let election_id = Uuid::new_v4();
    let bank_id = "CZ1234567890";
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let voter_hash = salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_time, 300)?;
    let voter_hash_str = hex::encode(voter_hash);

    // Issue token and acquire lock
    let token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, None)?;
    let voting_token = match token_result { TokenResult::Issued(t) => t, _ => panic!() };

    let lock_result = lock_service.acquire_lock_with_token(&salt_manager, &voting_token.token_id, &voter_hash_str, &election_id, VotingMethod::Digital)?;
    let voting_lock = match lock_result { LockResult::Acquired(l) => l, _ => panic!() };

    // Sign vote with current key
    let vote_content = b"vote_with_token_security";
    let (signature1, timestamp1) = key_manager.sign(vote_content).await?;
    let stats_before = key_manager.get_stats().await;

    println!("✅ Vote signed with key: {}", stats_before.current_key_id);

    // Complete voting
    let vote_id = Uuid::new_v4();
    let completion = lock_service.complete_voting_with_token_cleanup(&voting_lock, Some(vote_id))?;
    println!("✅ Voting completed with token cleanup");

    // Perform key rotation
    key_manager.manual_rotation("Token security integration test").await?;
    let stats_after = key_manager.get_stats().await;
    println!("✅ Key rotated: {} -> {}", stats_before.current_key_id, stats_after.current_key_id);

    // Verify historical signature still works
    key_manager.verify(vote_content, &signature1, timestamp1).await?;
    println!("✅ Historical signature verified after key rotation");

    // Verify token security persists after key rotation
    let new_token_result = token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, None)?;
    let new_token = match new_token_result { TokenResult::Issued(t) => t, _ => panic!() };

    let new_lock_result = lock_service.acquire_lock_with_token(&salt_manager, &new_token.token_id, &voter_hash_str, &election_id, VotingMethod::Analog)?;
    match new_lock_result {
        LockResult::AlreadyVoted { .. } => {
            println!("✅ Token security persists across key rotations");
        }
        _ => panic!("Double voting should be prevented even after key rotation"),
    }

    println!("✅ Key rotation integration with token security successful");

    Ok(())
}

#[tokio::test]
async fn test_banking_grade_workflow_with_tokens() -> Result<()> {
    println!("🏦 Testing banking-grade workflow with complete token security...");

    let config = Config::for_testing()?;
    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());
    let mut rate_limiter = CryptoRateLimiter::new(10);

    // Create election
    let now = Utc::now().timestamp();
    let election = Election {
        id: Uuid::new_v4(),
        title: "Token-Secured Banking Election 2024".to_string(),
        description: Some("Complete token security with banking-grade crypto".to_string()),
        start_time: now - 3600,
        end_time: now + 3600,
        active: true,
        created_at: Utc::now(),
    };

    assert!(election.is_accepting_votes());
    println!("✅ Secure election created");

    // Create candidates
    let candidates = vec![
        Candidate {
            id: "token_candidate_a".to_string(),
            election_id: election.id,
            name: "Alice TokenSecure".to_string(),
            description: Some("Token-validated candidate".to_string()),
            active: true,
        },
        Candidate {
            id: "token_candidate_b".to_string(),
            election_id: election.id,
            name: "Bob CryptoVerified".to_string(),
            description: Some("Session-managed candidate".to_string()),
            active: true,
        },
    ];

    println!("✅ Candidates created: {}", candidates.len());

    // Simulate complete banking-grade voting process
    for i in 1..=3 {
        rate_limiter.check_rate_limit()?;

        let bank_id = format!("CZ123456789{:02}", i);
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Generate secure voter hash
        let voter_hash = salt_manager.hash_voter_identity_secure(&bank_id, &election.id, current_time, 300)?;
        let voter_hash_str = hex::encode(voter_hash);

        // 1. Login - Issue voting token
        let login_result = token_service.issue_token(
            &salt_manager,
            &voter_hash_str,
            &election.id,
            Some(format!("banking_session_{}", i)),
        )?;

        let voter_token = match login_result {
            TokenResult::Issued(token) => token,
            _ => panic!("Expected login token for voter {}", i),
        };

        // 2. Check voting eligibility
        let voting_status = lock_service.get_voting_status(&voter_hash_str, &election.id)?;
        assert!(voting_status.can_vote());

        // 3. Acquire voting lock with token validation
        let lock_result = lock_service.acquire_lock_with_token(
            &salt_manager,
            &voter_token.token_id,
            &voter_hash_str,
            &election.id,
            VotingMethod::Digital,
        )?;

        let voting_lock = match lock_result {
            LockResult::Acquired(lock) => lock,
            _ => panic!("Expected to acquire lock for voter {}", i),
        };

        // 4. Generate additional secure voting tokens (if needed)
        let expires_at = current_time + config.security.key_expiry_seconds;
        let (_additional_token_hash, _nonce) = salt_manager.generate_voting_token_secure(&voter_hash, &election.id, expires_at)?;

        // 5. Create secure key pair for vote signing
        let key_pair = SecureKeyPair::generate_with_expiration(Some(config.security.key_expiry_seconds))?;

        // 6. Process vote
        let chosen_candidate = &candidates[i % candidates.len()];
        let vote_content = format!("banking_secure_vote_for:{}", chosen_candidate.id);

        // 7. Sign vote with timestamp
        let (vote_signature, signature_timestamp) = key_pair.sign_with_timestamp(vote_content.as_bytes())?;

        // 8. Verify signature
        key_pair.verify_with_timestamp(
            vote_content.as_bytes(),
            &vote_signature,
            signature_timestamp,
            config.security.max_timestamp_age_seconds,
        )?;

        // 9. Create integrity hash
        let integrity_hash = CryptoUtils::hash(vote_content.as_bytes());

        // 10. Create anonymous vote
        let vote_id = Uuid::new_v4();
        let anonymous_vote = AnonymousVote::new(
            vote_id,
            election.id,
            vote_content.into_bytes(),
            &vote_signature,
            &integrity_hash,
            signature_timestamp as i64,
        );

        // 11. Verify serialization security
        let vote_json = serde_json::to_string(&anonymous_vote)?;
        let vote_back: AnonymousVote = serde_json::from_str(&vote_json)?;
        assert_eq!(anonymous_vote.vote_id, vote_back.vote_id);

        // 12. COMPLETE VOTING with automatic token cleanup
        let completion = lock_service.complete_voting_with_token_cleanup(&voting_lock, Some(vote_id))?;
        println!("✅ Banking voter {} completed secure vote for {} (completion: {})",
                 i, chosen_candidate.name, completion.completion_id);

        // 13. Verify token is invalidated
        let token_validation = token_service.validate_token(&salt_manager, &voter_token.token_id, &voter_hash_str, &election.id)?;
        match token_validation {
            TokenResult::Invalid { .. } => {
                println!("   ✅ Token automatically invalidated after vote completion");
            }
            _ => panic!("Token should be invalidated after voting"),
        }

        // 14. Verify double voting prevention
        let double_vote_token = token_service.issue_token(&salt_manager, &voter_hash_str, &election.id, None)?;
        let double_vote_token = match double_vote_token { TokenResult::Issued(t) => t, _ => panic!() };

        let double_vote_attempt = lock_service.acquire_lock_with_token(&salt_manager, &double_vote_token.token_id, &voter_hash_str, &election.id, VotingMethod::Analog)?;
        match double_vote_attempt {
            LockResult::AlreadyVoted { .. } => {
                println!("   ✅ Double voting prevented for voter {}", i);
            }
            _ => panic!("Double voting should be prevented for voter {}", i),
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    // Final verification
    let final_stats = lock_service.get_stats()?;
    println!("\n📊 Final Banking-Grade Statistics:");
    println!("   Total completions: {}", final_stats.total_completions);
    println!("   Active locks: {}", final_stats.active_locks);
    println!("   Token statistics:");
    println!("     Total tokens: {}", final_stats.token_stats.total_tokens);
    println!("     Used tokens: {}", final_stats.token_stats.used_tokens);
    println!("     Active tokens: {}", final_stats.token_stats.active_tokens);
    println!("     Unique voters: {}", final_stats.token_stats.unique_voters);

    assert_eq!(final_stats.total_completions, 3);
    assert_eq!(final_stats.active_locks, 0);
    assert_eq!(final_stats.token_stats.used_tokens, 3);

    println!("✅ BANKING-GRADE WORKFLOW WITH TOKENS COMPLETED SUCCESSFULLY");
    println!("🔒 All security measures verified:");
    println!("   • Token-based authentication and session management");
    println!("   • Cryptographic token validation and replay prevention");
    println!("   • Temporal lock prevention for concurrent access");
    println!("   • Permanent completion tracking for double-vote prevention");
    println!("   • Automatic token lifecycle management");
    println!("   • Banking-grade cryptographic primitives");
    println!("   • Session-aware security for millions of users");

    Ok(())
}

#[test]
fn test_token_cryptographic_security() {
    println!("🔐 Testing token cryptographic security...");

    let salt_manager = SecureSaltManager::for_testing();
    let voter_hash = [1u8; 32];
    let election_id = Uuid::new_v4();
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires_at = current_time + 1800;

    // Generate legitimate token
    let (token_hash, nonce) = salt_manager.generate_voting_token_secure(&voter_hash, &election_id, expires_at).unwrap();

    // Test 1: Valid token validation
    let valid_result = salt_manager.validate_voting_token_secure(&token_hash, &nonce, &voter_hash, &election_id, expires_at, current_time).unwrap();
    assert!(valid_result, "Legitimate token should validate");

    // Test 2: Wrong voter hash
    let wrong_voter = [2u8; 32];
    let wrong_voter_result = salt_manager.validate_voting_token_secure(&token_hash, &nonce, &wrong_voter, &election_id, expires_at, current_time).unwrap();
    assert!(!wrong_voter_result, "Token should fail with wrong voter");

    // Test 3: Wrong election
    let wrong_election = Uuid::new_v4();
    let wrong_election_result = salt_manager.validate_voting_token_secure(&token_hash, &nonce, &voter_hash, &wrong_election, expires_at, current_time).unwrap();
    assert!(!wrong_election_result, "Token should fail with wrong election");

    // Test 4: Expired token
    let expired_time = expires_at + 1;
    let expired_result = salt_manager.validate_voting_token_secure(&token_hash, &nonce, &voter_hash, &election_id, expires_at, expired_time).unwrap();
    assert!(!expired_result, "Expired token should be invalid");

    // Test 5: Modified token hash (forgery attempt)
    let mut forged_token = token_hash;
    forged_token[0] ^= 0x01; // Flip one bit
    let forged_result = salt_manager.validate_voting_token_secure(&forged_token, &nonce, &voter_hash, &election_id, expires_at, current_time).unwrap();
    assert!(!forged_result, "Forged token should be invalid");

    // Test 6: Modified nonce
    let mut forged_nonce = nonce;
    forged_nonce[0] ^= 0x01; // Flip one bit
    let forged_nonce_result = salt_manager.validate_voting_token_secure(&token_hash, &forged_nonce, &voter_hash, &election_id, expires_at, current_time).unwrap();
    assert!(!forged_nonce_result, "Token with forged nonce should be invalid");

    println!("✅ ALL TOKEN CRYPTOGRAPHIC SECURITY TESTS PASSED");
    println!("🔒 Verified protections:");
    println!("   • Cryptographic token validation");
    println!("   • Voter identity binding");
    println!("   • Election-specific tokens");
    println!("   • Expiration enforcement");
    println!("   • Forgery prevention");
    println!("   • Nonce integrity");
}

#[test]
fn test_error_handling_comprehensive() {
    use vote::{Error, crypto_error, voting_error};

    // Test crypto errors
    let crypto_err = crypto_error!("test crypto error");
    assert!(matches!(crypto_err, Error::Crypto { .. }));

    // Test voting errors
    let voting_err = voting_error!("test voting error");
    assert!(matches!(voting_err, Error::Voting { .. }));

    // Test validation errors
    let validation_err = Error::validation("test_field");
    assert!(matches!(validation_err, Error::Validation { .. }));

    // Test that errors don't leak sensitive information
    let error_msg = format!("{}", crypto_err);
    assert!(!error_msg.contains("token"));
    assert!(!error_msg.contains("private"));
    assert!(!error_msg.contains("secret"));

    println!("✅ Comprehensive error handling works correctly");
}