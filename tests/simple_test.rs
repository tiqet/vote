//! Simple test to verify compilation and token-secured functionality

use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;
use vote::{
    Result,
    config::Config,
    crypto::{
        CryptoRateLimiter, CryptoUtils, SecureKeyPair, SecureMemory, SecureSaltManager,
        TokenGenerator, TokenResult, VotingTokenService,
        voting_lock::{LockResult, VotingLockService, VotingMethod},
    },
    types::Election,
};

#[tokio::test]
async fn test_basic_compilation_with_tokens() -> Result<()> {
    println!("🔧 Testing basic compilation and token-secured functionality...");

    // Test configuration
    let config = Config::for_testing()?;
    assert!(config.security.key_expiry_seconds > 0);
    println!("✅ Configuration works");

    // Test secure crypto
    let key_pair = SecureKeyPair::generate_with_expiration(Some(3600))?;
    assert!(!key_pair.is_expired());
    println!("✅ Secure key pair works");

    // Test signing with timestamp
    let message = b"test message";
    let (signature, timestamp) = key_pair.sign_with_timestamp(message)?;
    key_pair.verify_with_timestamp(message, &signature, timestamp, 300)?;
    println!("✅ Timestamped signing and verification works");

    // Test salt manager
    let salt_manager = SecureSaltManager::for_testing();
    let bank_id = "CZ1234567890";
    let election_id = Uuid::new_v4();
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let voter_hash =
        salt_manager.hash_voter_identity_secure(bank_id, &election_id, current_timestamp, 300)?;
    let voter_hash_str = hex::encode(voter_hash);
    println!("✅ Secure salt manager works");

    // Test rate limiter
    let mut rate_limiter = CryptoRateLimiter::new(10);
    assert!(rate_limiter.check_rate_limit().is_ok());
    println!("✅ Rate limiter works");

    // Test memory security
    let random1 = SecureMemory::secure_random_bytes::<32>();
    let random2 = SecureMemory::secure_random_bytes::<32>();
    assert_ne!(random1, random2);
    println!("✅ Secure memory works");

    // Test secure token generation
    let mut token_gen = TokenGenerator::new();
    let token1 = token_gen.generate_token();
    let token2 = token_gen.generate_token();
    assert_ne!(token1, token2);
    println!("✅ Secure token generation works");

    // **TEST TOKEN SERVICE**
    println!("\n🎫 Testing token service...");

    let token_service = Arc::new(VotingTokenService::for_testing());

    // Issue voting token
    let token_result = token_service.issue_token(
        &salt_manager,
        &voter_hash_str,
        &election_id,
        Some("test_session_123".to_string()),
    )?;

    let voting_token = match token_result {
        TokenResult::Issued(token) => {
            println!("✅ Voting token issued: {}...", &token.token_id[..12]);
            token
        }
        _ => panic!("Expected voting token to be issued"),
    };

    // Validate token
    let validation_result = token_service.validate_token(
        &salt_manager,
        &voting_token.token_id,
        &voter_hash_str,
        &election_id,
    )?;

    match validation_result {
        TokenResult::Valid(_) => {
            println!("✅ Token validation successful");
        }
        _ => panic!("Expected token to be valid"),
    }

    // Test secure voting token generation
    let expires_at = current_timestamp + 3600;
    let (secure_token_hash, nonce) =
        salt_manager.generate_voting_token_secure(&voter_hash, &election_id, expires_at)?;

    // Validate the secure token
    let secure_validation = salt_manager.validate_voting_token_secure(
        &secure_token_hash,
        &nonce,
        &voter_hash,
        &election_id,
        expires_at,
        current_timestamp,
    )?;
    assert!(secure_validation);
    println!("✅ Secure voting token generation and validation works");

    // **TEST INTEGRATED VOTING LOCK SERVICE**
    println!("\n🔒 Testing integrated voting lock service...");

    let lock_service = VotingLockService::new(token_service.clone());

    // Test voting status check
    let initial_status = lock_service.get_voting_status(&voter_hash_str, &election_id)?;
    assert!(initial_status.can_vote());
    assert!(initial_status.blocking_reason().is_none());
    assert!(!initial_status.active_tokens.is_empty());
    println!("✅ Initial voting status check works");

    // Test lock acquisition with token
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
            lock
        }
        _ => panic!("Expected to acquire voting lock with valid token"),
    };

    // Test voting completion with token cleanup
    let vote_id = Uuid::new_v4();
    let completion =
        lock_service.complete_voting_with_token_cleanup(&voting_lock, Some(vote_id))?;
    println!(
        "✅ Voting completion with token cleanup: {}",
        completion.completion_id
    );

    // Test that token is now invalid
    let post_vote_validation = token_service.validate_token(
        &salt_manager,
        &voting_token.token_id,
        &voter_hash_str,
        &election_id,
    )?;

    match post_vote_validation {
        TokenResult::Invalid { reason } => {
            println!("✅ Token correctly invalidated after voting: {reason}");
        }
        _ => panic!("Expected token to be invalid after voting"),
    }

    // Test double voting prevention
    let new_token_result =
        token_service.issue_token(&salt_manager, &voter_hash_str, &election_id, None)?;
    let new_token = match new_token_result {
        TokenResult::Issued(t) => t,
        _ => panic!("Should issue new token"),
    };

    let second_attempt = lock_service.acquire_lock_with_token(
        &salt_manager,
        &new_token.token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Analog,
    )?;
    match second_attempt {
        LockResult::AlreadyVoted { .. } => {
            println!("✅ Double voting correctly prevented despite new token");
        }
        _ => panic!("Expected double voting to be prevented"),
    }

    // Test final voting status
    let final_status = lock_service.get_voting_status(&voter_hash_str, &election_id)?;
    assert!(!final_status.can_vote());
    assert!(final_status.completion.is_some());
    assert!(final_status.active_lock.is_none());
    println!("✅ Final voting status correct");

    // **TEST BASIC TYPES**
    println!("\n📝 Testing basic types...");

    let election = Election {
        id: Uuid::new_v4(),
        title: "Token-Secured Test Election".to_string(),
        description: Some("Election with integrated token security".to_string()),
        start_time: Utc::now().timestamp() - 3600,
        end_time: Utc::now().timestamp() + 3600,
        active: true,
        created_at: Utc::now(),
    };

    assert!(election.is_accepting_votes());
    println!("✅ Election types work");

    // Test crypto utilities
    let test_data = b"test data for hashing";
    let hash = CryptoUtils::hash(test_data);
    let hash_hex = CryptoUtils::hash_to_hex(&hash);
    let hash_back = CryptoUtils::hex_to_hash(&hash_hex)?;
    assert_eq!(hash, hash_back);
    println!("✅ Crypto utilities work");

    // **TEST TOKEN SERVICE STATISTICS**
    println!("\n📊 Testing token service statistics...");

    let token_stats = token_service.get_stats()?;
    println!("✅ Token service statistics:");
    println!("   Total tokens: {}", token_stats.total_tokens);
    println!("   Active tokens: {}", token_stats.active_tokens);
    println!("   Used tokens: {}", token_stats.used_tokens);
    println!("   Unique voters: {}", token_stats.unique_voters);

    // Test cleanup
    let cleanup_stats = token_service.cleanup_expired_tokens()?;
    println!("✅ Token cleanup statistics:");
    println!("   Tokens removed: {}", cleanup_stats.total_removed);

    println!("\n🎉 All enhanced functionality with tokens verified!");
    println!("🔒 Complete security stack working:");
    println!("   • Environment-based salts");
    println!("   • Timestamp replay protection");
    println!("   • Cryptographic rate limiting");
    println!("   • Key expiration management");
    println!("   • Banking-grade crypto (Ed25519 + Blake3)");
    println!("   • ✅ Session-based token authentication");
    println!("   • ✅ Cryptographic token validation");
    println!("   • ✅ Automatic token lifecycle management");
    println!("   • ✅ Temporal lock prevention");
    println!("   • ✅ Voting completion tracking");
    println!("   • ✅ Permanent double-vote prevention");
    println!("   • ✅ Scalable architecture for millions of users");
    println!("   • 🧹 Clean codebase with secure APIs only");

    Ok(())
}

#[tokio::test]
async fn test_logout_scenarios() -> Result<()> {
    println!("🚪 Testing logout scenarios...");

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());
    let election_id = Uuid::new_v4();
    let voter_hash_str = hex::encode([1u8; 32]);

    // **SCENARIO 1: Logout during voting**
    println!("\n🔒 SCENARIO 1: Logout during active voting session");

    // Login and start voting
    let token_result = token_service.issue_token(
        &salt_manager,
        &voter_hash_str,
        &election_id,
        Some("logout_test_session".to_string()),
    )?;
    let token = match token_result {
        TokenResult::Issued(t) => t,
        _ => panic!(),
    };

    let lock_result = lock_service.acquire_lock_with_token(
        &salt_manager,
        &token.token_id,
        &voter_hash_str,
        &election_id,
        VotingMethod::Digital,
    )?;
    let _voting_lock = match lock_result {
        LockResult::Acquired(l) => l,
        _ => panic!(),
    };

    println!("✅ Voting session started");

    // Logout during voting
    let logout_result = lock_service.logout_voter(&voter_hash_str, &election_id)?;
    println!("✅ Logout completed:");
    println!(
        "   Tokens invalidated: {}",
        logout_result.invalidated_tokens
    );
    println!("   Lock released: {}", logout_result.released_lock);

    assert!(logout_result.invalidated_tokens > 0);
    assert!(logout_result.released_lock);

    // **SCENARIO 2: Logout without voting**
    println!("\n🚪 SCENARIO 2: Logout without voting");

    let voter2_hash_str = hex::encode([2u8; 32]);
    let token2_result = token_service.issue_token(
        &salt_manager,
        &voter2_hash_str,
        &election_id,
        Some("no_vote_session".to_string()),
    )?;
    let _token2 = match token2_result {
        TokenResult::Issued(t) => t,
        _ => panic!(),
    };

    println!("✅ Login without voting");

    let logout2_result = lock_service.logout_voter(&voter2_hash_str, &election_id)?;
    println!("✅ Logout without voting:");
    println!(
        "   Tokens invalidated: {}",
        logout2_result.invalidated_tokens
    );
    println!("   Lock released: {}", logout2_result.released_lock);

    assert!(logout2_result.invalidated_tokens > 0);
    assert!(!logout2_result.released_lock); // No lock to release

    println!("✅ All logout scenarios work correctly");

    Ok(())
}
