use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::RngCore;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;
use vote::crypto::{
    SecureSaltManager, SecurityContext, VotingLockService, VotingTokenService,
    voting_lock::{LockResult, VotingMethod},
    voting_token::TokenResult,
};

/// End-to-end voting workflow benchmarks
/// Performance validation for complete banking-grade voting process
fn bench_token_lifecycle(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("token_lifecycle");
    group.warm_up_time(Duration::from_millis(100));

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = VotingTokenService::for_testing();
    let voter_hash = hex::encode([1u8; 32]);
    let election_id = Uuid::new_v4();

    // Token issuance performance
    group.bench_function("token_issuance", |b| {
        b.to_async(&rt).iter(|| async {
            let result = token_service
                .issue_token(
                    black_box(&salt_manager),
                    black_box(&voter_hash),
                    black_box(&election_id),
                    black_box(Some("session_123".to_string())),
                )
                .unwrap();

            if let TokenResult::Issued(token) = result {
                black_box(token);
            }
        })
    });

    // Token validation performance - create fresh token each time
    group.bench_function("token_validation", |b| {
        b.iter_batched(
            || {
                // Create fresh token for each validation test
                let mut rng = rand::thread_rng();
                let mut voter_bytes = [0u8; 32];
                rng.fill_bytes(&mut voter_bytes);
                let unique_voter_hash = hex::encode(voter_bytes);
                let unique_election_id = Uuid::new_v4();

                let token_result = token_service
                    .issue_token(
                        &salt_manager,
                        &unique_voter_hash,
                        &unique_election_id,
                        Some(format!("session_{}", Uuid::new_v4())),
                    )
                    .unwrap();

                if let TokenResult::Issued(token) = token_result {
                    (token.token_id, unique_voter_hash, unique_election_id)
                } else {
                    panic!("Failed to issue token for validation benchmark");
                }
            },
            |(token_id, voter_hash, election_id)| {
                token_service
                    .validate_token(
                        black_box(&salt_manager),
                        black_box(&token_id),
                        black_box(&voter_hash),
                        black_box(&election_id),
                    )
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_voting_lock_operations(c: &mut Criterion) {
    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());

    let mut group = c.benchmark_group("voting_locks");

    // Lock acquisition with token validation
    group.bench_function("lock_acquisition", |b| {
        b.iter_batched(
            || {
                // Setup: Create fresh voter and token for each iteration
                let mut rng = rand::thread_rng();
                let mut voter_bytes = [0u8; 32];
                rng.fill_bytes(&mut voter_bytes);
                let voter_hash = hex::encode(voter_bytes);
                let election_id = Uuid::new_v4();
                let token_result = token_service
                    .issue_token(&salt_manager, &voter_hash, &election_id, None)
                    .unwrap();

                let token_id = if let TokenResult::Issued(token) = token_result {
                    token.token_id
                } else {
                    panic!("Token issuance failed");
                };

                (voter_hash, election_id, token_id)
            },
            |(voter_hash, election_id, token_id)| {
                lock_service
                    .acquire_lock_with_token(
                        black_box(&salt_manager),
                        black_box(&token_id),
                        black_box(&voter_hash),
                        black_box(&election_id),
                        black_box(VotingMethod::Digital),
                    )
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Lock release performance
    group.bench_function("lock_release", |b| {
        b.iter_batched(
            || {
                // Setup: Create lock for each iteration
                let mut rng = rand::thread_rng();
                let mut voter_bytes = [0u8; 32];
                rng.fill_bytes(&mut voter_bytes);
                let voter_hash = hex::encode(voter_bytes);
                let election_id = Uuid::new_v4();
                let token_result = token_service
                    .issue_token(&salt_manager, &voter_hash, &election_id, None)
                    .unwrap();

                let token_id = if let TokenResult::Issued(token) = token_result {
                    token.token_id
                } else {
                    panic!("Token issuance failed");
                };

                let lock_result = lock_service
                    .acquire_lock_with_token(
                        &salt_manager,
                        &token_id,
                        &voter_hash,
                        &election_id,
                        VotingMethod::Digital,
                    )
                    .unwrap();

                if let LockResult::Acquired(lock) = lock_result {
                    lock
                } else {
                    panic!("Lock acquisition failed");
                }
            },
            |lock| {
                lock_service
                    .release_lock_with_token_cleanup(black_box(&lock))
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_complete_voting_workflow(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("complete_workflow");
    group.warm_up_time(Duration::from_millis(200));
    group.measurement_time(Duration::from_secs(10));

    // Complete voting process: login → lock → vote → complete
    group.bench_function("full_voting_process", |b| {
        b.to_async(&rt).iter_batched(
            || {
                // Setup fresh components for each iteration
                let salt_manager = Arc::new(SecureSaltManager::for_testing());
                let token_service = Arc::new(VotingTokenService::for_testing());
                let lock_service = Arc::new(VotingLockService::new(token_service.clone()));
                let security_context = SecurityContext::for_testing(
                    salt_manager.clone(),
                    token_service.clone(),
                    lock_service.clone(),
                );

                let mut rng = rand::thread_rng();
                let mut voter_bytes = [0u8; 32];
                rng.fill_bytes(&mut voter_bytes);
                let bank_id = format!("CZ{}", hex::encode(&voter_bytes[..8]));
                let election_id = Uuid::new_v4();

                (security_context, bank_id, election_id)
            },
            |(security_context, bank_id, election_id)| async move {
                // Step 1: Secure login (this handles token issuance internally)
                let login_result = security_context
                    .secure_login(
                        black_box(&bank_id),
                        black_box(&election_id),
                        black_box(Some("session_bench".to_string())),
                        black_box(Some("192.168.1.1".to_string())),
                    )
                    .await
                    .unwrap();

                let (token, voter_hash) = match login_result {
                    vote::crypto::SecurityLoginResult::Success { token, .. } => {
                        (token.token_id, token.voter_hash)
                    }
                    _ => panic!("Login failed in benchmark"),
                };

                // Step 2: Secure vote (this handles lock acquisition)
                let vote_result = security_context
                    .secure_vote(
                        black_box(&token),
                        black_box(&voter_hash),
                        black_box(&election_id),
                        black_box(VotingMethod::Digital),
                    )
                    .await
                    .unwrap();

                let voting_lock = match vote_result {
                    vote::crypto::SecurityVoteResult::LockAcquired { lock } => lock,
                    _ => panic!("Vote lock acquisition failed in benchmark"),
                };

                // Step 3: Complete voting
                let vote_id = Uuid::new_v4();
                let completion = security_context
                    .complete_voting(black_box(&voting_lock), black_box(Some(vote_id)))
                    .await
                    .unwrap();

                black_box(completion);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_concurrent_voting(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_voting");
    group.sample_size(50); // Reduce sample size for expensive concurrent tests

    // Test concurrent voting performance - critical for banking systems
    for num_voters in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_voters", num_voters),
            num_voters,
            |b, &num_voters| {
                b.to_async(&rt).iter(|| async move {
                    let salt_manager = Arc::new(SecureSaltManager::for_testing());
                    let token_service = Arc::new(VotingTokenService::for_testing());
                    let lock_service = Arc::new(VotingLockService::new(token_service.clone()));

                    let election_id = Uuid::new_v4();
                    let mut handles = Vec::new();

                    for i in 0..num_voters {
                        let sm = salt_manager.clone();
                        let ts = token_service.clone();
                        let ls = lock_service.clone();
                        let eid = election_id;

                        handles.push(tokio::spawn(async move {
                            let voter_hash = hex::encode([i as u8; 32]);

                            // Issue token
                            let token_result =
                                ts.issue_token(&sm, &voter_hash, &eid, None).unwrap();
                            let token_id = if let TokenResult::Issued(token) = token_result {
                                token.token_id
                            } else {
                                return;
                            };

                            // Acquire lock
                            let lock_result = ls
                                .acquire_lock_with_token(
                                    &sm,
                                    &token_id,
                                    &voter_hash,
                                    &eid,
                                    VotingMethod::Digital,
                                )
                                .unwrap();

                            if let LockResult::Acquired(lock) = lock_result {
                                // Complete voting
                                let vote_id = Uuid::new_v4();
                                ls.complete_voting_with_token_cleanup(&lock, Some(vote_id))
                                    .unwrap();
                            }
                        }));
                    }

                    // Wait for all voters to complete
                    for handle in handles {
                        handle.await.unwrap();
                        black_box(());
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_error_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_handling");

    let salt_manager = SecureSaltManager::for_testing();
    let token_service = Arc::new(VotingTokenService::for_testing());
    let lock_service = VotingLockService::new(token_service.clone());

    // Invalid token performance - should be consistent timing
    group.bench_function("invalid_token_validation", |b| {
        let voter_hash = hex::encode([1u8; 32]);
        let election_id = Uuid::new_v4();

        b.iter(|| {
            lock_service
                .acquire_lock_with_token(
                    black_box(&salt_manager),
                    black_box("invalid_token_12345"),
                    black_box(&voter_hash),
                    black_box(&election_id),
                    black_box(VotingMethod::Digital),
                )
                .unwrap()
        })
    });

    // Double voting attempt performance
    group.bench_function("double_voting_prevention", |b| {
        b.iter_batched(
            || {
                // Setup: Complete voting first
                let mut rng = rand::thread_rng();
                let mut voter_bytes = [0u8; 32];
                rng.fill_bytes(&mut voter_bytes);
                let voter_hash = hex::encode(voter_bytes);
                let election_id = Uuid::new_v4();

                let token_result = token_service
                    .issue_token(&salt_manager, &voter_hash, &election_id, None)
                    .unwrap();
                let token_id = if let TokenResult::Issued(token) = token_result {
                    token.token_id
                } else {
                    panic!("Token issuance failed");
                };

                let lock_result = lock_service
                    .acquire_lock_with_token(
                        &salt_manager,
                        &token_id,
                        &voter_hash,
                        &election_id,
                        VotingMethod::Digital,
                    )
                    .unwrap();

                if let LockResult::Acquired(lock) = lock_result {
                    lock_service
                        .complete_voting_with_token_cleanup(&lock, Some(Uuid::new_v4()))
                        .unwrap();
                }

                // Issue new token for second attempt
                let second_token_result = token_service
                    .issue_token(&salt_manager, &voter_hash, &election_id, None)
                    .unwrap();
                let second_token_id = if let TokenResult::Issued(token) = second_token_result {
                    token.token_id
                } else {
                    panic!("Second token issuance failed");
                };

                (voter_hash, election_id, second_token_id)
            },
            |(voter_hash, election_id, token_id)| {
                // Attempt second vote - should be blocked
                lock_service
                    .acquire_lock_with_token(
                        black_box(&salt_manager),
                        black_box(&token_id),
                        black_box(&voter_hash),
                        black_box(&election_id),
                        black_box(VotingMethod::Digital),
                    )
                    .unwrap()
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_token_lifecycle,
    bench_voting_lock_operations,
    bench_complete_voting_workflow,
    bench_concurrent_voting,
    bench_error_scenarios
);

criterion_main!(benches);
