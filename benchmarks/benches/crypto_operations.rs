use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use vote::crypto::{CryptoRateLimiter, SecureKeyPair, SecureMemory, SecureSaltManager};

/// Banking-grade crypto operation benchmarks
/// Critical for timing attack resistance validation
fn bench_voter_hash_generation(c: &mut Criterion) {
    let salt_manager = SecureSaltManager::for_testing();
    let bank_id = "test_bank";
    let election_id = Uuid::new_v4();

    let mut group = c.benchmark_group("voter_hash");
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_secs(5));

    // Test timing consistency - critical for timing attack resistance
    group.bench_function("consistent_timing", |b| {
        b.iter(|| {
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            salt_manager
                .hash_voter_identity_secure(
                    black_box(bank_id),
                    black_box(&election_id),
                    black_box(current_timestamp),
                    black_box(300),
                )
                .unwrap()
        })
    });

    // Test with different input lengths
    for input_len in [10, 50, 100, 500].iter() {
        let long_bank_id = "x".repeat(*input_len);
        group.bench_with_input(
            BenchmarkId::new("variable_input", input_len),
            input_len,
            |b, _| {
                b.iter(|| {
                    let current_timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    salt_manager
                        .hash_voter_identity_secure(
                            black_box(&long_bank_id),
                            black_box(&election_id),
                            black_box(current_timestamp),
                            black_box(300),
                        )
                        .unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_key_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_operations");
    group.warm_up_time(Duration::from_millis(100));

    // Key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| SecureKeyPair::generate_with_expiration(black_box(Some(86400))).unwrap())
    });

    // Signature operations
    let key_pair = SecureKeyPair::generate_with_expiration(Some(86400)).unwrap();
    let message = b"test voting message for signature";

    group.bench_function("signature_creation", |b| {
        b.iter(|| key_pair.sign_with_timestamp(black_box(message)).unwrap())
    });

    let (signature, timestamp) = key_pair.sign_with_timestamp(message).unwrap();

    group.bench_function("signature_verification", |b| {
        b.iter(|| {
            key_pair
                .verify_with_timestamp(
                    black_box(message),
                    black_box(&signature),
                    black_box(timestamp),
                    black_box(300),
                )
                .unwrap()
        })
    });

    group.finish();
}

fn bench_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_security");

    // Constant-time comparison - critical security primitive
    let data1 = SecureMemory::secure_random_bytes::<32>();
    let data2 = SecureMemory::secure_random_bytes::<32>();
    let data3 = data1; // Same data for positive comparison

    group.bench_function("constant_time_eq_different", |b| {
        b.iter(|| SecureMemory::constant_time_eq(black_box(&data1), black_box(&data2)))
    });

    group.bench_function("constant_time_eq_same", |b| {
        b.iter(|| SecureMemory::constant_time_eq(black_box(&data1), black_box(&data3)))
    });

    // Random generation performance
    group.bench_function("secure_random_32", |b| {
        b.iter(|| SecureMemory::secure_random_bytes::<32>())
    });

    group.bench_function("secure_random_64", |b| {
        b.iter(|| SecureMemory::secure_random_bytes::<64>())
    });

    group.finish();
}

fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");

    // Rate limiter performance impact
    group.bench_function("rate_limit_check", |b| {
        b.iter_batched(
            || {
                // Create fresh rate limiter for each iteration to avoid hitting limits
                CryptoRateLimiter::new(10000) // Very high limit for benchmarking
            },
            |mut rate_limiter| rate_limiter.check_rate_limit().unwrap(),
            criterion::BatchSize::SmallInput,
        );
    });

    // Rate limiter with different limits - test performance, not actual limiting
    for limit in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(BenchmarkId::new("rate_limit", limit), limit, |b, &limit| {
            b.iter_batched(
                || CryptoRateLimiter::new(limit),
                |mut rate_limiter| {
                    // Only do one check per rate limiter to avoid hitting limits
                    rate_limiter.check_rate_limit().unwrap_or(())
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_timing_attack_resistance(c: &mut Criterion) {
    let mut group = c.benchmark_group("timing_resistance");
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    let salt_manager = SecureSaltManager::for_testing();

    // Test timing consistency across different voters
    // This is critical - variations could leak information
    let long_voter = "a".repeat(100);
    let voters = [
        "voter_short",
        "voter_with_much_longer_identifier_string",
        "special!@#$%^&*()characters",
        "unicode_测试_用户",
        &long_voter,
    ];

    for (i, voter) in voters.iter().enumerate() {
        group.bench_function(format!("voter_hash_{i}"), |b| {
            b.iter(|| {
                let current_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                salt_manager
                    .hash_voter_identity_secure(
                        black_box(voter),
                        black_box(&Uuid::new_v4()),
                        black_box(current_timestamp),
                        black_box(300),
                    )
                    .unwrap()
            })
        });
    }

    group.finish();
}

fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_crypto");

    // Simulate concurrent voting scenario
    group.bench_function("concurrent_hash_generation", |b| {
        let salt_manager = SecureSaltManager::for_testing();
        let election_id = Uuid::new_v4();

        b.iter(|| {
            // Simulate 10 concurrent voters
            let mut handles = Vec::new();

            for i in 0..10 {
                let sm = salt_manager.clone();
                let eid = election_id;
                handles.push(std::thread::spawn(move || {
                    let current_timestamp = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    sm.hash_voter_identity_secure(
                        &format!("voter_{i}"),
                        &eid,
                        current_timestamp,
                        300,
                    )
                    .unwrap()
                }));
            }

            for handle in handles {
                black_box(handle.join().unwrap());
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_voter_hash_generation,
    bench_key_operations,
    bench_memory_operations,
    bench_rate_limiting,
    bench_timing_attack_resistance,
    bench_concurrent_operations
);

criterion_main!(benches);
