use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use uuid::Uuid;
use vote::crypto::{
    EnhancedAuditSystem, ResourceUsage, SecurityIncidentManager, SecurityOperation,
    SecurityPerformanceMonitor, SecurityTimingContext,
};

/// Security monitoring system benchmarks
/// Performance validation for real-time threat detection
fn bench_security_timing_recording(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("security_timing");
    group.warm_up_time(Duration::from_millis(100));

    let monitor = SecurityPerformanceMonitor::for_testing();

    // Single timing record performance
    group.bench_function("single_timing_record", |b| {
        b.to_async(&rt).iter(|| async {
            let context = SecurityTimingContext {
                voter_hash: Some("bench_voter".to_string()),
                election_id: Some(Uuid::new_v4()),
                session_id: Some("bench_session".to_string()),
                operation_size: Some(1024),
                cpu_load: Some(0.5),
                memory_usage_mb: Some(256),
            };

            monitor
                .record_timing(
                    black_box(SecurityOperation::TokenValidation),
                    black_box(Duration::from_micros(150)),
                    black_box(true),
                    black_box(context),
                )
                .await
                .unwrap()
        })
    });

    // Batch timing records - simulate high load
    for batch_size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch_timing_records", batch_size),
            batch_size,
            |b, &batch_size| {
                b.to_async(&rt).iter(|| async {
                    for i in 0..batch_size {
                        let context = SecurityTimingContext {
                            voter_hash: Some(format!("voter_{i}")),
                            election_id: Some(Uuid::new_v4()),
                            ..Default::default()
                        };

                        monitor
                            .record_timing(
                                SecurityOperation::VoterHashGeneration,
                                Duration::from_micros(100 + i as u64),
                                true,
                                context,
                            )
                            .await
                            .unwrap();
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_authentication_pattern_analysis(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("auth_patterns");

    let monitor = SecurityPerformanceMonitor::for_testing();

    // Setup: Create authentication patterns
    rt.block_on(async {
        for i in 0..50 {
            let context = SecurityTimingContext {
                voter_hash: Some(format!("pattern_voter_{}", i % 10)), // Create 10 distinct patterns
                election_id: Some(Uuid::new_v4()),
                ..Default::default()
            };

            // Mix of successful and failed attempts
            let success = i % 3 != 0; // 2/3 success rate

            monitor
                .record_timing(
                    SecurityOperation::SecureLogin,
                    Duration::from_millis(50 + (i % 20) as u64), // Variable timing
                    success,
                    context,
                )
                .await
                .unwrap();
        }
    });

    // Pattern retrieval performance
    group.bench_function("get_auth_patterns", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(monitor.get_auth_patterns().await.unwrap()) })
    });

    // Pattern analysis performance
    group.bench_function("pattern_analysis", |b| {
        b.to_async(&rt).iter(|| async {
            let patterns = monitor.get_auth_patterns().await.unwrap();
            let suspicious_count = patterns.iter().filter(|p| p.is_suspicious()).count();
            black_box(suspicious_count)
        })
    });

    group.finish();
}

fn bench_resource_monitoring(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("resource_monitoring");

    let monitor = SecurityPerformanceMonitor::for_testing();

    // Resource usage recording
    group.bench_function("resource_recording", |b| {
        b.to_async(&rt).iter(|| async {
            let usage = ResourceUsage {
                timestamp: 1725120000, // Aug 2025
                cpu_percent: 45.5,
                memory_mb: 512,
                active_sessions: 150,
                pending_operations: 25,
                rate_limit_hits: 2,
            };

            monitor
                .record_resource_usage(black_box(usage))
                .await
                .unwrap()
        })
    });

    // DoS pattern detection performance
    group.bench_function("dos_pattern_detection", |b| {
        b.to_async(&rt).iter(|| async {
            // Simulate high resource usage
            let high_usage = ResourceUsage {
                timestamp: 1725120000,
                cpu_percent: 95.0, // High CPU
                memory_mb: 800,    // High memory
                active_sessions: 1000,
                pending_operations: 500,
                rate_limit_hits: 100,
            };

            monitor
                .record_resource_usage(black_box(high_usage))
                .await
                .unwrap();
            black_box(monitor.get_dos_patterns().await.unwrap())
        })
    });

    group.finish();
}

fn bench_metrics_aggregation(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("metrics_aggregation");

    let monitor = SecurityPerformanceMonitor::for_testing();

    // Setup: Add substantial data for aggregation
    rt.block_on(async {
        // Add timing data
        for i in 0..1000 {
            let context = SecurityTimingContext {
                voter_hash: Some(format!("metrics_voter_{}", i % 100)),
                ..Default::default()
            };

            monitor
                .record_timing(
                    if i % 2 == 0 {
                        SecurityOperation::TokenValidation
                    } else {
                        SecurityOperation::VoterHashGeneration
                    },
                    Duration::from_micros(100 + (i % 50) as u64),
                    i % 10 != 0, // 90% success rate
                    context,
                )
                .await
                .unwrap();
        }

        // Add resource data
        for i in 0..100 {
            let usage = ResourceUsage {
                timestamp: 1725120000 + i,
                cpu_percent: 20.0 + (i as f64 * 0.5),
                memory_mb: 200 + (i * 2),
                active_sessions: 50 + i,
                pending_operations: 10 + (i / 10),
                rate_limit_hits: i / 20,
            };

            monitor.record_resource_usage(usage).await.unwrap();
        }
    });

    // Current metrics calculation performance
    group.bench_function("current_metrics_calculation", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(monitor.get_current_metrics().await.unwrap()) })
    });

    // Timing statistics calculation
    group.bench_function("timing_stats_calculation", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                monitor
                    .get_timing_stats(&SecurityOperation::TokenValidation)
                    .await
                    .unwrap(),
            )
        })
    });

    // Baseline update performance
    group.bench_function("baseline_update", |b| {
        b.to_async(&rt)
            .iter(|| async { monitor.update_baselines().await.unwrap() })
    });

    group.finish();
}

fn bench_incident_management(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("incident_management");
    group.sample_size(20); // Reduce for expensive operations

    let incident_manager = SecurityIncidentManager::for_testing();
    let performance_monitor = SecurityPerformanceMonitor::for_testing();
    let audit_system = EnhancedAuditSystem::for_testing();

    // Setup security context for incident response
    let salt_manager = std::sync::Arc::new(vote::crypto::SecureSaltManager::for_testing());
    let token_service = std::sync::Arc::new(vote::crypto::VotingTokenService::for_testing());
    let lock_service = vote::crypto::VotingLockService::new(token_service.clone());
    let security_context = vote::crypto::SecurityContext::for_testing(
        salt_manager,
        token_service,
        std::sync::Arc::new(lock_service),
    );

    // Create suspicious activity for incident detection
    rt.block_on(async {
        for i in 0..20 {
            let context = SecurityTimingContext {
                voter_hash: Some(format!("suspicious_voter_{}", i % 3)), // Create attack patterns
                ..Default::default()
            };

            // Simulate failed authentication attacks
            performance_monitor
                .record_timing(
                    SecurityOperation::SecureLogin,
                    Duration::from_millis(100 + i * 10), // Increasing timing (suspicious)
                    false,                               // Failed attempts
                    context,
                )
                .await
                .unwrap();
        }
    });

    // Incident analysis and response performance
    group.bench_function("analyze_and_respond", |b| {
        b.to_async(&rt).iter(|| async {
            black_box(
                incident_manager
                    .analyze_and_respond(&performance_monitor, &audit_system, &security_context)
                    .await
                    .unwrap(),
            )
        })
    });

    // Incident statistics calculation
    group.bench_function("incident_statistics", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(incident_manager.get_incident_statistics().await.unwrap()) })
    });

    group.finish();
}

fn bench_audit_system_performance(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("audit_system");

    let audit_system = EnhancedAuditSystem::for_testing();

    // Security event logging performance
    group.bench_function("security_event_logging", |b| {
        b.to_async(&rt).iter(|| async {
            let security_event = vote::crypto::SecurityEvent::LoginAttempt {
                voter_hash: "audit_bench_voter".to_string(),
                election_id: Uuid::new_v4(),
                session_id: Some("audit_session".to_string()),
                success: true,
                timestamp: 1725120000,
                ip_address: Some("192.168.1.100".to_string()),
            };

            black_box(
                audit_system
                    .log_security_event(
                        security_event,
                        Some(vote::crypto::ComplianceLevel::Standard),
                        Some("bench_correlation".to_string()),
                    )
                    .await
                    .unwrap(),
            )
        })
    });

    // Setup audit records for integrity verification
    rt.block_on(async {
        for i in 0..100 {
            let security_event = vote::crypto::SecurityEvent::LoginAttempt {
                voter_hash: format!("audit_voter_{i}"),
                election_id: Uuid::new_v4(),
                session_id: Some(format!("session_{i}")),
                success: i % 5 != 0, // Mostly successful
                timestamp: 1725120000 + i,
                ip_address: Some("192.168.1.1".to_string()),
            };

            audit_system
                .log_security_event(
                    security_event,
                    Some(vote::crypto::ComplianceLevel::Standard),
                    None,
                )
                .await
                .unwrap();
        }
    });

    // Audit trail integrity verification performance
    group.bench_function("integrity_verification", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(audit_system.verify_integrity().await.unwrap()) })
    });

    // Audit record queries
    group.bench_function("audit_record_query", |b| {
        b.to_async(&rt).iter(|| async {
            let query = vote::crypto::AuditQuery {
                start_time: Some(1725120000),
                end_time: Some(1725120100),
                limit: Some(50),
                ..Default::default()
            };

            black_box(audit_system.query_audit_records(query).await.unwrap())
        })
    });

    group.finish();
}

fn bench_concurrent_security_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("concurrent_security");
    group.sample_size(10); // Expensive concurrent operations

    // Test concurrent security monitoring under load
    for thread_count in [5, 10, 20].iter() {
        group.bench_with_input(
            BenchmarkId::new("concurrent_monitoring", thread_count),
            thread_count,
            |b, &thread_count| {
                b.to_async(&rt).iter(|| async move {
                    let monitor = SecurityPerformanceMonitor::for_testing();
                    let mut handles = Vec::new();

                    for i in 0..thread_count {
                        // Create a new monitor instance for each task to avoid clone issue
                        let monitor_instance = SecurityPerformanceMonitor::for_testing();

                        handles.push(tokio::spawn(async move {
                            // Each thread performs multiple security operations
                            for j in 0..10 {
                                let context = SecurityTimingContext {
                                    voter_hash: Some(format!("concurrent_voter_{i}_{j}")),
                                    ..Default::default()
                                };

                                monitor_instance
                                    .record_timing(
                                        SecurityOperation::TokenValidation,
                                        Duration::from_micros(150),
                                        true,
                                        context,
                                    )
                                    .await
                                    .unwrap();
                            }
                        }));
                    }

                    // Wait for all operations to complete
                    for handle in handles {
                        handle.await.unwrap();
                        black_box(());
                    }

                    // Get final metrics
                    black_box(monitor.get_current_metrics().await.unwrap());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_security_timing_recording,
    bench_authentication_pattern_analysis,
    bench_resource_monitoring,
    bench_metrics_aggregation,
    bench_incident_management,
    bench_audit_system_performance,
    bench_concurrent_security_operations
);

criterion_main!(benches);
