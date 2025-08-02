//! Security-focused Performance Monitoring for Banking-Grade Threat Detection
//!
//! This module provides real-time security performance monitoring focused on
//! detecting timing attacks, DoS attempts, and crypto operation anomalies.
//! Designed for core security operations with interfaces for future integration
//! with DB and Web layers.
//!
//! Key Features:
//! - Real-time timing attack detection on crypto operations
//! - DoS pattern detection and resource monitoring
//! - Authentication pattern analysis and anomaly detection
//! - Security context performance monitoring
//! - Memory security pattern analysis
//! - Clean interfaces for future layer integration

use crate::crypto::SecurityEvent;
use crate::{Result, crypto_error};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// Maximum timing samples to keep for analysis
const MAX_TIMING_SAMPLES: usize = 10000;

/// Maximum resource usage samples
const MAX_RESOURCE_SAMPLES: usize = 1000;

/// Timing attack detection threshold (microseconds)
const TIMING_ATTACK_THRESHOLD_MICROS: u64 = 50;

/// DoS detection thresholds
#[allow(dead_code)]
const DOS_REQUEST_THRESHOLD: u32 = 1000; // requests per minute
const DOS_MEMORY_THRESHOLD_MB: u64 = 512; // MB
const DOS_CPU_THRESHOLD_PERCENT: f64 = 80.0;

/// Core security operation types for performance monitoring
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SecurityOperation {
    // Cryptographic operations
    VoterHashGeneration,
    TokenGeneration,
    TokenValidation,
    SignatureCreation,
    SignatureVerification,
    KeyRotation,
    HashComparison,

    // Authentication operations
    SecureLogin,
    SecureLogout,
    SessionValidation,

    // Voting operations
    VotingLockAcquisition,
    VotingCompletion,
    VotingValidation,

    // Security context operations
    SecurityEventLogging,
    AuditRecordCreation,
    IntegrityVerification,

    // Memory security operations
    SecureMemoryAllocation,
    SecureMemoryClearing,
}

/// Timing measurement for security operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTiming {
    pub operation: SecurityOperation,
    pub duration_micros: u64,
    pub timestamp: u64,
    pub success: bool,
    pub operation_id: String,
    pub context: SecurityTimingContext,
}

impl SecurityTiming {
    pub fn new(
        operation: SecurityOperation,
        duration: Duration,
        success: bool,
        context: SecurityTimingContext,
    ) -> Self {
        Self {
            operation,
            duration_micros: duration.as_micros() as u64,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            success,
            operation_id: Uuid::new_v4().to_string(),
            context,
        }
    }

    /// Check if this timing indicates a potential timing attack
    pub fn is_anomalous(&self, baseline_micros: u64) -> bool {
        let deviation = self.duration_micros.abs_diff(baseline_micros);

        deviation > TIMING_ATTACK_THRESHOLD_MICROS
    }
}

/// Context information for timing measurements
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityTimingContext {
    pub voter_hash: Option<String>,
    pub election_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub operation_size: Option<usize>, // Data size processed
    pub cpu_load: Option<f64>,
    pub memory_usage_mb: Option<u64>,
}

/// Resource usage measurement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub timestamp: u64,
    pub cpu_percent: f64,
    pub memory_mb: u64,
    pub active_sessions: u64,
    pub pending_operations: u64,
    pub rate_limit_hits: u64,
}

/// Authentication pattern tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationPattern {
    pub voter_hash: String,
    pub failed_attempts: u32,
    pub success_count: u32,
    pub first_attempt: u64,
    pub last_attempt: u64,
    pub avg_attempt_interval: f64,
    pub timing_anomalies: u32,
    pub suspicious_score: f64, // 0.0 to 1.0
}

impl AuthenticationPattern {
    pub fn new(voter_hash: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            voter_hash,
            failed_attempts: 0,
            success_count: 0,
            first_attempt: now,
            last_attempt: now,
            avg_attempt_interval: 0.0,
            timing_anomalies: 0,
            suspicious_score: 0.0,
        }
    }

    pub fn record_attempt(&mut self, success: bool, timing_anomaly: bool) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if success {
            self.success_count += 1;
        } else {
            self.failed_attempts += 1;
        }

        if timing_anomaly {
            self.timing_anomalies += 1;
        }

        // Update timing statistics
        if self.last_attempt > 0 {
            let interval = (now - self.last_attempt) as f64;
            let total_attempts = (self.failed_attempts + self.success_count) as f64;

            self.avg_attempt_interval =
                (self.avg_attempt_interval * (total_attempts - 1.0) + interval) / total_attempts;
        }

        self.last_attempt = now;

        // Calculate suspicious score
        self.calculate_suspicious_score();
    }

    fn calculate_suspicious_score(&mut self) {
        let mut score = 0.0;

        // High failure rate
        let total_attempts = self.failed_attempts + self.success_count;
        if total_attempts > 0 {
            let failure_rate = self.failed_attempts as f64 / total_attempts as f64;
            score += failure_rate * 0.4; // 40% weight for failure rate
        }

        // High frequency (short intervals)
        if self.avg_attempt_interval > 0.0 && self.avg_attempt_interval < 1.0 {
            score += (1.0 - self.avg_attempt_interval) * 0.3; // 30% weight for frequency
        }

        // Timing anomalies
        if total_attempts > 0 {
            let anomaly_rate = self.timing_anomalies as f64 / total_attempts as f64;
            score += anomaly_rate * 0.3; // 30% weight for timing anomalies
        }

        self.suspicious_score = score.min(1.0);
    }

    pub fn is_suspicious(&self) -> bool {
        self.suspicious_score >= 0.7 // 70% threshold
    }
}

/// DoS attack detection patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoSPattern {
    pub pattern_id: String,
    pub detection_type: DoSDetectionType,
    pub severity: DoSSeverity,
    pub start_time: u64,
    pub peak_time: Option<u64>,
    pub duration_seconds: u64,
    pub affected_operations: Vec<SecurityOperation>,
    pub mitigation_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DoSDetectionType {
    RequestFlooding,
    ResourceExhaustion,
    ConcurrentSessions,
    CryptoOverload,
    MemoryExhaustion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DoSSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security performance metrics aggregated over time windows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPerformanceMetrics {
    pub timestamp: u64,
    pub window_duration_seconds: u64,

    // Timing metrics
    pub operation_timings: HashMap<SecurityOperation, OperationTimingStats>,
    pub timing_anomalies_detected: u32,
    pub potential_timing_attacks: u32,

    // Authentication metrics
    pub authentication_attempts: u64,
    pub authentication_failures: u64,
    pub suspicious_patterns: u32,
    pub brute_force_attempts: u32,

    // Resource metrics
    pub avg_cpu_percent: f64,
    pub peak_memory_mb: u64,
    pub active_sessions_peak: u64,
    pub rate_limit_violations: u64,

    // DoS detection
    pub dos_patterns_detected: u32,
    pub dos_mitigation_activated: bool,

    // Security health score (0.0 to 1.0)
    pub security_health_score: f64,
}

/// Statistical analysis of operation timings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationTimingStats {
    pub operation: SecurityOperation,
    pub sample_count: u64,
    pub min_micros: u64,
    pub max_micros: u64,
    pub avg_micros: f64,
    pub median_micros: u64,
    pub std_deviation: f64,
    pub p95_micros: u64,
    pub p99_micros: u64,
    pub anomaly_count: u32,
}

impl OperationTimingStats {
    pub fn from_timings(operation: SecurityOperation, timings: &[SecurityTiming]) -> Self {
        if timings.is_empty() {
            return Self {
                operation,
                sample_count: 0,
                min_micros: 0,
                max_micros: 0,
                avg_micros: 0.0,
                median_micros: 0,
                std_deviation: 0.0,
                p95_micros: 0,
                p99_micros: 0,
                anomaly_count: 0,
            };
        }

        let mut durations: Vec<u64> = timings.iter().map(|t| t.duration_micros).collect();
        durations.sort_unstable();

        let sample_count = durations.len() as u64;
        let min_micros = durations[0];
        let max_micros = durations[durations.len() - 1];
        let avg_micros = durations.iter().sum::<u64>() as f64 / durations.len() as f64;

        let median_micros = if durations.len() % 2 == 0 {
            (durations[durations.len() / 2 - 1] + durations[durations.len() / 2]) / 2
        } else {
            durations[durations.len() / 2]
        };

        // Calculate standard deviation
        let variance = durations
            .iter()
            .map(|&d| (d as f64 - avg_micros).powi(2))
            .sum::<f64>()
            / durations.len() as f64;
        let std_deviation = variance.sqrt();

        // Calculate percentiles
        let p95_index = ((durations.len() as f64) * 0.95) as usize;
        let p99_index = ((durations.len() as f64) * 0.99) as usize;
        let p95_micros = durations[p95_index.min(durations.len() - 1)];
        let p99_micros = durations[p99_index.min(durations.len() - 1)];

        // Count anomalies (values beyond 3 standard deviations)
        let anomaly_threshold = avg_micros + (3.0 * std_deviation);
        let anomaly_count = durations
            .iter()
            .filter(|&&d| d as f64 > anomaly_threshold)
            .count() as u32;

        Self {
            operation,
            sample_count,
            min_micros,
            max_micros,
            avg_micros,
            median_micros,
            std_deviation,
            p95_micros,
            p99_micros,
            anomaly_count,
        }
    }

    pub fn is_healthy(&self) -> bool {
        // Consider healthy if:
        // 1. Low anomaly rate (< 1%)
        // 2. Reasonable standard deviation (< 50% of average)
        // 3. P99 latency is reasonable (< 10x average)

        let anomaly_rate = if self.sample_count > 0 {
            self.anomaly_count as f64 / self.sample_count as f64
        } else {
            0.0
        };

        anomaly_rate < 0.01
            && self.std_deviation < (self.avg_micros * 0.5)
            && self.p99_micros < (self.avg_micros * 10.0) as u64
    }
}

/// Main security performance monitor
pub struct SecurityPerformanceMonitor {
    // Timing data
    timing_data: Arc<RwLock<HashMap<SecurityOperation, VecDeque<SecurityTiming>>>>,

    // Resource monitoring
    resource_history: Arc<RwLock<VecDeque<ResourceUsage>>>,

    // Authentication patterns
    auth_patterns: Arc<RwLock<HashMap<String, AuthenticationPattern>>>,

    // DoS detection
    dos_patterns: Arc<RwLock<Vec<DoSPattern>>>,

    // Current metrics
    current_metrics: Arc<RwLock<SecurityPerformanceMetrics>>,

    // Baseline performance data
    baselines: Arc<RwLock<HashMap<SecurityOperation, OperationTimingStats>>>,

    // Configuration
    config: SecurityMonitoringConfig,
}

impl SecurityPerformanceMonitor {
    /// Create new security performance monitor
    pub fn new(config: SecurityMonitoringConfig) -> Self {
        let initial_metrics = SecurityPerformanceMetrics {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            window_duration_seconds: config.metrics_window_seconds,
            operation_timings: HashMap::new(),
            timing_anomalies_detected: 0,
            potential_timing_attacks: 0,
            authentication_attempts: 0,
            authentication_failures: 0,
            suspicious_patterns: 0,
            brute_force_attempts: 0,
            avg_cpu_percent: 0.0,
            peak_memory_mb: 0,
            active_sessions_peak: 0,
            rate_limit_violations: 0,
            dos_patterns_detected: 0,
            dos_mitigation_activated: false,
            security_health_score: 1.0,
        };

        Self {
            timing_data: Arc::new(RwLock::new(HashMap::new())),
            resource_history: Arc::new(RwLock::new(VecDeque::new())),
            auth_patterns: Arc::new(RwLock::new(HashMap::new())),
            dos_patterns: Arc::new(RwLock::new(Vec::new())),
            current_metrics: Arc::new(RwLock::new(initial_metrics)),
            baselines: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create monitor for testing
    pub fn for_testing() -> Self {
        Self::new(SecurityMonitoringConfig::for_testing())
    }

    /// Record timing for a security operation
    pub async fn record_timing(
        &self,
        operation: SecurityOperation,
        duration: Duration,
        success: bool,
        context: SecurityTimingContext,
    ) -> Result<SecurityThreatAssessment> {
        let timing = SecurityTiming::new(operation.clone(), duration, success, context.clone());

        // Store timing data
        {
            let mut timing_data = self
                .timing_data
                .write()
                .map_err(|_| crypto_error!("Failed to lock timing data"))?;

            let operation_timings = timing_data
                .entry(operation.clone())
                .or_insert_with(VecDeque::new);
            operation_timings.push_back(timing.clone());

            // Maintain size limit
            while operation_timings.len() > MAX_TIMING_SAMPLES {
                operation_timings.pop_front();
            }
        }

        // **NEW: Immediately aggregate authentication patterns**
        if matches!(
            operation,
            SecurityOperation::SecureLogin | SecurityOperation::SessionValidation
        ) {
            self.update_auth_pattern_immediately(&timing, success)
                .await?;
        }

        // Analyze for threats
        let threat_assessment = self.analyze_timing_threat(&timing).await?;

        Ok(threat_assessment)
    }

    /// **NEW: Immediately aggregate individual login attempts into AuthenticationPattern**
    async fn update_auth_pattern_immediately(
        &self,
        timing: &SecurityTiming,
        success: bool,
    ) -> Result<()> {
        if let Some(voter_hash) = &timing.context.voter_hash {
            let mut auth_patterns = self
                .auth_patterns
                .write()
                .map_err(|_| crypto_error!("Failed to write auth patterns"))?;

            let pattern = auth_patterns
                .entry(voter_hash.clone())
                .or_insert_with(|| AuthenticationPattern::new(voter_hash.clone()));

            let timing_anomaly =
                timing.duration_micros > (self.config.timing_anomaly_threshold_micros * 2);
            pattern.record_attempt(success, timing_anomaly);

            // **CRITICAL**: Immediately calculate if this pattern is now suspicious
            // This ensures get_auth_patterns() returns detectable patterns right away
        }

        Ok(())
    }

    /// Get authentication patterns analysis - **FIXED: Now returns immediately aggregated patterns**
    pub async fn get_auth_patterns(&self) -> Result<Vec<AuthenticationPattern>> {
        let auth_patterns = self
            .auth_patterns
            .read()
            .map_err(|_| crypto_error!("Failed to read auth patterns"))?;

        // Return all patterns (they're already aggregated immediately when recorded)
        Ok(auth_patterns.values().cloned().collect())
    }

    /// Record resource usage
    pub async fn record_resource_usage(&self, usage: ResourceUsage) -> Result<()> {
        {
            let mut resource_history = self
                .resource_history
                .write()
                .map_err(|_| crypto_error!("Failed to lock resource history"))?;

            resource_history.push_back(usage.clone());

            // Maintain size limit
            while resource_history.len() > MAX_RESOURCE_SAMPLES {
                resource_history.pop_front();
            }
        }

        // Check for DoS patterns
        self.detect_dos_patterns(&usage).await?;

        Ok(())
    }

    /// Get current security performance metrics
    pub async fn get_current_metrics(&self) -> Result<SecurityPerformanceMetrics> {
        self.update_metrics_window().await?;

        let metrics = self
            .current_metrics
            .read()
            .map_err(|_| crypto_error!("Failed to read current metrics"))?;

        Ok(metrics.clone())
    }

    /// Get operation timing statistics
    pub async fn get_timing_stats(
        &self,
        operation: &SecurityOperation,
    ) -> Result<Option<OperationTimingStats>> {
        let timing_data = self
            .timing_data
            .read()
            .map_err(|_| crypto_error!("Failed to read timing data"))?;

        if let Some(timings) = timing_data.get(operation) {
            let timings_vec: Vec<SecurityTiming> = timings.iter().cloned().collect();
            Ok(Some(OperationTimingStats::from_timings(
                operation.clone(),
                &timings_vec,
            )))
        } else {
            Ok(None)
        }
    }

    /// Get detected DoS patterns
    pub async fn get_dos_patterns(&self) -> Result<Vec<DoSPattern>> {
        let dos_patterns = self
            .dos_patterns
            .read()
            .map_err(|_| crypto_error!("Failed to read DoS patterns"))?;

        Ok(dos_patterns.clone())
    }

    /// Update performance baselines
    pub async fn update_baselines(&self) -> Result<()> {
        let timing_data = self
            .timing_data
            .read()
            .map_err(|_| crypto_error!("Failed to read timing data"))?;

        let mut baselines = self
            .baselines
            .write()
            .map_err(|_| crypto_error!("Failed to write baselines"))?;

        for (operation, timings) in timing_data.iter() {
            let timings_vec: Vec<SecurityTiming> = timings.iter().cloned().collect();
            let stats = OperationTimingStats::from_timings(operation.clone(), &timings_vec);
            baselines.insert(operation.clone(), stats);
        }

        tracing::info!(
            "📊 Security performance baselines updated for {} operations",
            baselines.len()
        );

        Ok(())
    }

    /// Private helper methods
    async fn analyze_timing_threat(
        &self,
        timing: &SecurityTiming,
    ) -> Result<SecurityThreatAssessment> {
        let mut assessment = SecurityThreatAssessment {
            threat_level: ThreatLevel::None,
            threat_type: None,
            confidence: 0.0,
            details: String::new(),
            recommended_actions: Vec::new(),
        };

        // Check against baseline
        let baselines = self
            .baselines
            .read()
            .map_err(|_| crypto_error!("Failed to read baselines"))?;

        if let Some(baseline) = baselines.get(&timing.operation) {
            if timing.is_anomalous(baseline.avg_micros as u64) {
                assessment.threat_level = ThreatLevel::Medium;
                assessment.threat_type = Some(ThreatType::TimingAttack);
                assessment.confidence = 0.7;
                assessment.details = format!(
                    "Timing anomaly detected: {}μs vs baseline {}μs",
                    timing.duration_micros, baseline.avg_micros
                );
                assessment
                    .recommended_actions
                    .push("Monitor for timing attack patterns".to_string());
            }
        }

        Ok(assessment)
    }

    #[allow(dead_code)]
    async fn update_auth_pattern(&self, timing: &SecurityTiming, success: bool) -> Result<()> {
        if let Some(voter_hash) = &timing.context.voter_hash {
            let mut auth_patterns = self
                .auth_patterns
                .write()
                .map_err(|_| crypto_error!("Failed to write auth patterns"))?;

            let pattern = auth_patterns
                .entry(voter_hash.clone())
                .or_insert_with(|| AuthenticationPattern::new(voter_hash.clone()));

            let timing_anomaly = timing.duration_micros > (TIMING_ATTACK_THRESHOLD_MICROS * 2);
            pattern.record_attempt(success, timing_anomaly);
        }

        Ok(())
    }

    async fn detect_dos_patterns(&self, usage: &ResourceUsage) -> Result<()> {
        let mut detected_patterns = Vec::new();

        // Check resource exhaustion
        if usage.memory_mb > DOS_MEMORY_THRESHOLD_MB {
            detected_patterns.push(DoSPattern {
                pattern_id: Uuid::new_v4().to_string(),
                detection_type: DoSDetectionType::MemoryExhaustion,
                severity: DoSSeverity::High,
                start_time: usage.timestamp,
                peak_time: Some(usage.timestamp),
                duration_seconds: 0,
                affected_operations: vec![SecurityOperation::SecureMemoryAllocation],
                mitigation_applied: false,
            });
        }

        // Check CPU exhaustion
        if usage.cpu_percent > DOS_CPU_THRESHOLD_PERCENT {
            detected_patterns.push(DoSPattern {
                pattern_id: Uuid::new_v4().to_string(),
                detection_type: DoSDetectionType::ResourceExhaustion,
                severity: DoSSeverity::Medium,
                start_time: usage.timestamp,
                peak_time: Some(usage.timestamp),
                duration_seconds: 0,
                affected_operations: vec![
                    SecurityOperation::TokenValidation,
                    SecurityOperation::VoterHashGeneration,
                ],
                mitigation_applied: false,
            });
        }

        // Store detected patterns
        if !detected_patterns.is_empty() {
            let mut dos_patterns = self
                .dos_patterns
                .write()
                .map_err(|_| crypto_error!("Failed to write DoS patterns"))?;

            dos_patterns.extend(detected_patterns);

            // Keep only recent patterns (last 24 hours)
            let cutoff_time = usage.timestamp - 86400;
            dos_patterns.retain(|pattern| pattern.start_time > cutoff_time);
        }

        Ok(())
    }

    async fn update_metrics_window(&self) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timing_data = self
            .timing_data
            .read()
            .map_err(|_| crypto_error!("Failed to read timing data"))?;

        let auth_patterns = self
            .auth_patterns
            .read()
            .map_err(|_| crypto_error!("Failed to read auth patterns"))?;

        let resource_history = self
            .resource_history
            .read()
            .map_err(|_| crypto_error!("Failed to read resource history"))?;

        let dos_patterns = self
            .dos_patterns
            .read()
            .map_err(|_| crypto_error!("Failed to read DoS patterns"))?;

        // Calculate metrics for current window
        let mut operation_timings = HashMap::new();
        let mut timing_anomalies = 0;

        for (operation, timings) in timing_data.iter() {
            let recent_timings: Vec<SecurityTiming> = timings
                .iter()
                .filter(|t| now - t.timestamp < self.config.metrics_window_seconds)
                .cloned()
                .collect();

            if !recent_timings.is_empty() {
                let stats = OperationTimingStats::from_timings(operation.clone(), &recent_timings);
                timing_anomalies += stats.anomaly_count;
                operation_timings.insert(operation.clone(), stats);
            }
        }

        // Calculate authentication metrics
        let suspicious_patterns = auth_patterns
            .values()
            .filter(|pattern| pattern.is_suspicious())
            .count() as u32;

        let brute_force_attempts = auth_patterns
            .values()
            .filter(|pattern| pattern.failed_attempts > 10)
            .count() as u32;

        // Calculate resource metrics
        let recent_resources: Vec<&ResourceUsage> = resource_history
            .iter()
            .filter(|r| now - r.timestamp < self.config.metrics_window_seconds)
            .collect();

        let (avg_cpu, peak_memory, peak_sessions, rate_limit_violations) = if !recent_resources
            .is_empty()
        {
            let avg_cpu = recent_resources.iter().map(|r| r.cpu_percent).sum::<f64>()
                / recent_resources.len() as f64;
            let peak_memory = recent_resources
                .iter()
                .map(|r| r.memory_mb)
                .max()
                .unwrap_or(0);
            let peak_sessions = recent_resources
                .iter()
                .map(|r| r.active_sessions)
                .max()
                .unwrap_or(0);
            let total_rate_violations = recent_resources.iter().map(|r| r.rate_limit_hits).sum();
            (avg_cpu, peak_memory, peak_sessions, total_rate_violations)
        } else {
            (0.0, 0, 0, 0)
        };

        // Calculate security health score
        let security_health_score = self.calculate_security_health_score(
            timing_anomalies,
            suspicious_patterns,
            avg_cpu,
            dos_patterns.len() as u32,
        );

        // Update current metrics
        {
            let mut current_metrics = self
                .current_metrics
                .write()
                .map_err(|_| crypto_error!("Failed to write current metrics"))?;

            *current_metrics = SecurityPerformanceMetrics {
                timestamp: now,
                window_duration_seconds: self.config.metrics_window_seconds,
                operation_timings,
                timing_anomalies_detected: timing_anomalies,
                potential_timing_attacks: timing_anomalies / 10, // Estimate
                authentication_attempts: auth_patterns
                    .values()
                    .map(|p| p.success_count + p.failed_attempts)
                    .sum::<u32>() as u64,
                authentication_failures: auth_patterns
                    .values()
                    .map(|p| p.failed_attempts)
                    .sum::<u32>() as u64,
                suspicious_patterns,
                brute_force_attempts,
                avg_cpu_percent: avg_cpu,
                peak_memory_mb: peak_memory,
                active_sessions_peak: peak_sessions,
                rate_limit_violations,
                dos_patterns_detected: dos_patterns.len() as u32,
                dos_mitigation_activated: dos_patterns.iter().any(|p| p.mitigation_applied),
                security_health_score,
            };
        }

        Ok(())
    }

    fn calculate_security_health_score(
        &self,
        timing_anomalies: u32,
        suspicious_patterns: u32,
        avg_cpu: f64,
        dos_patterns: u32,
    ) -> f64 {
        let mut score = 1.0;

        // Reduce score for timing anomalies
        score -= (timing_anomalies as f64 / 100.0).min(0.3);

        // Reduce score for suspicious authentication patterns
        score -= (suspicious_patterns as f64 / 10.0).min(0.3);

        // Reduce score for high CPU usage
        if avg_cpu > 70.0 {
            score -= ((avg_cpu - 70.0) / 30.0).min(0.2);
        }

        // Reduce score for DoS patterns
        score -= (dos_patterns as f64 / 5.0).min(0.2);

        score.max(0.0)
    }
}

/// Security threat assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityThreatAssessment {
    pub threat_level: ThreatLevel,
    pub threat_type: Option<ThreatType>,
    pub confidence: f64,
    pub details: String,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    TimingAttack,
    DoSAttack,
    BruteForce,
    ResourceExhaustion,
    AuthenticationPattern,
}

/// Configuration for security monitoring
#[derive(Debug, Clone)]
pub struct SecurityMonitoringConfig {
    pub metrics_window_seconds: u64,
    pub timing_anomaly_threshold_micros: u64,
    pub dos_detection_enabled: bool,
    pub authentication_pattern_analysis: bool,
    pub baseline_update_interval_seconds: u64,
}

impl Default for SecurityMonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_window_seconds: 300, // 5 minutes
            timing_anomaly_threshold_micros: TIMING_ATTACK_THRESHOLD_MICROS,
            dos_detection_enabled: true,
            authentication_pattern_analysis: true,
            baseline_update_interval_seconds: 3600, // 1 hour
        }
    }
}

impl SecurityMonitoringConfig {
    pub fn for_testing() -> Self {
        Self {
            metrics_window_seconds: 60,          // 1 minute for testing
            timing_anomaly_threshold_micros: 10, // Lower threshold for testing
            dos_detection_enabled: true,
            authentication_pattern_analysis: true,
            baseline_update_interval_seconds: 60, // 1 minute for testing
        }
    }
}

/// Interface for future layer integration
pub trait LayerSecurityIntegration {
    /// Called by web layer to provide HTTP context
    fn provide_web_context(
        &self,
        request_id: String,
        client_ip: Option<String>,
        user_agent: Option<String>,
    );

    /// Called by DB layer to provide database operation context
    fn provide_db_context(&self, query_type: String, execution_time: Duration, affected_rows: u64);

    /// Called to get security events for upper layers
    fn get_security_events_for_layer(&self, layer: LayerType, since: u64) -> Vec<SecurityEvent>;
}

#[derive(Debug, Clone)]
pub enum LayerType {
    Database,
    Web,
    Infrastructure,
}

/// Future: Timer-based security operation measurement
pub struct SecurityTimer {
    operation: SecurityOperation,
    context: SecurityTimingContext,
    start_time: Instant,
}

impl SecurityTimer {
    pub fn start(operation: SecurityOperation, context: SecurityTimingContext) -> Self {
        Self {
            operation,
            context,
            start_time: Instant::now(),
        }
    }

    pub async fn finish(
        self,
        success: bool,
        monitor: &SecurityPerformanceMonitor,
    ) -> Result<SecurityThreatAssessment> {
        let duration = self.start_time.elapsed();
        monitor
            .record_timing(self.operation, duration, success, self.context)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_performance_monitor_creation() {
        let monitor = SecurityPerformanceMonitor::for_testing();
        let metrics = monitor.get_current_metrics().await.unwrap();

        assert_eq!(metrics.security_health_score, 1.0);
        assert_eq!(metrics.timing_anomalies_detected, 0);

        println!("✅ Security performance monitor created successfully");
    }

    #[tokio::test]
    async fn test_timing_measurement_and_analysis() {
        let monitor = SecurityPerformanceMonitor::for_testing();

        let context = SecurityTimingContext {
            voter_hash: Some("test_voter".to_string()),
            election_id: Some(Uuid::new_v4()),
            ..Default::default()
        };

        // Record normal timing
        let normal_duration = Duration::from_micros(100);
        let assessment1 = monitor
            .record_timing(
                SecurityOperation::TokenValidation,
                normal_duration,
                true,
                context.clone(),
            )
            .await
            .unwrap();

        assert_eq!(assessment1.threat_level, ThreatLevel::None);

        // Record anomalous timing
        let anomalous_duration = Duration::from_millis(100); // Much longer
        let _assessment2 = monitor
            .record_timing(
                SecurityOperation::TokenValidation,
                anomalous_duration,
                true,
                context,
            )
            .await
            .unwrap();

        // Update baselines first
        monitor.update_baselines().await.unwrap();

        // Get timing stats
        let stats = monitor
            .get_timing_stats(&SecurityOperation::TokenValidation)
            .await
            .unwrap();
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.sample_count, 2);

        println!("✅ Timing measurement and analysis works");
        println!("   Normal duration: {}μs", normal_duration.as_micros());
        println!(
            "   Anomalous duration: {}μs",
            anomalous_duration.as_micros()
        );
        println!(
            "   Stats: avg={}μs, max={}μs",
            stats.avg_micros, stats.max_micros
        );
    }

    #[tokio::test]
    async fn test_authentication_pattern_analysis() {
        let monitor = SecurityPerformanceMonitor::for_testing();

        let voter_hash = "suspicious_voter".to_string();
        let context = SecurityTimingContext {
            voter_hash: Some(voter_hash.clone()),
            election_id: Some(Uuid::new_v4()),
            ..Default::default()
        };

        // Simulate multiple failed login attempts
        for i in 0..10 {
            let success = i % 5 == 0; // Mostly failures
            monitor
                .record_timing(
                    SecurityOperation::SecureLogin,
                    Duration::from_millis(50),
                    success,
                    context.clone(),
                )
                .await
                .unwrap();
        }

        let auth_patterns = monitor.get_auth_patterns().await.unwrap();
        assert!(!auth_patterns.is_empty());

        let pattern = auth_patterns
            .iter()
            .find(|p| p.voter_hash == voter_hash)
            .unwrap();

        assert!(pattern.failed_attempts > 5);
        assert!(pattern.suspicious_score > 0.0);

        println!("✅ Authentication pattern analysis works");
        println!("   Failed attempts: {}", pattern.failed_attempts);
        println!("   Suspicious score: {:.2}", pattern.suspicious_score);
        println!("   Is suspicious: {}", pattern.is_suspicious());
    }

    #[tokio::test]
    async fn test_resource_monitoring_and_dos_detection() {
        let monitor = SecurityPerformanceMonitor::for_testing();

        // Record normal resource usage
        let normal_usage = ResourceUsage {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cpu_percent: 20.0,
            memory_mb: 100,
            active_sessions: 50,
            pending_operations: 10,
            rate_limit_hits: 0,
        };

        monitor.record_resource_usage(normal_usage).await.unwrap();

        // Record high resource usage (potential DoS)
        let high_usage = ResourceUsage {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cpu_percent: 95.0, // Very high CPU
            memory_mb: 600,    // High memory
            active_sessions: 1000,
            pending_operations: 500,
            rate_limit_hits: 100,
        };

        monitor.record_resource_usage(high_usage).await.unwrap();

        let dos_patterns = monitor.get_dos_patterns().await.unwrap();
        assert!(!dos_patterns.is_empty());

        let cpu_pattern = dos_patterns
            .iter()
            .find(|p| matches!(p.detection_type, DoSDetectionType::ResourceExhaustion))
            .unwrap();

        assert!(matches!(
            cpu_pattern.severity,
            DoSSeverity::Medium | DoSSeverity::High
        ));

        println!("✅ Resource monitoring and DoS detection works");
        println!("   DoS patterns detected: {}", dos_patterns.len());
        println!("   CPU pattern severity: {:?}", cpu_pattern.severity);
    }

    #[tokio::test]
    async fn test_security_timer_convenience() {
        let monitor = SecurityPerformanceMonitor::for_testing();

        let context = SecurityTimingContext {
            voter_hash: Some("timer_test_voter".to_string()),
            ..Default::default()
        };

        // Test security timer
        let timer = SecurityTimer::start(SecurityOperation::VotingLockAcquisition, context);

        // Simulate some work
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let assessment = timer.finish(true, &monitor).await.unwrap();

        // Should be no threat for normal timing
        assert_eq!(assessment.threat_level, ThreatLevel::None);

        let metrics = monitor.get_current_metrics().await.unwrap();
        assert!(
            metrics
                .operation_timings
                .contains_key(&SecurityOperation::VotingLockAcquisition)
        );

        println!("✅ Security timer convenience functionality works");
    }

    #[tokio::test]
    async fn test_security_health_score_calculation() {
        let monitor = SecurityPerformanceMonitor::for_testing();

        // Start with perfect health
        let initial_metrics = monitor.get_current_metrics().await.unwrap();
        assert_eq!(initial_metrics.security_health_score, 1.0);

        // Add some problematic patterns
        for i in 0..20 {
            let suspicious_context = SecurityTimingContext {
                voter_hash: Some(format!("attacker_{i}")),
                ..Default::default()
            };

            // Failed authentication attempts
            monitor
                .record_timing(
                    SecurityOperation::SecureLogin,
                    Duration::from_millis(200), // Slower timing
                    false,                      // Failed
                    suspicious_context,
                )
                .await
                .unwrap();
        }

        // Record high resource usage
        let high_usage = ResourceUsage {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            cpu_percent: 85.0,
            memory_mb: 400,
            active_sessions: 200,
            pending_operations: 100,
            rate_limit_hits: 50,
        };

        monitor.record_resource_usage(high_usage).await.unwrap();

        let final_metrics = monitor.get_current_metrics().await.unwrap();

        // Health score should be reduced
        assert!(final_metrics.security_health_score < 1.0);
        assert!(final_metrics.authentication_failures > 0);
        assert!(final_metrics.avg_cpu_percent > 80.0);

        println!("✅ Security health score calculation works");
        println!(
            "   Initial health: {:.2}",
            initial_metrics.security_health_score
        );
        println!(
            "   Final health: {:.2}",
            final_metrics.security_health_score
        );
        println!(
            "   Auth failures: {}",
            final_metrics.authentication_failures
        );
        println!("   Avg CPU: {:.1}%", final_metrics.avg_cpu_percent);
    }
}
