//! Diagnosis Engine - Correlate test results and provide recommendations

use serde::{Deserialize, Serialize};

use crate::network_tests::{HttpsTestResult, HttpsDiagnosis};
use crate::noc_metrics::threshold::{CompareOp, ThresholdConfig, ThresholdProfile, WindowType};
use crate::noc_metrics::window::Sample;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnosis {
    pub issue: DiagnosisIssue,
    pub severity: Severity,
    pub description: String,
    pub recommendation: String,
    pub related_tests: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DiagnosisIssue {
    MtuBlackhole,
    TcpSegmentationLimit,
    DnsFailure,
    PortBlocking,
    HighLatency,
    PacketLoss,
    PathMtuMismatch,
    BlackholeScore,
}

#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,  // Service unusable
    High,      // Major functionality broken
    Medium,    // Performance degraded
    Low,       // Minor issue
    Info,      // Informational
}

pub trait DiagnosisRule {
    fn name(&self) -> &str;
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis>;
}

#[derive(Debug, Clone, Default)]
pub struct DiagnosisEvidence {
    pub https_result: Option<HttpsTestResult>,
    pub interface_mtu: Option<usize>,
    pub icmp_mtu: Option<usize>,
    pub tcp_mtu: Option<usize>,
    pub tcp_segment_limit: Option<usize>,
    // New fields for enhanced rules
    pub ping_success: Option<bool>,
    pub tcp_connect_success: Option<bool>,
    pub dns_resolution_time_ms: Option<f64>,
    pub dns_success: Option<bool>,
    pub packet_loss_percent: Option<f64>,
    pub rtt_ms: Option<f64>,
    /// Optional time-series samples backing `packet_loss_percent`/`rtt_ms`
    /// for callers (e.g. a monitoring loop) that have more than one
    /// measurement to offer. When empty, `HighPacketLossRule`/
    /// `HighLatencyRule` fall back to treating the scalar field above as a
    /// single-sample window, which is exactly equivalent to the old
    /// point-threshold check.
    pub packet_loss_samples: Vec<Sample>,
    pub rtt_samples: Vec<Sample>,
    // Shell-script-equivalent evidence
    pub upload_fail_sizes: Vec<usize>,
    pub ssh_banner_ok: Option<bool>,
    pub ssh_exec_ok: Option<bool>,
    pub printer_fail_sizes: Vec<usize>,
    pub icmp_frag_needed_received: Option<bool>,
}

/// MTU Blackhole Detection Rule
pub struct MtuBlackholeRule;

impl DiagnosisRule for MtuBlackholeRule {
    fn name(&self) -> &str {
        "MTU Blackhole Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let https = evidence.https_result.as_ref()?;
        
        // Signature: TCP OK + TLS timeout + high interface MTU
        if https.tcp_success 
            && https.diagnosis == HttpsDiagnosis::TlsTimeout
            && evidence.interface_mtu.unwrap_or(0) >= 1500 {
            
            // Find suggested MTU
            let suggested_mtu = evidence.tcp_mtu
                .or(evidence.icmp_mtu)
                .map(|m| m - 100)  // Safety margin
                .unwrap_or(1400);
            
            return Some(Diagnosis {
                issue: DiagnosisIssue::MtuBlackhole,
                severity: Severity::Critical,
                description: format!(
                    "MTU blackhole detected on {}. TCP connects but TLS times out. \
                    This occurs when intermediate routers drop large packets without \
                    sending ICMP 'Packet Too Big' messages.",
                    https.target
                ),
                recommendation: format!(
                    "Lower interface MTU to {} bytes:\n\
                    Linux: sudo ip link set dev eth0 mtu {}\n\
                    Windows: netsh interface ipv4 set subinterface \"Ethernet\" mtu={} store=persistent\n\
                    macOS: sudo ifconfig en0 mtu {}",
                    suggested_mtu, suggested_mtu, suggested_mtu, suggested_mtu
                ),
                related_tests: vec![
                    "HTTPS Test".to_string(),
                    "MTU Test".to_string(),
                ],
            });
        }
        
        None
    }
}

/// Path MTU Mismatch Rule
pub struct PathMtuMismatchRule;

impl DiagnosisRule for PathMtuMismatchRule {
    fn name(&self) -> &str {
        "Path MTU Mismatch Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let interface_mtu = evidence.interface_mtu?;
        let icmp_mtu = evidence.icmp_mtu?;
        
        // Path MTU < Interface MTU = potential issue
        if icmp_mtu < interface_mtu && interface_mtu - icmp_mtu > 50 {
            return Some(Diagnosis {
                issue: DiagnosisIssue::PathMtuMismatch,
                severity: Severity::High,
                description: format!(
                    "Path MTU ({} bytes) is lower than interface MTU ({} bytes). \
                    This can cause fragmentation or dropped packets.",
                    icmp_mtu, interface_mtu
                ),
                recommendation: format!(
                    "Consider lowering interface MTU to {} bytes to match path MTU.",
                    icmp_mtu
                ),
                related_tests: vec!["MTU Test".to_string()],
            });
        }
        
        None
    }
}

/// Port Blocking Rule - Ping OK but TCP fails
pub struct PortBlockingRule;

impl DiagnosisRule for PortBlockingRule {
    fn name(&self) -> &str {
        "Port Blocking Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let ping_ok = evidence.ping_success?;
        let tcp_fail = !evidence.tcp_connect_success.unwrap_or(true);
        
        // ICMP works but TCP doesn't = port blocking
        if ping_ok && tcp_fail {
            return Some(Diagnosis {
                issue: DiagnosisIssue::PortBlocking,
                severity: Severity::High,
                description: "Port blocking detected. ICMP (ping) succeeds but TCP connection fails. \
                    This indicates a firewall is blocking TCP traffic while allowing ICMP.".to_string(),
                recommendation: "Check firewall rules:\n\
                    - Verify target firewall allows TCP on the tested port\n\
                    - Check intermediate firewalls/routers\n\
                    - Try different ports (80, 443, 8080)\n\
                    - Contact network administrator if persistent".to_string(),
                related_tests: vec![
                    "Packet Loss Test".to_string(),
                    "TCP Health Test".to_string(),
                ],
            });
        }
        
        None
    }
}

/// DNS Issues Rule - Slow or failed resolution
pub struct DnsIssuesRule;

impl DiagnosisRule for DnsIssuesRule {
    fn name(&self) -> &str {
        "DNS Issues Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        // Check for DNS failure
        if let Some(false) = evidence.dns_success {
            return Some(Diagnosis {
                issue: DiagnosisIssue::DnsFailure,
                severity: Severity::Critical,
                description: "DNS resolution failed. Unable to resolve hostname to IP address.".to_string(),
                recommendation: "DNS troubleshooting steps:\n\
                    - Check /etc/resolv.conf (Linux/macOS) or DNS settings (Windows)\n\
                    - Try alternative DNS servers: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google)\n\
                    - Verify network connectivity\n\
                    - Check if hostname is correct\n\
                    - Test with: dig <hostname> or nslookup <hostname>".to_string(),
                related_tests: vec!["DNS Test".to_string()],
            });
        }
        
        // Check for slow DNS
        if let Some(time_ms) = evidence.dns_resolution_time_ms {
            if time_ms > 1000.0 {
                return Some(Diagnosis {
                    issue: DiagnosisIssue::DnsFailure,
                    severity: Severity::Medium,
                    description: format!(
                        "Slow DNS resolution detected ({:.0}ms). This can significantly impact application performance.",
                        time_ms
                    ),
                    recommendation: format!(
                        "Improve DNS performance:\n\
                        - Switch to faster DNS servers (current: {:.0}ms)\n\
                        - Try 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google)\n\
                        - Check local DNS cache\n\
                        - Verify DNS server is not overloaded",
                        time_ms
                    ),
                    related_tests: vec!["DNS Test".to_string()],
                });
            }
        }
        
        None
    }
}

/// TCP Segmentation Limit Rule
pub struct TcpSegmentationLimitRule;

impl DiagnosisRule for TcpSegmentationLimitRule {
    fn name(&self) -> &str {
        "TCP Segmentation Limit Detector"
    }
    
    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let segment_limit = evidence.tcp_segment_limit?;
        
        // Artificial limit detected (typically 100-500 bytes)
        if segment_limit < 1000 {
            return Some(Diagnosis {
                issue: DiagnosisIssue::TcpSegmentationLimit,
                severity: Severity::High,
                description: format!(
                    "Artificial TCP segment size limit detected ({} bytes). \
                    A firewall or middlebox is limiting TCP segment sizes, which severely impacts performance.",
                    segment_limit
                ),
                recommendation: format!(
                    "Address TCP segmentation restriction:\n\
                    - Check firewall rules for TCP segment size limits\n\
                    - Review DPI (Deep Packet Inspection) settings\n\
                    - Contact ISP if using VPN or proxy\n\
                    - Current limit: {} bytes (normal: ~1460 bytes)",
                    segment_limit
                ),
                related_tests: vec![
                    "TCP Segmentation Test".to_string(),
                    "TCP Health Test".to_string(),
                ],
            });
        }
        
        None
    }
}

/// Default packet-loss `ThresholdProfile`, adapted from NOC's
/// `pm.models.thresholdprofile.ThresholdProfile`: rungs are ordered
/// most-severe-first, each with its own open condition and a looser clear
/// condition to give hysteresis. `window_function = "avg"` smooths a
/// multi-sample window (e.g. from a monitoring loop feeding
/// `packet_loss_samples`); with a single sample it is numerically
/// identical to a plain point check, which is what `report`'s one-shot use
/// gets today.
pub fn packet_loss_profile() -> ThresholdProfile {
    ThresholdProfile {
        name: "packet_loss",
        window_type: WindowType::Measurements,
        window: 5,
        window_function: "avg",
        thresholds: vec![
            ThresholdConfig::new("high", CompareOp::Ge, 10.0, CompareOp::Lt, 8.0),
            ThresholdConfig::new("medium", CompareOp::Ge, 1.0, CompareOp::Lt, 0.5),
        ],
    }
}

/// Default RTT/latency `ThresholdProfile` -- see `packet_loss_profile` for
/// the rationale.
pub fn latency_profile() -> ThresholdProfile {
    ThresholdProfile {
        name: "latency",
        window_type: WindowType::Measurements,
        window: 5,
        window_function: "avg",
        thresholds: vec![ThresholdConfig::new(
            "medium",
            CompareOp::Gt,
            200.0,
            CompareOp::Le,
            180.0,
        )],
    }
}

/// High Packet Loss Rule -- backed by a NOC-style [`ThresholdProfile`]
/// (see `noc_metrics::threshold`) instead of a bare `if`/`else` on magic
/// numbers. Prefers `evidence.packet_loss_samples` (a real window) when the
/// caller supplied one, and otherwise falls back to treating
/// `evidence.packet_loss_percent` as a single-sample window -- which is
/// exactly equivalent to the point check this rule used to do.
pub struct HighPacketLossRule;

impl DiagnosisRule for HighPacketLossRule {
    fn name(&self) -> &str {
        "High Packet Loss Detector"
    }

    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let samples: Vec<Sample> = if !evidence.packet_loss_samples.is_empty() {
            evidence.packet_loss_samples.clone()
        } else {
            vec![(0, evidence.packet_loss_percent?)]
        };

        let profile = packet_loss_profile();
        let (loss_percent, matched) = profile.evaluate(&samples).ok().flatten()?;

        let (severity, recommendation) = match matched.label {
            "high" => (
                Severity::High,
                "Investigate packet loss:\n\
                    - Check physical cable connections\n\
                    - Test with different network interfaces\n\
                    - Check for network congestion\n\
                    - Run path analysis to identify problematic hop\n\
                    - Contact ISP if issue persists"
                    .to_string(),
            ),
            _ => (
                Severity::Medium,
                "Monitor packet loss:\n\
                    - Continue monitoring\n\
                    - May affect VoIP, video conferencing\n\
                    - Consider running path analysis"
                    .to_string(),
            ),
        };

        let description = if matched.label == "high" {
            format!(
                "High packet loss detected ({:.1}%). This will significantly impact application performance.",
                loss_percent
            )
        } else {
            format!(
                "Moderate packet loss detected ({:.1}%). May affect real-time applications.",
                loss_percent
            )
        };

        Some(Diagnosis {
            issue: DiagnosisIssue::PacketLoss,
            severity,
            description,
            recommendation,
            related_tests: vec![
                "Packet Loss Test".to_string(),
                "Path Analysis Test".to_string(),
            ],
        })
    }
}

/// High Latency Rule -- see [`HighPacketLossRule`] for the same
/// threshold-profile / windowed-sample rationale.
pub struct HighLatencyRule;

impl DiagnosisRule for HighLatencyRule {
    fn name(&self) -> &str {
        "High Latency Detector"
    }

    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let samples: Vec<Sample> = if !evidence.rtt_samples.is_empty() {
            evidence.rtt_samples.clone()
        } else {
            vec![(0, evidence.rtt_ms?)]
        };

        let profile = latency_profile();
        let (rtt_ms, _matched) = profile.evaluate(&samples).ok().flatten()?;

        Some(Diagnosis {
            issue: DiagnosisIssue::HighLatency,
            severity: Severity::Medium,
            description: format!(
                "High latency detected ({:.1}ms). This may impact interactive applications.",
                rtt_ms
            ),
            recommendation: format!(
                "Reduce latency:\n\
                    - Check for network congestion\n\
                    - Use closer/faster DNS servers\n\
                    - Consider CDN for content delivery\n\
                    - Run path analysis to find slow hops\n\
                    - Current RTT: {:.1}ms (good: <50ms, acceptable: <150ms)",
                rtt_ms
            ),
            related_tests: vec![
                "RTT Test".to_string(),
                "Path Analysis Test".to_string(),
            ],
        })
    }
}

/// Aggregated heuristic score rule (mirrors the shell script's scoring).
pub struct BlackholeScoreRule;

impl BlackholeScoreRule {
    pub fn score(ev: &DiagnosisEvidence) -> (u32, Vec<String>) {
        let mut score = 0u32;
        let mut findings = Vec::new();

        if let Some(mtu) = ev.icmp_mtu.or(ev.tcp_mtu) {
            if mtu < 1500 {
                score += 2;
                findings.push(format!("Observed path MTU appears reduced: ~{}", mtu));
            }
            if mtu < 1400 {
                score += 2;
                findings.push("Path MTU low enough to strongly suspect tunnel overhead".to_string());
            }
        }

        if let Some(https) = &ev.https_result {
            if https.tcp_success
                && (https.diagnosis == HttpsDiagnosis::TlsTimeout
                    || https.diagnosis == HttpsDiagnosis::HttpResponseTimeout
                    || https.diagnosis == HttpsDiagnosis::MtuBlackhole)
            {
                score += 3;
                findings.push(
                    "TCP connect succeeded but TLS/HTTP path looked unhealthy".to_string(),
                );
            }
        }

        if !ev.upload_fail_sizes.is_empty() {
            score += 3;
            findings.push(format!(
                "HTTP POST upload showed trouble at sizes: {:?}",
                ev.upload_fail_sizes
            ));
        }

        if ev.ssh_banner_ok == Some(true) && ev.ssh_exec_ok == Some(false) {
            score += 3;
            findings.push(
                "SSH banner reachable but authenticated data-path test did not complete"
                    .to_string(),
            );
        }

        if !ev.printer_fail_sizes.is_empty() {
            score += 3;
            findings.push(format!(
                "Raw printer bulk stream showed failures at sizes: {:?}",
                ev.printer_fail_sizes
            ));
        }

        if ev.icmp_frag_needed_received == Some(true) {
            score += 2;
            findings.push("ICMP fragmentation-needed responses observed".to_string());
        }

        (score, findings)
    }

    pub fn severity_for_score(score: u32) -> Severity {
        if score >= 6 {
            Severity::Critical
        } else if score >= 3 {
            Severity::High
        } else {
            Severity::Info
        }
    }
}

impl DiagnosisRule for BlackholeScoreRule {
    fn name(&self) -> &str {
        "Blackhole Score"
    }

    fn check(&self, evidence: &DiagnosisEvidence) -> Option<Diagnosis> {
        let (score, findings) = Self::score(evidence);
        if findings.is_empty() && score == 0 {
            return None;
        }
        let severity = Self::severity_for_score(score);
        let verdict = match severity {
            Severity::Critical => "high",
            Severity::High => "moderate",
            _ => "low",
        };
        let mut description = format!(
            "Aggregated blackhole score {} ({} likelihood). Findings:\n",
            score, verdict
        );
        for f in &findings {
            description.push_str("- ");
            description.push_str(f);
            description.push('\n');
        }
        Some(Diagnosis {
            issue: DiagnosisIssue::BlackholeScore,
            severity,
            description,
            recommendation: "Compare against MTU tests and upload sweep before changing MTU. For tunnels, clamp MSS conservatively (max(1200, MSS-20)).".to_string(),
            related_tests: vec![
                "HTTPS Test".to_string(),
                "Upload Size Sweep".to_string(),
                "SSH Data-Path".to_string(),
                "Raw 9100 Bulk Sweep".to_string(),
                "ICMP MTU Discovery".to_string(),
            ],
        })
    }
}

/// Render a README_FIRST-style text report that mirrors the shell script.
pub fn render_unified_report(
    diagnoses: &[Diagnosis],
    evidence: &DiagnosisEvidence,
) -> String {
    let (score, findings) = BlackholeScoreRule::score(evidence);
    let verdict = if score >= 6 {
        "LIKELY_MTU_OR_MSS_BLACKHOLE=high"
    } else if score >= 3 {
        "LIKELY_MTU_OR_MSS_BLACKHOLE=moderate"
    } else {
        "LIKELY_MTU_OR_MSS_BLACKHOLE=low"
    };
    let mut out = String::new();
    out.push_str("=== Findings ===\n");
    if findings.is_empty() {
        out.push_str("- No strong blackhole indicators found from these probes\n");
    } else {
        for f in &findings {
            out.push_str("- ");
            out.push_str(f);
            out.push('\n');
        }
    }
    out.push_str("\n=== Interpretation ===\n");
    out.push_str(verdict);
    out.push('\n');
    if let Some(mtu) = evidence.icmp_mtu.or(evidence.tcp_mtu) {
        let mss_v4 = mtu.saturating_sub(40);
        out.push_str(&format!("SUGGESTED_BASE_MSS_IPV4={}\n", mss_v4));
        let conservative = mss_v4.saturating_sub(20).max(1200);
        out.push_str(&format!("SUGGESTED_CONSERVATIVE_CLAMP={}\n", conservative));
    }
    if !diagnoses.is_empty() {
        out.push_str("\n=== Ranked Diagnoses ===\n");
        for d in diagnoses {
            out.push_str(&format!("- [{:?}] {:?}: {}\n", d.severity, d.issue, d.description.lines().next().unwrap_or("")));
        }
    }
    out.push_str("\n=== Notes ===\n");
    out.push_str("- This score is heuristic, not proof.\n");
    out.push_str("- Strongest evidence: small/control traffic works but larger transfers stall.\n");
    out.push_str("- If a VPN is involved, clamp slightly below the theoretical max.\n");
    out
}

/// Diagnosis Engine - runs all rules
pub struct DiagnosisEngine {
    rules: Vec<Box<dyn DiagnosisRule>>,
}

impl DiagnosisEngine {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn DiagnosisRule>> = vec![
            Box::new(MtuBlackholeRule),
            Box::new(PathMtuMismatchRule),
            Box::new(PortBlockingRule),
            Box::new(DnsIssuesRule),
            Box::new(TcpSegmentationLimitRule),
            Box::new(HighPacketLossRule),
            Box::new(HighLatencyRule),
            Box::new(BlackholeScoreRule),
        ];

        Self { rules }
    }

    pub fn diagnose(&self, evidence: &DiagnosisEvidence) -> Vec<Diagnosis> {
        let mut diagnoses = Vec::new();

        for rule in &self.rules {
            if let Some(diagnosis) = rule.check(evidence) {
                diagnoses.push(diagnosis);
            }
        }

        // Sort by severity
        diagnoses.sort_by(|a, b| b.severity.cmp(&a.severity));

        diagnoses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_tests::HttpsTestResult;
    
    #[test]
    fn test_mtu_blackhole_detection() {
        let mut https_result = HttpsTestResult::new("test.com".to_string());
        https_result.tcp_success = true;
        https_result.diagnosis = HttpsDiagnosis::TlsTimeout;
        
        let evidence = DiagnosisEvidence {
            https_result: Some(https_result),
            interface_mtu: Some(1500),
            icmp_mtu: Some(1400),
            ..Default::default()
        };
        
        let engine = DiagnosisEngine::new();
        let diagnoses = engine.diagnose(&evidence);
        
        assert!(!diagnoses.is_empty());
        // MTU blackhole is Critical, so should be first after sorting
        let has_blackhole = diagnoses.iter().any(|d| d.issue == DiagnosisIssue::MtuBlackhole);
        assert!(has_blackhole, "Should detect MTU blackhole");
        
        // Also has path mismatch
        let has_mismatch = diagnoses.iter().any(|d| d.issue == DiagnosisIssue::PathMtuMismatch);
        assert!(has_mismatch, "Should also detect path MTU mismatch");
    }
    
    #[test]
    fn test_path_mtu_mismatch() {
        let evidence = DiagnosisEvidence {
            interface_mtu: Some(1500),
            icmp_mtu: Some(1400),
            ..Default::default()
        };
        
        let engine = DiagnosisEngine::new();
        let diagnoses = engine.diagnose(&evidence);
        
        let has_mismatch = diagnoses.iter()
            .any(|d| d.issue == DiagnosisIssue::PathMtuMismatch);
        assert!(has_mismatch);
    }

    #[test]
    fn high_packet_loss_rule_matches_the_old_point_thresholds_from_a_single_sample() {
        let engine = DiagnosisEngine::new();

        let high = DiagnosisEvidence { packet_loss_percent: Some(12.0), ..Default::default() };
        let diagnoses = engine.diagnose(&high);
        let d = diagnoses.iter().find(|d| d.issue == DiagnosisIssue::PacketLoss).unwrap();
        assert_eq!(d.severity, Severity::High);

        let medium = DiagnosisEvidence { packet_loss_percent: Some(2.0), ..Default::default() };
        let diagnoses = engine.diagnose(&medium);
        let d = diagnoses.iter().find(|d| d.issue == DiagnosisIssue::PacketLoss).unwrap();
        assert_eq!(d.severity, Severity::Medium);

        let fine = DiagnosisEvidence { packet_loss_percent: Some(0.1), ..Default::default() };
        let diagnoses = engine.diagnose(&fine);
        assert!(!diagnoses.iter().any(|d| d.issue == DiagnosisIssue::PacketLoss));
    }

    #[test]
    fn high_latency_rule_matches_the_old_point_threshold_from_a_single_sample() {
        let engine = DiagnosisEngine::new();

        let slow = DiagnosisEvidence { rtt_ms: Some(250.0), ..Default::default() };
        let diagnoses = engine.diagnose(&slow);
        assert!(diagnoses.iter().any(|d| d.issue == DiagnosisIssue::HighLatency));

        let fine = DiagnosisEvidence { rtt_ms: Some(40.0), ..Default::default() };
        let diagnoses = engine.diagnose(&fine);
        assert!(!diagnoses.iter().any(|d| d.issue == DiagnosisIssue::HighLatency));
    }

    #[test]
    fn packet_loss_rule_windows_multiple_samples_instead_of_only_looking_at_the_last_one() {
        // A single spike among otherwise-clean samples must not, on
        // average, trip the "high" rung -- this is only possible because
        // the rule now runs a window function instead of comparing the
        // latest sample alone.
        let engine = DiagnosisEngine::new();
        let ev = DiagnosisEvidence {
            packet_loss_samples: vec![(0, 0.0), (1, 0.0), (2, 30.0), (3, 0.0), (4, 0.0)],
            ..Default::default()
        };
        let diagnoses = engine.diagnose(&ev);
        let d = diagnoses.iter().find(|d| d.issue == DiagnosisIssue::PacketLoss);
        // Averaged over the 5-sample window the spike works out to 6%,
        // which crosses the "medium" rung but must NOT reach "high" (>=10%)
        // the way comparing only the raw 30% spike would have.
        assert_eq!(d.map(|d| &d.severity), Some(&Severity::Medium));
    }

    #[test]
    fn threshold_state_hysteresis_is_available_for_repeated_evaluation() {
        // Demonstrates that a caller doing repeated evaluation (e.g. a
        // monitoring loop) can opt into stateful hysteresis via
        // `ThresholdState`, rather than the diagnosis engine's stateless
        // per-call check re-triggering on every noisy tick.
        use crate::noc_metrics::threshold::ThresholdState;

        let profile = packet_loss_profile();
        let mut state = ThresholdState::new();

        assert!(state.evaluate(&profile, &[(0, 5.0)]).unwrap().is_some());
        assert!(state.is_open());
        // Dips back under the open threshold (1.0) but not below the clear
        // threshold (0.5): a naive point check would flap closed here.
        assert!(state.evaluate(&profile, &[(1, 0.7)]).unwrap().is_some());
        assert!(state.is_open());
        // Crosses the clear threshold: now it closes.
        assert!(state.evaluate(&profile, &[(2, 0.2)]).unwrap().is_none());
        assert!(!state.is_open());
    }
}

