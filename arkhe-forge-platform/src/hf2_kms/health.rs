//! Multi-channel KMS health check (spec §14.11.2.1 HF2 surface 10).
//!
//! Supplies the N-of-M quorum signal that drives the `observer_state →
//! degraded` transition (metric `arkhe_runtime_kms_health_channels{channel,
//! region}`). Three channel types defend against disjoint network-attack
//! paths:
//!
//! - [`DohHealthChannel`] — DNS-over-HTTPS endpoint reachability
//!   (Cloudflare `1.1.1.1` / Google `8.8.8.8` by default) → mitigates DNS
//!   poisoning.
//! - [`RegionHealthChannel`] — alternate-region KMS endpoint TCP probe →
//!   detects regional outages and BGP partitioning.
//! - [`StaticIpHealthChannel`] — static IP + port probe (e.g. a pinned
//!   KMS VPC endpoint) → survives both DNS and regional CDN hijack.
//!
//! [`ConsensusHealthChecker`] aggregates the three (or more) channels with
//! an N-of-M quorum (default 2-of-3). A single-channel failure is **not**
//! sufficient — two or more concurrent failures are required to fire the
//! auto-promote signal, which prevents a single provider outage or a
//! targeted DNS hijack from driving spurious failovers.
//!
//! ## HTTP client selection — `std::net::TcpStream` only, no `ureq`
//!
//! `KmsBackend` is a sync trait; this module stays sync to match.
//! We probe TCP reachability with [`std::net::TcpStream::connect_timeout`]
//! and do **not** pull in an HTTPS client (`ureq` / `reqwest`). Rationale:
//!
//! 1. v0.11 alpha is pre-tag — any new workspace dep expands the supply
//!    chain surface (`cargo audit` / `cargo deny`).
//! 2. A full HTTPS GET against Cloudflare DoH requires rustls + intermediate
//!    certificate management inside the health loop, which is out of scope
//!    for a "is the KMS path reachable at the L4 layer?" probe.
//! 3. TCP reachability already detects the attacks the HF2 threat model
//!    actually covers (DNS + BGP + regional outage). Full application-layer
//!    HTTPS validation is a future release item.
//!
//! The [`HealthChannel`] trait leaves room for a future `UreqDohChannel` —
//! impls are not sealed.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Health channel identifier — preserved across releases so metric labels
/// stay stable (`arkhe_runtime_kms_health_channels{channel}`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// 일반 DNS / HTTPS resolver — 기본 경로.
    Default,
    /// DNS-over-HTTPS (DoH) 경유 — DNS poisoning mitigation.
    DnsOverHttps,
    /// Static IP + TLS — BGP hijack / DNS 완전 우회.
    StaticIp,
    /// Alternate region endpoint — regional outage 식별.
    AlternateRegion,
}

/// Latest health status of each channel.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// 정상.
    Healthy,
    /// 실패 (timeout / 5xx / network error).
    Failing,
    /// 최초 check 이전.
    Unknown,
}

/// Probe error — distinct from `Status::Failing` (probe executed but failed)
/// when the channel itself is misconfigured (e.g. unresolvable hostname).
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    /// DNS resolution 실패 — channel config 오류 수준.
    #[error("dns resolution failed for {hostport}")]
    DnsResolution {
        /// 원본 host:port 문자열.
        hostport: String,
    },
    /// I/O error — internally mapped from `std::io::Error`.
    #[error("io error: {0}")]
    Io(String),
}

/// Single health-probe channel.
///
/// Impls are intentionally synchronous — `KmsBackend` is a sync trait and
/// the consensus checker runs probes in-line from the auto_promote
/// evaluator. Future async backends can wrap `tokio::task::block_in_place`
/// but must not leak async surface.
pub trait HealthChannel: Send + Sync {
    /// Channel identifier for metric / logging.
    fn channel_id(&self) -> Channel;
    /// Perform one probe. Returns `Healthy` / `Failing` (probe executed) or
    /// `HealthError` (channel config broken).
    fn probe(&self) -> Result<Status, HealthError>;
}

fn tcp_reachable(hostport: &str, timeout: Duration) -> Result<Status, HealthError> {
    let mut addrs = hostport
        .to_socket_addrs()
        .map_err(|_| HealthError::DnsResolution {
            hostport: hostport.to_string(),
        })?;
    match addrs.next() {
        Some(addr) => match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => Ok(Status::Healthy),
            Err(_) => Ok(Status::Failing),
        },
        None => Err(HealthError::DnsResolution {
            hostport: hostport.to_string(),
        }),
    }
}

fn static_reachable(addr: SocketAddr, timeout: Duration) -> Status {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Status::Healthy,
        Err(_) => Status::Failing,
    }
}

/// DoH endpoint reachability probe. Defaults: Cloudflare `1.1.1.1:443` +
/// Google `8.8.8.8:443` — spec HF2 surface 10.
pub struct DohHealthChannel {
    hostport: String,
    timeout: Duration,
}

impl DohHealthChannel {
    /// Cloudflare DoH default (`1.1.1.1:443`).
    pub fn cloudflare() -> Self {
        Self {
            hostport: "1.1.1.1:443".to_string(),
            timeout: Duration::from_secs(3),
        }
    }

    /// Google DoH default (`8.8.8.8:443`).
    pub fn google() -> Self {
        Self {
            hostport: "8.8.8.8:443".to_string(),
            timeout: Duration::from_secs(3),
        }
    }

    /// Custom DoH endpoint with timeout override.
    pub fn custom(hostport: impl Into<String>, timeout: Duration) -> Self {
        Self {
            hostport: hostport.into(),
            timeout,
        }
    }
}

impl HealthChannel for DohHealthChannel {
    fn channel_id(&self) -> Channel {
        Channel::DnsOverHttps
    }

    fn probe(&self) -> Result<Status, HealthError> {
        tcp_reachable(&self.hostport, self.timeout)
    }
}

/// Alternate-region KMS endpoint probe (DNS resolved hostport).
pub struct RegionHealthChannel {
    hostport: String,
    timeout: Duration,
}

impl RegionHealthChannel {
    /// New alternate-region probe — `hostport` like `kms.eu-central-1.amazonaws.com:443`.
    pub fn new(hostport: impl Into<String>, timeout: Duration) -> Self {
        Self {
            hostport: hostport.into(),
            timeout,
        }
    }
}

impl HealthChannel for RegionHealthChannel {
    fn channel_id(&self) -> Channel {
        Channel::AlternateRegion
    }

    fn probe(&self) -> Result<Status, HealthError> {
        tcp_reachable(&self.hostport, self.timeout)
    }
}

/// Static IP + port probe — bypasses DNS + CDN completely. Operators pin
/// this to a known-good VPC endpoint IP (spec §14.11.2.1 fallback path).
pub struct StaticIpHealthChannel {
    addr: SocketAddr,
    timeout: Duration,
}

impl StaticIpHealthChannel {
    /// New static-IP probe — `addr` is parsed at construction so DNS is
    /// never exercised during probe.
    pub fn new(addr: SocketAddr, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}

impl HealthChannel for StaticIpHealthChannel {
    fn channel_id(&self) -> Channel {
        Channel::StaticIp
    }

    fn probe(&self) -> Result<Status, HealthError> {
        Ok(static_reachable(self.addr, self.timeout))
    }
}

/// Aggregated probe result — returned by [`ConsensusHealthChecker::check`].
#[derive(Debug, Clone)]
pub struct ConsensusResult {
    /// Per-channel probe status (order = channel registration order).
    pub per_channel: Vec<(Channel, Status)>,
    /// `Failing` probe count.
    pub failing_count: usize,
    /// Total channels checked.
    pub total: usize,
    /// `failing_count >= threshold` — quorum-fail reached.
    pub is_quorum_failing: bool,
}

/// Multi-channel consensus health checker (N-of-M quorum).
///
/// Default configuration (HF2 surface 10): 3 channels (DoH / AlternateRegion /
/// StaticIp) with threshold = 2. Two or more concurrent probe failures trigger
/// `is_quorum_failing = true`; the caller (auto_promote evaluator) maps that
/// to `observer_state='degraded'`.
pub struct ConsensusHealthChecker {
    channels: Vec<Box<dyn HealthChannel>>,
    threshold: usize,
}

impl ConsensusHealthChecker {
    /// New checker with an explicit threshold.
    pub fn new(channels: Vec<Box<dyn HealthChannel>>, threshold: usize) -> Self {
        Self {
            channels,
            threshold,
        }
    }

    /// Default HF2 2-of-3 constructor — caller still provides the concrete
    /// channel impls so DI stays explicit.
    pub fn two_of_three(channels: Vec<Box<dyn HealthChannel>>) -> Self {
        assert_eq!(
            channels.len(),
            3,
            "two_of_three requires exactly 3 channels; got {}",
            channels.len()
        );
        Self::new(channels, 2)
    }

    /// Total channels.
    pub fn total(&self) -> usize {
        self.channels.len()
    }

    /// Probe every channel; aggregate result. Probe error on a channel is
    /// treated as `Failing` (conservative) — the channel is unusable, so
    /// from the consensus perspective that is a fail vote.
    pub fn check(&self) -> ConsensusResult {
        let mut per_channel = Vec::with_capacity(self.channels.len());
        let mut failing_count = 0usize;
        for ch in &self.channels {
            let status = ch.probe().unwrap_or(Status::Failing);
            if status == Status::Failing {
                failing_count += 1;
            }
            per_channel.push((ch.channel_id(), status));
        }
        let total = per_channel.len();
        let is_quorum_failing = failing_count >= self.threshold;
        ConsensusResult {
            per_channel,
            failing_count,
            total,
            is_quorum_failing,
        }
    }
}

/// Legacy in-memory aggregator — retained for callers that set status
/// externally (e.g. metric-driven rolling window). New call sites should
/// prefer [`ConsensusHealthChecker`].
pub struct MultiChannelHealth {
    channels: Vec<(Channel, Status)>,
}

impl MultiChannelHealth {
    /// 새 aggregator — 초기에 모든 channel Unknown.
    pub fn new(channels: &[Channel]) -> Self {
        Self {
            channels: channels.iter().map(|c| (*c, Status::Unknown)).collect(),
        }
    }

    /// 개별 channel 의 status 업데이트.
    pub fn set_status(&mut self, channel: Channel, status: Status) {
        for (c, s) in &mut self.channels {
            if *c == channel {
                *s = status;
                return;
            }
        }
        self.channels.push((channel, status));
    }

    /// N-of-M aggregate — 전체 channel 중 `threshold` 개 이상 `Failing` 이면 true.
    ///
    /// HF2 default: M=3 channel (Default / DoH / StaticIp 또는 AlternateRegion) +
    /// threshold=2. 2 이상 실패 시 auto_promote trigger 조건 충족.
    pub fn is_quorum_failing(&self, threshold: usize) -> bool {
        self.channels
            .iter()
            .filter(|(_, s)| *s == Status::Failing)
            .count()
            >= threshold
    }

    /// 현재 healthy channel 개수 — metric export 용.
    pub fn healthy_count(&self) -> usize {
        self.channels
            .iter()
            .filter(|(_, s)| *s == Status::Healthy)
            .count()
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Test double — probes return a pre-baked status without touching the
    /// network.
    struct FakeChannel {
        id: Channel,
        status: Status,
    }

    impl HealthChannel for FakeChannel {
        fn channel_id(&self) -> Channel {
            self.id
        }
        fn probe(&self) -> Result<Status, HealthError> {
            Ok(self.status)
        }
    }

    fn fake(id: Channel, status: Status) -> Box<dyn HealthChannel> {
        Box::new(FakeChannel { id, status })
    }

    #[test]
    fn consensus_single_failure_does_not_trigger() {
        let checker = ConsensusHealthChecker::two_of_three(vec![
            fake(Channel::DnsOverHttps, Status::Healthy),
            fake(Channel::AlternateRegion, Status::Healthy),
            fake(Channel::StaticIp, Status::Failing),
        ]);
        let r = checker.check();
        assert_eq!(r.failing_count, 1);
        assert_eq!(r.total, 3);
        assert!(!r.is_quorum_failing);
    }

    #[test]
    fn consensus_two_of_three_triggers() {
        let checker = ConsensusHealthChecker::two_of_three(vec![
            fake(Channel::DnsOverHttps, Status::Failing),
            fake(Channel::AlternateRegion, Status::Failing),
            fake(Channel::StaticIp, Status::Healthy),
        ]);
        let r = checker.check();
        assert_eq!(r.failing_count, 2);
        assert!(r.is_quorum_failing);
    }

    #[test]
    fn consensus_all_failing_triggers() {
        let checker = ConsensusHealthChecker::two_of_three(vec![
            fake(Channel::DnsOverHttps, Status::Failing),
            fake(Channel::AlternateRegion, Status::Failing),
            fake(Channel::StaticIp, Status::Failing),
        ]);
        let r = checker.check();
        assert_eq!(r.failing_count, 3);
        assert!(r.is_quorum_failing);
    }

    #[test]
    fn explicit_threshold_overrides_default() {
        let checker = ConsensusHealthChecker::new(
            vec![
                fake(Channel::DnsOverHttps, Status::Failing),
                fake(Channel::AlternateRegion, Status::Healthy),
            ],
            1,
        );
        let r = checker.check();
        assert_eq!(r.failing_count, 1);
        assert!(r.is_quorum_failing);
    }

    #[test]
    fn static_ip_channel_records_channel_id() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let ch = StaticIpHealthChannel::new(addr, Duration::from_millis(50));
        assert_eq!(ch.channel_id(), Channel::StaticIp);
        // Probe goes to a closed port; should surface `Failing`, not error.
        let status = ch.probe().unwrap();
        assert!(matches!(status, Status::Failing | Status::Healthy));
    }

    #[test]
    fn doh_defaults_provide_cloudflare_and_google() {
        let cf = DohHealthChannel::cloudflare();
        let gg = DohHealthChannel::google();
        assert_eq!(cf.channel_id(), Channel::DnsOverHttps);
        assert_eq!(gg.channel_id(), Channel::DnsOverHttps);
    }

    #[test]
    fn region_channel_reports_channel_id() {
        let ch = RegionHealthChannel::new("127.0.0.1:1", Duration::from_millis(50));
        assert_eq!(ch.channel_id(), Channel::AlternateRegion);
    }

    // Legacy aggregator kept working.

    #[test]
    fn n_of_m_2_of_3_trigger() {
        let mut h =
            MultiChannelHealth::new(&[Channel::Default, Channel::DnsOverHttps, Channel::StaticIp]);
        h.set_status(Channel::Default, Status::Failing);
        assert!(!h.is_quorum_failing(2));
        h.set_status(Channel::DnsOverHttps, Status::Failing);
        assert!(h.is_quorum_failing(2));
    }

    #[test]
    fn healthy_count_accurate() {
        let mut h = MultiChannelHealth::new(&[Channel::Default, Channel::DnsOverHttps]);
        h.set_status(Channel::Default, Status::Healthy);
        assert_eq!(h.healthy_count(), 1);
    }
}
