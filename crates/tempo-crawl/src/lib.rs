//! tempo-crawl - crawler-facing policy and frontier API.
//!
//! This crate is intentionally thin. `tempo-net` owns URL policy, per-origin
//! scheduling, robots.txt, Retry-After backoff, and request dispatch state; this
//! facade gives SDKs a crawl-focused import surface without duplicating that
//! enforcement logic.
//!
//! SDKs should pass [`NetworkRequest`] values into [`CrawlFrontier`]. The
//! facade delegates canonical crawl request identity, scheduler state, and
//! checked dispatch to tempo-net, but does not expose raw `dispatch_ready()` as a
//! normal method. Only [`CheckedCrawlConnection`] values reached through
//! [`CheckedCrawlDispatch::connection`] have a resolved socket pinned by URL,
//! egress, audit, and optional Web Bot Auth checks. Raw scheduler dispatch types
//! are kept as deprecated compatibility aliases because they have not passed
//! SSRF/egress checks and are not safe as a direct network execution surface.
//!
//! ```compile_fail
//! let mut frontier = tempo_crawl::CrawlFrontier::default();
//! let _ = frontier.dispatch_ready(1, 1);
//! ```

pub use tempo_net::{
    AuditRecord, BlockCode, BlockReason, CheckedCrawlConnection, CheckedCrawlDispatch,
    CrawlCheckedBatch, CrawlConnectionTarget, CrawlDecision, CrawlDispatchError,
    CrawlDispatchGuard, CrawlDispatchSigner, CrawlError, CrawlFrontierSnapshot, CrawlPolicy,
    CrawlScheduler, DomainRule, EgressDenied, EgressPolicy, EgressRecord, IdentityMode,
    NetworkRequest, NetworkResponseRecord, OriginCrawlSnapshot, ProfileId, ProxyRoute,
    RejectedCrawlDispatch, RequestId, RobotsRules, SignatureError, SignatureHeaders, UrlBlocked,
    UrlPolicy, WebBotAuthSigningKey, DEFAULT_CRAWL_MAX_CONCURRENT_PER_ORIGIN,
    DEFAULT_CRAWL_MAX_GLOBAL_INFLIGHT, DEFAULT_CRAWL_MIN_DELAY_TICKS,
};

#[deprecated(
    note = "raw CrawlBatch is scheduler-only; use CrawlCheckedBatch from dispatch_checked_ready before network execution"
)]
#[doc(hidden)]
pub type CrawlBatch = tempo_net::CrawlBatch;

#[deprecated(
    note = "raw CrawlDispatch has not passed URL/socket/egress checks; use CheckedCrawlDispatch before network execution"
)]
#[doc(hidden)]
pub type CrawlDispatch = tempo_net::CrawlDispatch;

/// Human-readable crate summary for smoke tests and package metadata.
pub fn describe() -> &'static str {
    "crawler facade over tempo-net: scheduler primitives plus checked dispatch for network execution"
}

/// SDK-facing crawl frontier.
///
/// This wrapper intentionally omits tempo-net's raw `dispatch_ready()` method so
/// callers use checked dispatch before network execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrawlFrontier {
    inner: tempo_net::CrawlFrontier,
}

impl CrawlFrontier {
    pub fn new(policy: CrawlPolicy) -> Self {
        Self {
            inner: tempo_net::CrawlFrontier::new(policy),
        }
    }

    pub fn scheduler(&self) -> &CrawlScheduler {
        self.inner.scheduler()
    }

    pub fn scheduler_mut(&mut self) -> &mut CrawlScheduler {
        self.inner.scheduler_mut()
    }

    /// Add a request by canonical crawl request identity. Returns `false` when
    /// the same identity is already pending or active.
    pub fn enqueue(&mut self, request: NetworkRequest) -> Result<bool, CrawlError> {
        self.inner.enqueue(request)
    }

    /// Dispatch ready requests only after URL, socket, egress, audit, and
    /// optional signing checks pass.
    pub fn dispatch_checked_ready<F>(
        &mut self,
        tick: u64,
        max_requests: usize,
        guard: CrawlDispatchGuard<'_>,
        resolve_socket: F,
    ) -> Result<CrawlCheckedBatch, CrawlError>
    where
        F: FnMut(CrawlConnectionTarget<'_>) -> Result<std::net::SocketAddr, CrawlDispatchError>,
    {
        self.inner
            .dispatch_checked_ready(tick, max_requests, guard, resolve_socket)
    }

    pub fn finish(&mut self, response: &NetworkResponseRecord, tick: u64) -> bool {
        self.inner.finish(response, tick)
    }

    pub fn snapshot(&self) -> CrawlFrontierSnapshot {
        self.inner.snapshot()
    }
}

impl Default for CrawlFrontier {
    fn default() -> Self {
        Self::new(CrawlPolicy::default())
    }
}

/// Build a crawler frontier with the shared tempo-net policy engine.
pub fn frontier(policy: CrawlPolicy) -> CrawlFrontier {
    CrawlFrontier::new(policy)
}

/// Build the default crawl policy for a named agent user-agent.
pub fn policy_for_agent(user_agent: impl Into<String>) -> CrawlPolicy {
    CrawlPolicy::new(user_agent)
}

/// Build a checked-dispatch guard backed by the shared tempo-net policies.
pub fn checked_dispatch_guard<'a>(
    url_policy: &'a UrlPolicy,
    egress_policy: &'a EgressPolicy,
) -> CrawlDispatchGuard<'a> {
    CrawlDispatchGuard::new(url_policy, egress_policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_reexports_scheduler_contract() -> Result<(), CrawlError> {
        let mut scheduler = CrawlScheduler::new(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_concurrent_per_origin(1)
                .with_min_delay_ticks_per_origin(0),
        );
        let request = crawl_request("crawl-1", "https://example.com/page");
        scheduler.set_robots_for_origin("https://example.com", RobotsRules::allow_all())?;

        assert_eq!(
            scheduler.begin(&request, 1)?,
            CrawlDecision::Allow {
                origin: "https://example.com".into()
            }
        );
        assert_eq!(scheduler.snapshots().len(), 1);
        Ok(())
    }

    #[test]
    fn facade_frontier_delegates_dedupe_and_limits_to_tempo_net() -> Result<(), CrawlError> {
        let mut frontier = frontier(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_global_inflight(2)
                .with_max_concurrent_per_origin(1)
                .with_min_delay_ticks_per_origin(0),
        );
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://a.example", RobotsRules::allow_all())?;
        frontier
            .scheduler_mut()
            .set_robots_for_origin("https://b.example", RobotsRules::allow_all())?;

        assert!(frontier.enqueue(crawl_request("b", "https://b.example/b"))?);
        assert!(frontier.enqueue(crawl_request("a1", "https://a.example/a#ignored"))?);
        assert!(!frontier.enqueue(crawl_request("a1-dup", "https://a.example/a"))?);
        assert!(frontier.enqueue(crawl_request("a2", "https://a.example/c"))?);

        let guard = public_checked_guard();
        let batch = frontier.dispatch_checked_ready(1, 8, guard, |_| {
            Ok(std::net::SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;
        assert_eq!(
            batch
                .dispatches
                .iter()
                .map(|checked| checked.request().id.0.as_str())
                .collect::<Vec<_>>(),
            vec!["a1", "b"]
        );
        assert_eq!(
            batch.waiting,
            vec![CrawlDecision::Wait {
                origin: "https://a.example".into(),
                until_tick: 2,
                reason: "per-origin concurrency cap reached".into(),
            }]
        );
        assert_eq!(frontier.snapshot().pending, 1);
        assert_eq!(frontier.snapshot().inflight, 2);
        Ok(())
    }

    #[test]
    fn facade_frontier_uses_request_identity_for_dedupe() -> Result<(), CrawlError> {
        let mut frontier = frontier(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_max_concurrent_per_origin(4)
                .with_min_delay_ticks_per_origin(0),
        );

        assert!(frontier.enqueue(crawl_request("get-a", "https://example.com/page#one"))?);
        assert!(!frontier.enqueue(crawl_request("get-dup", "https://example.com:443/page#two",))?);
        assert!(!frontier.enqueue(
            crawl_request("get-empty-bytes", "https://example.com/page").with_body_bytes([])
        )?);
        assert!(frontier.enqueue(NetworkRequest::new(
            "get-profile-b",
            "GET",
            "https://example.com/page",
            "profile-b",
            IdentityMode::AgentDeclared,
        ))?);
        assert!(frontier.enqueue(NetworkRequest::new(
            "post-a",
            "POST",
            "https://example.com/page",
            "profile-a",
            IdentityMode::AgentDeclared,
        ))?);
        assert!(frontier.enqueue(NetworkRequest::new(
            "get-user-driven",
            "GET",
            "https://example.com/page",
            "profile-a",
            IdentityMode::UserDriven,
        ))?);

        let guard = public_checked_guard();
        let batch = frontier.dispatch_checked_ready(1, 4, guard, |_| {
            Ok(std::net::SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;
        assert_eq!(batch.dispatches.len(), 4);
        let _request_id: RequestId = batch.dispatches[0].request().id.clone();
        assert!(frontier
            .scheduler()
            .is_url_active("https://example.com/page")?);
        assert!(frontier
            .scheduler()
            .is_request_active(&crawl_request("get-active", "https://example.com/page"))?);
        Ok(())
    }

    #[test]
    fn facade_reexports_checked_dispatch_contract() -> Result<(), CrawlError> {
        let mut frontier = frontier(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "https://example.com/page"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = checked_dispatch_guard(&url_policy, &egress_policy);
        let batch: CrawlCheckedBatch = frontier.dispatch_checked_ready(1, 1, guard, |target| {
            assert!(!target.is_proxied());
            assert_eq!(target.destination_domain(), "example.com");
            assert_eq!(target.destination_port(), 443);
            assert_eq!(target.resolution_endpoint(), "https://example.com/page");
            Ok(std::net::SocketAddr::from(([93, 184, 216, 34], 443)))
        })?;

        assert_eq!(batch.dispatches.len(), 1);
        assert!(batch.rejected.is_empty());
        assert_eq!(batch.dispatches[0].audit.request_id, RequestId("r1".into()));
        let connection: &CheckedCrawlConnection = batch.dispatches[0].connection();
        assert_eq!(connection.request().id, RequestId("r1".into()));
        assert_eq!(
            connection.resolved_socket(),
            std::net::SocketAddr::from(([93, 184, 216, 34], 443))
        );
        assert_eq!(frontier.snapshot().inflight, 1);
        Ok(())
    }

    #[test]
    fn facade_checked_dispatch_rejection_is_not_activated() -> Result<(), CrawlError> {
        let mut frontier = frontier(
            CrawlPolicy::default()
                .without_robots_txt()
                .with_min_delay_ticks_per_origin(0),
        );
        frontier.enqueue(crawl_request("r1", "http://127.0.0.1/private"))?;

        let url_policy = UrlPolicy::block_private();
        let egress_policy = EgressPolicy::allow_all();
        let guard = checked_dispatch_guard(&url_policy, &egress_policy);
        let mut resolve_calls = 0usize;
        let batch = frontier.dispatch_checked_ready(1, 1, guard, |_| {
            resolve_calls += 1;
            Ok(std::net::SocketAddr::from(([127, 0, 0, 1], 80)))
        })?;

        assert_eq!(resolve_calls, 0);
        assert!(batch.dispatches.is_empty());
        assert_eq!(batch.rejected.len(), 1);
        assert!(matches!(
            &batch.rejected[0].error,
            CrawlDispatchError::Url(UrlBlocked { reason }) if reason.code == BlockCode::BlockedIp
        ));
        assert_eq!(frontier.snapshot().inflight, 0);
        assert!(!frontier
            .scheduler()
            .is_url_active("http://127.0.0.1/private")?);
        Ok(())
    }

    #[test]
    fn policy_helper_uses_shared_defaults() {
        let policy = policy_for_agent("tempo-sdk");

        assert_eq!(policy.user_agent, "tempo-sdk");
        assert_eq!(
            policy.max_concurrent_per_origin,
            DEFAULT_CRAWL_MAX_CONCURRENT_PER_ORIGIN
        );
        assert_eq!(
            policy.max_global_inflight,
            DEFAULT_CRAWL_MAX_GLOBAL_INFLIGHT
        );
        assert!(policy.respect_robots_txt);
    }

    fn crawl_request(id: &str, url: &str) -> NetworkRequest {
        NetworkRequest::new(id, "GET", url, "profile-a", IdentityMode::AgentDeclared)
    }

    fn public_checked_guard<'a>() -> CrawlDispatchGuard<'a> {
        static URL_POLICY: std::sync::LazyLock<UrlPolicy> =
            std::sync::LazyLock::new(UrlPolicy::block_private);
        static EGRESS_POLICY: std::sync::LazyLock<EgressPolicy> =
            std::sync::LazyLock::new(EgressPolicy::allow_all);
        checked_dispatch_guard(&URL_POLICY, &EGRESS_POLICY)
    }
}
