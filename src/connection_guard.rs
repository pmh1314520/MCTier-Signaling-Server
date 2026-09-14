use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use tokio_tungstenite::tungstenite::http::HeaderMap;

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

/// Privacy addresses on one IPv6 network must not multiply source quotas.
pub fn quota_source(ip: IpAddr) -> IpAddr {
    match canonical(ip) {
        IpAddr::V6(ip) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
        ip => ip,
    }
}

pub struct Admission {
    pub trusted_proxies: HashSet<IpAddr>,
    pending: Arc<Pool>,
    active: Arc<Pool>,
}

struct Pool {
    limit: usize,
    source_limit: Option<usize>,
    counts: Mutex<(usize, HashMap<IpAddr, usize>)>,
}

/// Handshakes are short-lived, but one source must not consume the complete
/// pre-authentication pool. This limit is independent of the optional active
/// per-source quota.
const DEFAULT_PENDING_SOURCE_LIMIT: usize = 16;

pub struct Lease {
    pool: Arc<Pool>,
    source: Option<IpAddr>,
}

impl Pool {
    fn acquire(self: &Arc<Self>, source: Option<IpAddr>) -> Result<Lease, &'static str> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if counts.0 >= self.limit {
            return Err("connection capacity reached");
        }
        let counted_source = match (source, self.source_limit) {
            (Some(ip), Some(limit)) => {
                if counts.1.get(&ip).copied().unwrap_or(0) >= limit {
                    return Err("source connection capacity reached");
                }
                *counts.1.entry(ip).or_default() += 1;
                Some(ip)
            }
            _ => None,
        };
        counts.0 += 1;
        Ok(Lease {
            pool: Arc::clone(self),
            source: counted_source,
        })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut counts = self.pool.counts.lock().unwrap_or_else(|e| e.into_inner());
        counts.0 -= 1;
        if let Some(ip) = self.source {
            if let Some(count) = counts.1.get_mut(&ip) {
                *count -= 1;
                if *count == 0 {
                    counts.1.remove(&ip);
                }
            }
        }
    }
}

impl Lease {
    /// Re-classify a proxied handshake once its forwarded client is known.
    ///
    /// A proxy TCP peer cannot be attributed to an end user until HTTP headers
    /// are available. Keep the same pool slot, but atomically move its
    /// per-source accounting to the forwarded identity.
    pub fn resolve_source(&mut self, source: IpAddr) -> Result<(), &'static str> {
        let source = quota_source(source);
        let mut counts = self.pool.counts.lock().unwrap_or_else(|e| e.into_inner());
        if self.source == Some(source) {
            return Ok(());
        }

        let limit = self
            .pool
            .source_limit
            .ok_or("source connection capacity reached")?;
        if counts.1.get(&source).copied().unwrap_or(0) >= limit {
            return Err("source connection capacity reached");
        }
        *counts.1.entry(source).or_default() += 1;

        if let Some(previous) = self.source.take() {
            if let Some(count) = counts.1.get_mut(&previous) {
                *count -= 1;
                if *count == 0 {
                    counts.1.remove(&previous);
                }
            }
        }
        self.source = Some(source);
        Ok(())
    }
}

impl Admission {
    pub fn new(max: usize, per_source: Option<usize>, proxies: &str) -> Result<Self, String> {
        let trusted_proxies = proxies
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim().parse::<IpAddr>().map(canonical).map_err(|_| {
                    "TRUSTED_PROXIES must contain comma-separated IP addresses".to_owned()
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let pool = |limit, source_limit| {
            Arc::new(Pool {
                limit,
                source_limit,
                counts: Mutex::new((0, HashMap::new())),
            })
        };
        Ok(Self {
            trusted_proxies,
            // Handshakes cannot consume the established WebSocket pool.
            pending: pool(
                max.clamp(1, 128),
                Some(
                    per_source
                        .unwrap_or(DEFAULT_PENDING_SOURCE_LIMIT)
                        .clamp(1, DEFAULT_PENDING_SOURCE_LIMIT),
                ),
            ),
            active: pool(
                max.max(1),
                per_source.map(|limit| limit.max(1).min(max.saturating_sub(1).max(1))),
            ),
        })
    }

    pub fn source_limit(&self) -> Option<usize> {
        self.active.source_limit
    }

    pub fn pending(&self, peer: IpAddr) -> Result<Lease, &'static str> {
        let peer = canonical(peer);
        self.pending
            .acquire((!self.trusted_proxies.contains(&peer)).then_some(quota_source(peer)))
    }

    pub fn active(&self, source: IpAddr) -> Result<Lease, &'static str> {
        self.active.acquire(Some(quota_source(source)))
    }

    pub fn source(&self, peer: IpAddr, headers: &HeaderMap) -> Result<IpAddr, &'static str> {
        let peer = canonical(peer);
        if !self.trusted_proxies.contains(&peer) {
            return Ok(peer);
        }
        // Walk from the nearest proxy. Never trust a client-supplied leftmost IP.
        if headers.contains_key("x-forwarded-for") {
            if headers.get_all("x-forwarded-for").iter().count() != 1 {
                return Err("ambiguous forwarded address");
            }
            let value = headers["x-forwarded-for"]
                .to_str()
                .map_err(|_| "invalid forwarded address")?;
            if value.len() > 1024 {
                return Err("forwarded chain too long");
            }
            let chain = value
                .split(',')
                .map(|s| s.trim().parse::<IpAddr>().map(canonical))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "invalid forwarded address")?;
            if chain.len() > 16 {
                return Err("forwarded chain too long");
            }
            let client = chain
                .into_iter()
                .rev()
                .find(|ip| !self.trusted_proxies.contains(ip))
                .ok_or("forwarded chain has no client address")?;
            match headers.get_all("x-real-ip").iter().count() {
                0 => {}
                1 => {
                    let real = headers["x-real-ip"]
                        .to_str()
                        .ok()
                        .and_then(|value| value.parse::<IpAddr>().ok())
                        .map(canonical)
                        .ok_or("invalid real address")?;
                    if !self.trusted_proxies.contains(&real) && real != client {
                        return Err("conflicting forwarded address");
                    }
                }
                _ => return Err("ambiguous forwarded address"),
            }
            return Ok(client);
        }
        if headers.get_all("x-real-ip").iter().count() != 1 {
            return Err("trusted proxy must send client address");
        }
        headers["x-real-ip"]
            .to_str()
            .ok()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .map(canonical)
            .filter(|ip| !self.trusted_proxies.contains(ip))
            .ok_or("invalid real address")
    }
}

fn source_limit_from_env(value: Option<&str>) -> Option<usize> {
    value
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|limit| *limit > 0)
}

pub fn admission() -> &'static Admission {
    static VALUE: OnceLock<Admission> = OnceLock::new();
    VALUE.get_or_init(|| {
        let max = super::max_connections();
        let limit =
            source_limit_from_env(std::env::var("MAX_CONNECTIONS_PER_SOURCE").ok().as_deref());
        Admission::new(
            max,
            limit,
            &std::env::var("TRUSTED_PROXIES").unwrap_or_default(),
        )
        .expect("invalid connection admission configuration")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_headers_cannot_spoof_source_and_trusted_chains_use_nearest_client() {
        let guard = Admission::new(16, Some(4), "127.0.0.1,::1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "1.1.1.1, 203.0.113.9, 127.0.0.1".parse().unwrap(),
        );
        assert_eq!(
            guard
                .source("192.0.2.7".parse().unwrap(), &headers)
                .unwrap()
                .to_string(),
            "192.0.2.7"
        );
        assert_eq!(
            guard
                .source("127.0.0.1".parse().unwrap(), &headers)
                .unwrap()
                .to_string(),
            "203.0.113.9"
        );
        headers.append("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert!(guard
            .source("127.0.0.1".parse().unwrap(), &headers)
            .is_err());
        assert!(guard
            .source("127.0.0.1".parse().unwrap(), &HeaderMap::new())
            .is_err());
    }

    #[test]
    fn forwarded_chain_must_agree_with_a_client_x_real_ip_vouch() {
        let guard = Admission::new(16, Some(4), "127.0.0.1,::1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.23".parse().unwrap());
        headers.insert("x-real-ip", "192.0.2.7".parse().unwrap());
        assert_eq!(
            guard
                .source("127.0.0.1".parse().unwrap(), &headers)
                .unwrap_err(),
            "conflicting forwarded address"
        );
        headers.insert("x-forwarded-for", "192.0.2.7".parse().unwrap());
        assert_eq!(
            guard
                .source("127.0.0.1".parse().unwrap(), &headers)
                .unwrap()
                .to_string(),
            "192.0.2.7"
        );
    }

    #[test]
    fn disabled_source_limit_allows_one_source_up_to_global_limit() {
        let guard = Admission::new(4, None, "").unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..4).map(|_| guard.active(ip).unwrap()).collect();

        assert!(matches!(
            guard.active(ip),
            Err("connection capacity reached")
        ));
        drop(held);
        assert!(guard.active(ip).is_ok());

        let pending: Vec<_> = (0..4).map(|_| guard.pending(ip).unwrap()).collect();
        assert!(matches!(
            guard.pending(ip),
            Err("connection capacity reached")
        ));
        drop(pending);
        assert!(guard.pending(ip).is_ok());
    }

    #[test]
    fn proxy_handshakes_are_limited_by_forwarded_source() {
        let guard = Admission::new(16, Some(1), "127.0.0.1").unwrap();
        let proxy = "127.0.0.1".parse().unwrap();
        let mut first = guard.pending(proxy).unwrap();
        let mut second = guard.pending(proxy).unwrap();

        first.resolve_source("192.0.2.1".parse().unwrap()).unwrap();
        second.resolve_source("192.0.2.2".parse().unwrap()).unwrap();
        let mut third = guard.pending(proxy).unwrap();
        assert!(third.resolve_source("192.0.2.1".parse().unwrap()).is_err());
        drop(first);
        let mut fourth = guard.pending(proxy).unwrap();
        assert!(fourth.resolve_source("192.0.2.1".parse().unwrap()).is_ok());
    }

    #[test]
    fn explicit_source_limit_rejects_third_connection_and_recovers() {
        let guard = Admission::new(16, Some(2), "").unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        let held: Vec<_> = (0..2).map(|_| guard.active(ip).unwrap()).collect();
        assert!(matches!(
            guard.active(ip),
            Err("source connection capacity reached")
        ));
        assert!(guard.active("192.0.2.2".parse().unwrap()).is_ok());
        assert!(guard.active("::ffff:192.0.2.1".parse().unwrap()).is_err());
        drop(held);
        assert!(guard.active(ip).is_ok());
        let pending: Vec<_> = (0..2).map(|_| guard.pending(ip).unwrap()).collect();
        assert!(guard.pending(ip).is_err());
        assert!(guard.active(ip).is_ok());
        drop(pending);
        assert!(guard.pending(ip).is_ok());
        let ipv6 = "2001:db8:1:2::1".parse().unwrap();
        let _v6: Vec<_> = (0..2).map(|_| guard.active(ipv6).unwrap()).collect();
        assert!(guard.active("2001:db8:1:2::ffff".parse().unwrap()).is_err());
        assert!(guard.active("2001:db8:1:3::1".parse().unwrap()).is_ok());
    }

    #[test]
    fn different_sources_share_global_limit_and_disconnect_restores_capacity() {
        let guard = Admission::new(3, None, "").unwrap();
        let first = guard.active("192.0.2.1".parse().unwrap()).unwrap();
        let _second = guard.active("192.0.2.2".parse().unwrap()).unwrap();
        let _third = guard.active("192.0.2.3".parse().unwrap()).unwrap();

        assert!(matches!(
            guard.active("192.0.2.4".parse().unwrap()),
            Err("connection capacity reached")
        ));
        drop(first);
        assert!(guard.active("192.0.2.4".parse().unwrap()).is_ok());
    }

    #[test]
    fn source_limit_is_disabled_for_missing_empty_zero_and_invalid_values() {
        assert_eq!(source_limit_from_env(None), None);
        assert_eq!(source_limit_from_env(Some("")), None);
        assert_eq!(source_limit_from_env(Some("   ")), None);
        assert_eq!(source_limit_from_env(Some("0")), None);
        assert_eq!(source_limit_from_env(Some("not-a-number")), None);
        assert_eq!(source_limit_from_env(Some(" 128 ")), Some(128));
    }
}
