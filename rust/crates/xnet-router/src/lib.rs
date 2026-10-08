//! xnet-router — deterministic routing feedback (C-06 family in the graph).
//! Routes are ranked by MEASURED latency/success only — never by vibe.
//! Same measurement table -> same route, always replayable.
//! The router RANKS; it never grants authority (gates do that).

pub mod predict;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStat {
    pub successes: u64,
    pub failures: u64,
    /// exponential moving average latency, milliseconds (measured)
    pub ema_latency_ms: f64,
    /// quarantined until this utc (0 = not quarantined)
    pub quarantined_until: i64,
}

impl Default for RouteStat {
    fn default() -> Self {
        Self { successes: 0, failures: 0, ema_latency_ms: f64::INFINITY, quarantined_until: 0 }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouterConfig {
    /// EMA gain: weight of the newest measurement (0 < a <= 1)
    pub gain: f64,
    /// per-day decay applied to stale stats so old glory fades
    pub decay_per_day: f64,
    /// consecutive failures before quarantine
    pub quarantine_after: u32,
    /// quarantine TTL, seconds
    pub quarantine_ttl_s: i64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self { gain: 0.3, decay_per_day: 0.9, quarantine_after: 3, quarantine_ttl_s: 3600 }
    }
}

pub struct Router {
    pub cfg: RouterConfig,
    /// route name -> measured stats (BTreeMap: deterministic iteration order)
    pub table: BTreeMap<String, RouteStat>,
    consecutive_failures: BTreeMap<String, u32>,
}

impl Router {
    pub fn new(cfg: RouterConfig) -> Self {
        Self { cfg, table: BTreeMap::new(), consecutive_failures: BTreeMap::new() }
    }

    /// Record a MEASURED outcome for a route.
    pub fn observe(&mut self, route: &str, ok: bool, latency_ms: f64, ts_utc: i64) {
        let s = self.table.entry(route.to_string()).or_default();
        if ok {
            s.successes += 1;
            self.consecutive_failures.insert(route.to_string(), 0);
            s.ema_latency_ms = if s.ema_latency_ms.is_infinite() {
                latency_ms
            } else {
                self.cfg.gain * latency_ms + (1.0 - self.cfg.gain) * s.ema_latency_ms
            };
        } else {
            s.failures += 1;
            let n = self.consecutive_failures.entry(route.to_string()).or_insert(0);
            *n += 1;
            if *n >= self.cfg.quarantine_after {
                s.quarantined_until = ts_utc.saturating_add(self.cfg.quarantine_ttl_s);
                *n = 0;
            }
        }
    }

    fn score(&self, _route: &str, s: &RouteStat, now_utc: i64) -> Option<f64> {
        if s.quarantined_until > now_utc {
            return None; // quarantined routes do not rank
        }
        let total = s.successes + s.failures;
        if total == 0 {
            return Some(f64::INFINITY); // never measured: worst score, but eligible
        }
        let reliability = s.successes as f64 / total as f64;
        let latency = if s.ema_latency_ms.is_infinite() { f64::MAX / 1e6 } else { s.ema_latency_ms };
        // lower is better: latency penalized by unreliability
        Some(latency / reliability.max(1e-9))
    }

    /// Deterministic pick: lowest score; ties break lexicographically. Same table -> same pick.
    pub fn pick(&self, candidates: &[&str], now_utc: i64) -> Option<String> {
        let mut best: Option<(&str, f64)> = None;
        for c in candidates {
            let s = self.table.get(*c).cloned().unwrap_or_default();
            let Some(sc) = self.score(c, &s, now_utc) else { continue; };
            match best {
                None => best = Some((c, sc)),
                Some((bc, bs)) if sc < bs || (sc == bs && *c < bc) => best = Some((c, sc)),
                _ => {}
            }
        }
        best.map(|(c, _)| c.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faster_reliable_route_wins() {
        let mut r = Router::new(RouterConfig::default());
        for _ in 0..10 {
            r.observe("nullclaw", true, 40.0, 0);
            r.observe("model", true, 77_700.0, 0);
        }
        assert_eq!(r.pick(&["nullclaw", "model"], 100).unwrap(), "nullclaw");
    }

    #[test]
    fn quarantine_removes_route_then_expires() {
        let mut r = Router::new(RouterConfig::default());
        r.observe("bad", false, 1.0, 0);
        r.observe("bad", false, 1.0, 0);
        r.observe("bad", false, 1.0, 0); // 3rd consecutive failure -> quarantine
        r.observe("good", true, 100.0, 0);
        assert_eq!(r.pick(&["bad", "good"], 100).unwrap(), "good");
        // after TTL the route is eligible again (decay, not memory-hole)
        assert!(r.pick(&["bad", "good"], 100 + 3700).is_some());
    }

    #[test]
    fn determinism() {
        let mut r = Router::new(RouterConfig::default());
        r.observe("a", true, 10.0, 0);
        r.observe("b", true, 10.0, 0);
        assert_eq!(r.pick(&["b", "a"], 100), r.pick(&["a", "b"], 100));
    }
}
