//! xnet-router::predict — the prediction/pivot layer (prediction-loop-spec v1
//! + oracle-legion-spec v1, made executable).
//!
//! The contract: PREDICT (sealed) -> ACT -> MEASURE -> GRADE -> FEED -> PIVOT.
//! Predictions change ORDERING, never ADMISSION. A predictor that misses
//! chronically loses authority (quarantine), exactly like a route.
//! Everything here is deterministic: same ledger data -> same grades -> same pivot.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A sealed prediction. Written BEFORE the act; immutable afterward.
/// Editing a sealed prediction is the lattice's capital crime — this struct
/// has no mutating methods on purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub id: u64,
    pub predictor: String,          // loop/legion id, e.g. "C-08" or "triathlon"
    pub route: String,              // the route this prediction is about
    pub metric: String,             // e.g. "wall_ms", "success", "recall_fidelity"
    pub predicted: f64,
    pub band: (f64, f64),           // confidence band [lo, hi]
    pub horizon_s: i64,
    pub sealed_utc: i64,
    pub basis: String,              // provenance, e.g. "ema:40ms,n=12" — never unlabeled intuition
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Grade {
    Hit,  // measured inside band
    Miss, // measured outside band
    Void, // horizon expired unmeasured
}

#[derive(Debug, Default, Clone)]
pub struct Calibration {
    pub hits: u64,
    pub misses: u64,
    pub voids: u64,
    pub consecutive_misses: u32,
    /// confidence-band honesty: predictions whose stated band actually contained
    /// the outcome, weighted against band width. 1.0 = perfectly calibrated.
    pub band_score_sum: f64,
}

impl Calibration {
    pub fn graded(&self) -> u64 {
        self.hits + self.misses
    }
    pub fn hit_rate(&self) -> f64 {
        let g = self.graded();
        if g == 0 { 0.0 } else { self.hits as f64 / g as f64 }
    }
    /// Heuristic interval score in [0,1]; not a probability or a Brier score.
    pub fn calibration_score(&self) -> f64 {
        let g = self.graded();
        if g == 0 { return 0.0 }
        (self.band_score_sum / g as f64).clamp(0.0, 1.0)
    }
}

pub const PREDICTOR_QUARANTINE_AFTER: u32 = 3; // consecutive misses, same law as routes
pub const ORACLE_ELIGIBILITY_MIN_GRADED: u64 = 30;

/// The book of sealed predictions and their grades. Deterministic throughout.
#[derive(Default)]
pub struct OracleBook {
    pub next_id: u64,
    pub pending: BTreeMap<u64, Prediction>,     // sealed, awaiting measurement
    pub graded_count: BTreeMap<String, u64>,    // predictor -> lifetime graded
    pub calibration: BTreeMap<String, Calibration>,
    pub predictor_quarantined_until: BTreeMap<String, i64>,
}

impl OracleBook {
    /// Seal a prediction. Returns its id. No edit path exists.
    pub fn seal(&mut self, mut p: Prediction) -> u64 {
        p.id = self.next_id;
        self.next_id += 1;
        let id = p.id;
        self.pending.insert(id, p);
        id
    }

    /// Grade a sealed prediction against a MEASURED value. Consumes the pending
    /// entry — a prediction is graded exactly once.
    pub fn grade(&mut self, id: u64, measured: f64, now_utc: i64) -> Option<Grade> {
        let p = self.pending.remove(&id)?;
        let (lo, hi) = p.band;
        let grade = if measured >= lo && measured <= hi { Grade::Hit } else { Grade::Miss };
        let cal = self.calibration.entry(p.predictor.clone()).or_default();
        *self.graded_count.entry(p.predictor.clone()).or_insert(0) += 1;
        match grade {
            Grade::Hit => {
                cal.hits += 1;
                cal.consecutive_misses = 0;
                // band honesty: narrower true bands score higher
                let width = (hi - lo).abs().max(1e-9);
                let center_dist = (measured - (lo + hi) / 2.0).abs();
                let sharpness = 1.0 / (1.0 + width / p.predicted.abs().max(1.0));
                cal.band_score_sum += sharpness * (1.0 - center_dist / (width / 2.0)).clamp(0.0, 1.0);
            }
            Grade::Miss => {
                cal.misses += 1;
                cal.consecutive_misses += 1;
                if cal.consecutive_misses >= PREDICTOR_QUARANTINE_AFTER {
                    // the PREDICTOR loses authority, not just the route
                    self.predictor_quarantined_until
                        .insert(p.predictor.clone(), now_utc.saturating_add(3600));
                    cal.consecutive_misses = 0;
                }
            }
            Grade::Void => unreachable!(),
        }
        Some(grade)
    }

    /// Expire unmeasured predictions past horizon -> Void (never graded, never gamed).
    pub fn sweep_voids(&mut self, now_utc: i64) -> Vec<u64> {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| now_utc > p.sealed_utc.saturating_add(p.horizon_s))
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            if let Some(p) = self.pending.remove(id) {
                self.calibration.entry(p.predictor).or_default().voids += 1;
            }
        }
        expired
    }

    pub fn predictor_allowed(&self, predictor: &str, now_utc: i64) -> bool {
        self.predictor_quarantined_until
            .get(predictor)
            .map(|&until| now_utc >= until)
            .unwrap_or(true)
    }

    /// Oracle eligibility: enough graded volume, no voids in window, not quarantined.
    pub fn oracle_eligible(&self, predictor: &str, now_utc: i64) -> bool {
        self.predictor_allowed(predictor, now_utc)
            && self.graded_count.get(predictor).copied().unwrap_or(0) >= ORACLE_ELIGIBILITY_MIN_GRADED
            && self.calibration.get(predictor).map(|c| c.voids == 0).unwrap_or(false)
    }

    /// Current Oracle: highest calibration score among eligible predictors.
    /// Ties break lexicographically — deterministic, replay-safe.
    pub fn oracle(&self, candidates: &[&str], now_utc: i64) -> Option<String> {
        let mut best: Option<(&str, f64)> = None;
        for c in candidates {
            if !self.oracle_eligible(c, now_utc) {
                continue;
            }
            let s = self
                .calibration
                .get(*c)
                .map(|k| k.calibration_score())
                .unwrap_or(0.0);
            match best {
                None => best = Some((c, s)),
                Some((bc, bs)) if s > bs || (s == bs && *c < bc) => best = Some((c, s)),
                _ => {}
            }
        }
        best.map(|(c, _)| c.to_string())
    }

    /// PIVOT recommendation: should traffic rotate from `incumbent` route to a
    /// challenger? Deterministic; the margin prevents dithering. The caller
    /// (Rubik rotation + RPS arbitration on ties) decides whether to act —
    /// this layer recommends, gates decide.
    pub fn pivot_recommendation(
        &self,
        incumbent_prediction: u64,
        challenger_prediction: u64,
        margin: f64,
    ) -> PivotVerdict {
        let inc = match self.pending.get(&incumbent_prediction) {
            Some(p) => p,
            None => return PivotVerdict::Hold("incumbent prediction not sealed".into()),
        };
        let chal = match self.pending.get(&challenger_prediction) {
            Some(p) => p,
            None => return PivotVerdict::Hold("challenger prediction not sealed".into()),
        };
        // lower-is-better metrics (latency): challenger wins if its predicted
        // value beats incumbent's by margin, with bands not overlapping upward
        if chal.predicted * (1.0 + margin) < inc.predicted && chal.band.1 < inc.band.0 {
            PivotVerdict::Rotate { to: chal.route.clone() }
        } else {
            PivotVerdict::Hold("no decisive graded edge".into())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PivotVerdict {
    Rotate { to: String },
    Hold(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(predictor: &str, route: &str, val: f64, lo: f64, hi: f64) -> Prediction {
        Prediction {
            id: 0,
            predictor: predictor.into(),
            route: route.into(),
            metric: "wall_ms".into(),
            predicted: val,
            band: (lo, hi),
            horizon_s: 3600,
            sealed_utc: 0,
            basis: "test".into(),
        }
    }

    #[test]
    fn grade_hit_and_miss() {
        let mut b = OracleBook::default();
        let id = b.seal(pred("context", "capsule", 40.0, 25.0, 80.0));
        assert_eq!(b.grade(id, 50.0, 100), Some(Grade::Hit));
        let id2 = b.seal(pred("context", "capsule", 40.0, 25.0, 80.0));
        assert_eq!(b.grade(id2, 120.0, 100), Some(Grade::Miss));
        // graded exactly once: second grade of same id is impossible
        assert_eq!(b.grade(id, 50.0, 100), None);
    }

    #[test]
    fn chronic_miss_quarantines_predictor() {
        let mut b = OracleBook::default();
        for _ in 0..PREDICTOR_QUARANTINE_AFTER {
            let id = b.seal(pred("broker", "warm", 1.0, 0.0, 2.0));
            b.grade(id, 99.0, 100);
        }
        assert!(!b.predictor_allowed("broker", 200));
        assert!(b.predictor_allowed("broker", 100 + 3600 + 1));
    }

    #[test]
    fn voids_expire_unmeasured() {
        let mut b = OracleBook::default();
        b.seal(pred("eyes", "qr", 1.0, 0.0, 2.0));
        let voided = b.sweep_voids(3601);
        assert_eq!(voided.len(), 1);
        assert_eq!(b.calibration["eyes"].voids, 1);
        // a voided predictor is not oracle-eligible
        assert!(!b.oracle_eligible("eyes", 4000));
    }

    #[test]
    fn oracle_picks_best_calibrated_eligible() {
        let mut b = OracleBook::default();
        for i in 0..30 {
            let id = b.seal(pred("triathlon", "nullclaw", 10.0, 5.0, 15.0));
            b.grade(id, 10.0, i as i64 + 1); // perfect hits at center
            let id2 = b.seal(pred("context", "capsule", 10.0, 0.0, 100.0));
            b.grade(id2, 50.0, i as i64 + 1); // hits but sloppy wide bands
        }
        assert_eq!(b.oracle(&["triathlon", "context"], 1000).unwrap(), "triathlon");
    }

    #[test]
    fn pivot_requires_sealed_edge() {
        let mut b = OracleBook::default();
        let inc = b.seal(pred("triathlon", "model", 100.0, 80.0, 120.0));
        let chal = b.seal(pred("triathlon", "nullclaw", 50.0, 45.0, 55.0));
        assert!(matches!(
            b.pivot_recommendation(inc, chal, 0.1),
            PivotVerdict::Rotate { .. }
        ));
        let weak = b.seal(pred("triathlon", "model2", 95.0, 70.0, 130.0));
        assert!(matches!(
            b.pivot_recommendation(inc, weak, 0.1),
            PivotVerdict::Hold(_)
        ));
    }
}
