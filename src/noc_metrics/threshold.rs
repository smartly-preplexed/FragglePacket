//! Threshold profiles, ported from NOC's `pm.models.thresholdprofile`
//! (noc-master `pm/models/thresholdprofile.py`).
//!
//! NOC never compares a metric's raw last sample against a single fixed
//! number. Instead an operator-configurable `ThresholdProfile` says:
//!   * which window function to run over recent samples first (see
//!     `window.rs`), and
//!   * an ordered list of `ThresholdConfig`s, each with a separate *open*
//!     condition and *clear* condition.
//!
//! The open/clear split gives hysteresis for free: once a threshold opens,
//! the metric has to cross back past the (looser) clear condition before
//! the diagnosis goes away, instead of flapping open/closed every time a
//! noisy metric ticks a fraction of a percent either side of one number.
//! `ThresholdState` below implements exactly that lifecycle.

use super::window::{self, Sample};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Lt,
    Le,
    Ge,
    Gt,
}

impl CompareOp {
    pub fn matches(&self, value: f64, threshold: f64) -> bool {
        match self {
            CompareOp::Lt => value < threshold,
            CompareOp::Le => value <= threshold,
            CompareOp::Ge => value >= threshold,
            CompareOp::Gt => value > threshold,
        }
    }
}

/// One severity rung within a profile: an open condition and a separate,
/// looser clear condition (NOC's `ThresholdConfig` embedded document).
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// Caller-defined label identifying this rung (e.g. a severity name);
    /// `noc_metrics` itself doesn't interpret it.
    pub label: &'static str,
    pub op: CompareOp,
    pub value: f64,
    pub clear_op: CompareOp,
    pub clear_value: f64,
}

impl ThresholdConfig {
    pub const fn new(
        label: &'static str,
        op: CompareOp,
        value: f64,
        clear_op: CompareOp,
        clear_value: f64,
    ) -> Self {
        Self { label, op, value, clear_op, clear_value }
    }

    pub fn is_open_match(&self, value: f64) -> bool {
        self.op.matches(value, self.value)
    }

    pub fn is_clear_match(&self, value: f64) -> bool {
        self.clear_op.matches(value, self.clear_value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowType {
    /// Keep the last N samples regardless of their age.
    Measurements,
    /// Keep samples whose timestamp is within `window` seconds of the most
    /// recent sample.
    Time,
}

/// A named, reusable threshold definition for one metric (NOC's
/// `ThresholdProfile` document). `thresholds` must be ordered
/// most-severe-first: the first rung whose open condition matches wins.
#[derive(Debug, Clone)]
pub struct ThresholdProfile {
    pub name: &'static str,
    pub window_type: WindowType,
    pub window: i64,
    pub window_function: &'static str,
    pub thresholds: Vec<ThresholdConfig>,
}

impl ThresholdProfile {
    fn select_window(&self, samples: &[Sample]) -> Vec<Sample> {
        let mut sorted = samples.to_vec();
        sorted.sort_by_key(|s| s.0);
        match self.window_type {
            WindowType::Measurements => {
                let n = self.window.max(1) as usize;
                let start = sorted.len().saturating_sub(n);
                sorted[start..].to_vec()
            }
            WindowType::Time => match sorted.last() {
                Some(&(last_ts, _)) => {
                    let floor = last_ts - self.window.max(0);
                    sorted.into_iter().filter(|s| s.0 >= floor).collect()
                }
                None => Vec::new(),
            },
        }
    }

    /// Run this profile's window function over the trimmed window.
    pub fn aggregate(&self, samples: &[Sample]) -> Result<Option<f64>, String> {
        let w = self.select_window(samples);
        window::apply(self.window_function, &w)
    }

    /// Stateless check: does the *current* window match any open condition?
    /// (No hysteresis -- see `ThresholdState` for that.)
    pub fn evaluate(&self, samples: &[Sample]) -> Result<Option<(f64, &ThresholdConfig)>, String> {
        let Some(value) = self.aggregate(samples)? else {
            return Ok(None);
        };
        for t in &self.thresholds {
            if t.is_open_match(value) {
                return Ok(Some((value, t)));
            }
        }
        Ok(None)
    }
}

/// Per-target hysteresis state for one profile, mirroring NOC's alarm
/// open/clear lifecycle: once a rung opens, only its *clear* condition can
/// close it, even if the metric dips back under the open threshold.
#[derive(Debug, Clone, Default)]
pub struct ThresholdState {
    open_index: Option<usize>,
}

impl ThresholdState {
    pub fn new() -> Self {
        Self { open_index: None }
    }

    pub fn is_open(&self) -> bool {
        self.open_index.is_some()
    }

    /// Feed a fresh window through `profile`, updating hysteresis state.
    /// Returns the matched threshold while open, `None` once clear.
    pub fn evaluate<'a>(
        &mut self,
        profile: &'a ThresholdProfile,
        samples: &[Sample],
    ) -> Result<Option<(f64, &'a ThresholdConfig)>, String> {
        let Some(value) = profile.aggregate(samples)? else {
            return Ok(None);
        };
        if let Some(idx) = self.open_index {
            let t = &profile.thresholds[idx];
            if t.is_clear_match(value) {
                self.open_index = None;
                return Ok(None);
            }
            return Ok(Some((value, t)));
        }
        for (idx, t) in profile.thresholds.iter().enumerate() {
            if t.is_open_match(value) {
                self.open_index = Some(idx);
                return Ok(Some((value, t)));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ThresholdProfile {
        ThresholdProfile {
            name: "test",
            window_type: WindowType::Measurements,
            window: 5,
            window_function: "last",
            thresholds: vec![
                ThresholdConfig::new("high", CompareOp::Ge, 10.0, CompareOp::Lt, 8.0),
                ThresholdConfig::new("medium", CompareOp::Ge, 1.0, CompareOp::Lt, 0.5),
            ],
        }
    }

    #[test]
    fn stateless_evaluate_picks_the_most_severe_matching_rung() {
        let p = profile();
        let (value, t) = p.evaluate(&[(0, 12.0)]).unwrap().unwrap();
        assert_eq!(value, 12.0);
        assert_eq!(t.label, "high");
    }

    #[test]
    fn stateless_evaluate_below_every_open_condition_is_none() {
        let p = profile();
        assert!(p.evaluate(&[(0, 0.2)]).unwrap().is_none());
    }

    #[test]
    fn last_window_function_reproduces_a_single_point_threshold_check() {
        // A single-sample window with "last" behaves exactly like the old
        // point comparison it replaces -- this is the backward-compat path.
        let p = profile();
        assert!(p.evaluate(&[(0, 1.0)]).unwrap().is_some());
        assert!(p.evaluate(&[(0, 0.99)]).unwrap().is_none());
    }

    #[test]
    fn hysteresis_keeps_a_diagnosis_open_through_the_dead_zone() {
        let p = profile();
        let mut state = ThresholdState::new();

        // Opens at >= 1.0
        assert!(state.evaluate(&p, &[(0, 1.5)]).unwrap().is_some());
        assert!(state.is_open());

        // Dips into the dead zone (below open 1.0 but not below clear 0.5):
        // must STAY open, unlike a naive point-threshold check.
        let still_open = state.evaluate(&p, &[(1, 0.7)]).unwrap();
        assert!(still_open.is_some());
        assert!(state.is_open());

        // Finally crosses the clear condition (< 0.5): closes.
        assert!(state.evaluate(&p, &[(2, 0.3)]).unwrap().is_none());
        assert!(!state.is_open());
    }

    #[test]
    fn windowed_average_smooths_a_single_spike() {
        let mut p = profile();
        p.window_function = "avg";
        p.window = 4;
        // One spike to 20 among mostly-quiet samples should not, on
        // average, cross the "high" (>=10) rung.
        let samples = [(0, 1.0), (1, 1.0), (2, 20.0), (3, 1.0)];
        let (value, t) = p.evaluate(&samples).unwrap().unwrap();
        assert!((value - 5.75).abs() < 1e-9);
        assert_eq!(t.label, "medium");
    }

    #[test]
    fn measurements_window_keeps_only_the_last_n_samples() {
        let mut p = profile();
        p.window = 2;
        p.window_function = "avg";
        // Only the last two samples (1.0, 1.0) should count -- the old 50.0
        // sample must be trimmed out of the window.
        let samples = [(0, 50.0), (1, 1.0), (2, 1.0)];
        let value = p.aggregate(&samples).unwrap().unwrap();
        assert_eq!(value, 1.0);
    }

    #[test]
    fn time_window_drops_samples_older_than_the_configured_span() {
        let mut p = profile();
        p.window_type = WindowType::Time;
        p.window = 10; // seconds
        p.window_function = "avg";
        // Sample at t=0 is 100s before the latest sample at t=100, so a
        // 10s window must drop it.
        let samples = [(0, 1000.0), (95, 2.0), (100, 4.0)];
        let value = p.aggregate(&samples).unwrap().unwrap();
        assert_eq!(value, 3.0);
    }
}
