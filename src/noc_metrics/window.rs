//! Window aggregation functions, ported from NOC's `core.window`
//! (noc-master `core/window.py`).
//!
//! NOC's threshold profiles don't evaluate a metric's raw last sample --
//! they run a *window function* over the recent samples first (last N
//! measurements, or the last T seconds), producing a single value that is
//! then compared against the threshold. This module ports the pure-math
//! window functions NOC ships (NOC's `handler` window function, which
//! dispatches to an arbitrary Python callable, is intentionally not
//! ported -- there is no equivalent "arbitrary plugin" concept here).
//!
//! A window is a time-ordered series of `(unix_timestamp, value)` samples.

/// A single metric sample: `(unix_timestamp_seconds, value)`.
pub type Sample = (i64, f64);

fn sorted_values(window: &[Sample]) -> Vec<Sample> {
    let mut w = window.to_vec();
    w.sort_by_key(|s| s.0);
    w
}

/// Most recent sample's value (NOC's `last`).
pub fn last(window: &[Sample]) -> Option<f64> {
    sorted_values(window).last().map(|s| s.1)
}

/// Sum of all values in the window (NOC's `sum`).
pub fn sum(window: &[Sample]) -> Option<f64> {
    if window.is_empty() {
        return None;
    }
    Some(window.iter().map(|s| s.1).sum())
}

/// Arithmetic mean of all values in the window (NOC's `avg`).
pub fn avg(window: &[Sample]) -> Option<f64> {
    if window.is_empty() {
        return None;
    }
    Some(window.iter().map(|s| s.1).sum::<f64>() / window.len() as f64)
}

/// Linear-interpolated percentile (0..=100) over the window's values,
/// mirroring NOC's percentile-based window functions (`q1`, `q2`/median,
/// `q3`, `p95`, `p99`).
pub fn percentile(window: &[Sample], q: f64) -> Option<f64> {
    if window.is_empty() {
        return None;
    }
    let mut values: Vec<f64> = window.iter().map(|s| s.1).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if values.len() == 1 {
        return Some(values[0]);
    }
    let rank = (q.clamp(0.0, 100.0) / 100.0) * (values.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        Some(values[lo])
    } else {
        let frac = rank - lo as f64;
        Some(values[lo] + (values[hi] - values[lo]) * frac)
    }
}

pub fn q1(window: &[Sample]) -> Option<f64> {
    percentile(window, 25.0)
}
pub fn q2(window: &[Sample]) -> Option<f64> {
    percentile(window, 50.0)
}
pub fn q3(window: &[Sample]) -> Option<f64> {
    percentile(window, 75.0)
}
pub fn p95(window: &[Sample]) -> Option<f64> {
    percentile(window, 95.0)
}
pub fn p99(window: &[Sample]) -> Option<f64> {
    percentile(window, 99.0)
}

/// Sum of positive step-to-step increases (NOC's `step_inc`); useful for
/// monotonically increasing counters sampled irregularly.
pub fn step_inc(window: &[Sample]) -> Option<f64> {
    let w = sorted_values(window);
    if w.is_empty() {
        return None;
    }
    Some(
        w.windows(2)
            .map(|pair| (pair[1].1 - pair[0].1).max(0.0))
            .sum(),
    )
}

/// Sum of the magnitude of negative step-to-step decreases (NOC's
/// `step_dec`).
pub fn step_dec(window: &[Sample]) -> Option<f64> {
    let w = sorted_values(window);
    if w.is_empty() {
        return None;
    }
    Some(
        w.windows(2)
            .map(|pair| (pair[0].1 - pair[1].1).max(0.0))
            .sum(),
    )
}

/// Sum of absolute step-to-step differences (NOC's `step_abs`).
pub fn step_abs(window: &[Sample]) -> Option<f64> {
    let w = sorted_values(window);
    if w.is_empty() {
        return None;
    }
    Some(w.windows(2).map(|pair| (pair[1].1 - pair[0].1).abs()).sum())
}

/// Exponentially-decayed weighted average, most recent sample weighted
/// heaviest (NOC's `exp_decay`). `half_life_secs` controls how quickly
/// older samples lose influence.
pub fn exp_decay(window: &[Sample], half_life_secs: f64) -> Option<f64> {
    let w = sorted_values(window);
    let last_ts = w.last()?.0;
    if half_life_secs <= 0.0 {
        return last(window);
    }
    let lambda = std::f64::consts::LN_2 / half_life_secs;
    let mut weighted_sum = 0.0;
    let mut weight_total = 0.0;
    for (ts, value) in &w {
        let age = (last_ts - ts) as f64;
        let weight = (-lambda * age).exp();
        weighted_sum += weight * value;
        weight_total += weight;
    }
    if weight_total == 0.0 {
        None
    } else {
        Some(weighted_sum / weight_total)
    }
}

/// Named window function, dispatched by string so a `ThresholdProfile` can
/// store its aggregation choice as data (mirroring NOC's
/// `get_window_function(name)` registry lookup).
pub fn apply(name: &str, window: &[Sample]) -> Result<Option<f64>, String> {
    match name {
        "last" => Ok(last(window)),
        "sum" => Ok(sum(window)),
        "avg" => Ok(avg(window)),
        "q1" => Ok(q1(window)),
        "q2" | "median" => Ok(q2(window)),
        "q3" => Ok(q3(window)),
        "p95" => Ok(p95(window)),
        "p99" => Ok(p99(window)),
        "step_inc" => Ok(step_inc(window)),
        "step_dec" => Ok(step_dec(window)),
        "step_abs" => Ok(step_abs(window)),
        other => Err(format!("unknown window function '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(values: &[f64]) -> Vec<Sample> {
        values
            .iter()
            .enumerate()
            .map(|(i, v)| (i as i64, *v))
            .collect()
    }

    #[test]
    fn last_returns_the_most_recent_sample_regardless_of_input_order() {
        let mut window = w(&[1.0, 2.0, 3.0]);
        window.reverse();
        assert_eq!(last(&window), Some(3.0));
    }

    #[test]
    fn avg_and_sum_match_manual_calculation() {
        let window = w(&[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(sum(&window), Some(10.0));
        assert_eq!(avg(&window), Some(2.5));
    }

    #[test]
    fn median_of_an_odd_length_window_is_the_middle_value() {
        let window = w(&[5.0, 1.0, 3.0]);
        assert_eq!(q2(&window), Some(3.0));
    }

    #[test]
    fn p95_interpolates_between_the_two_nearest_ranks() {
        let window = w(&[0.0, 10.0, 20.0, 30.0, 40.0]);
        // rank = 0.95 * 4 = 3.8 -> interpolate between index 3 (30) and 4 (40)
        let got = p95(&window).unwrap();
        assert!((got - 38.0).abs() < 1e-9);
    }

    #[test]
    fn step_inc_ignores_decreases_and_step_dec_ignores_increases() {
        let window = w(&[10.0, 15.0, 12.0, 20.0]);
        assert_eq!(step_inc(&window), Some(5.0 + 8.0));
        assert_eq!(step_dec(&window), Some(3.0));
        assert_eq!(step_abs(&window), Some(5.0 + 3.0 + 8.0));
    }

    #[test]
    fn exp_decay_weights_recent_samples_more_than_old_ones() {
        let window: Vec<Sample> = vec![(0, 0.0), (100, 100.0)];
        let decayed = exp_decay(&window, 1.0).unwrap();
        // half-life of 1s means the sample 100s old is essentially weightless
        assert!((decayed - 100.0).abs() < 0.01);
    }

    #[test]
    fn empty_window_yields_none_not_a_fabricated_zero() {
        assert_eq!(last(&[]), None);
        assert_eq!(avg(&[]), None);
        assert_eq!(step_inc(&[]), None);
    }

    #[test]
    fn apply_dispatches_by_name_and_rejects_unknown_functions() {
        let window = w(&[1.0, 2.0, 3.0]);
        assert_eq!(apply("avg", &window), Ok(Some(2.0)));
        assert!(apply("nonsense", &window).is_err());
    }
}
