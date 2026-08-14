//! Scale ladders, ported from NOC's `pm.models.scale.Scale` model
//! (noc-master `pm/models/scale.py`).
//!
//! NOC stores a set of `Scale` documents (name, code, SI/IEC multiplier) and
//! uses them to render a raw counter/gauge value in human-friendly form --
//! e.g. turning `1_500_000` into `"1.5M"`. Rather than a Mongo-backed
//! document per scale step, this is a small `const` ladder plus a
//! `humanize()` walk, since FragglePacket has no database layer, but the
//! selection algorithm (find the largest step whose divisor does not push
//! the value below 1.0) mirrors NOC's behaviour.

/// One rung of a scale ladder: `value_in_base_units / base^exp` gives the
/// scaled value to display next to `label`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scale {
    pub label: &'static str,
    pub base: f64,
    pub exp: i32,
}

impl Scale {
    pub const fn new(label: &'static str, base: f64, exp: i32) -> Self {
        Self { label, base, exp }
    }

    pub fn divisor(&self) -> f64 {
        self.base.powi(self.exp)
    }
}

/// SI decimal ladder (n, u, m, <none>, k, M, G, T), ascending by exponent.
pub const SI_SCALES: &[Scale] = &[
    Scale::new("n", 10.0, -9),
    Scale::new("u", 10.0, -6),
    Scale::new("m", 10.0, -3),
    Scale::new("", 10.0, 0),
    Scale::new("k", 10.0, 3),
    Scale::new("M", 10.0, 6),
    Scale::new("G", 10.0, 9),
    Scale::new("T", 10.0, 12),
];

/// Binary (IEC) ladder for byte-oriented values (Ki, Mi, Gi, Ti).
pub const BINARY_SCALES: &[Scale] = &[
    Scale::new("", 2.0, 0),
    Scale::new("Ki", 2.0, 10),
    Scale::new("Mi", 2.0, 20),
    Scale::new("Gi", 2.0, 30),
    Scale::new("Ti", 2.0, 40),
];

/// No scaling at all -- used for units like percent where a raw number is
/// always shown as-is.
pub const UNSCALED: &[Scale] = &[Scale::new("", 1.0, 0)];

/// Pick the largest ladder step whose divisor does not push `value` below
/// 1.0 in magnitude (falling back to the smallest step for tiny values),
/// then return `(scaled_value, step)`.
pub fn humanize(value: f64, ladder: &[Scale]) -> (f64, Scale) {
    if ladder.is_empty() {
        return (value, Scale::new("", 1.0, 0));
    }
    if value == 0.0 || !value.is_finite() {
        let zero_step = ladder
            .iter()
            .copied()
            .find(|s| s.exp == 0)
            .unwrap_or(ladder[0]);
        return (value, zero_step);
    }
    let mag = value.abs();
    let mut chosen = ladder[0];
    for step in ladder {
        if mag >= step.divisor() {
            chosen = *step;
        } else {
            break;
        }
    }
    (value / chosen.divisor(), chosen)
}

/// `humanize()` plus formatting into a display string, e.g. `"1.50M"`.
pub fn humanize_string(value: f64, ladder: &[Scale], precision: usize) -> String {
    let (scaled, step) = humanize(value, ladder);
    format!("{:.*}{}", precision, scaled, step.label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn si_scale_picks_the_right_rung() {
        assert_eq!(humanize(0.005, SI_SCALES).1.label, "m");
        assert_eq!(humanize(42.0, SI_SCALES).1.label, "");
        assert_eq!(humanize(1_500_000.0, SI_SCALES).1.label, "M");
        assert_eq!(humanize(2_500_000_000.0, SI_SCALES).1.label, "G");
    }

    #[test]
    fn si_scale_value_is_divided_by_the_chosen_step() {
        let (scaled, step) = humanize(1_500_000.0, SI_SCALES);
        assert_eq!(step.label, "M");
        assert!((scaled - 1.5).abs() < 1e-9);
    }

    #[test]
    fn binary_scale_picks_kibi_and_mebi_correctly() {
        assert_eq!(humanize(2048.0, BINARY_SCALES).1.label, "Ki");
        assert_eq!(humanize(5_242_880.0, BINARY_SCALES).1.label, "Mi");
    }

    #[test]
    fn zero_and_nan_never_pick_an_exponent_shifted_rung() {
        assert_eq!(humanize(0.0, SI_SCALES).1.exp, 0);
        assert_eq!(humanize(f64::NAN, SI_SCALES).1.exp, 0);
    }

    #[test]
    fn humanize_string_formats_with_label_suffix() {
        assert_eq!(humanize_string(1_500_000.0, SI_SCALES, 1), "1.5M");
        assert_eq!(humanize_string(42.0, UNSCALED, 1), "42.0");
    }
}
