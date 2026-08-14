//! Measurement units, ported from NOC's `pm.models.measurementunits`
//! (noc-master `pm/models/measurementunits.py`).
//!
//! NOC's `MeasurementUnits` document ties a metric to a display label and a
//! scale ladder (SI, binary, or none) so operators see e.g. `12.3 Mbit/s`
//! instead of a raw integer. This module keeps a small static registry of
//! the units FragglePacket's own metrics actually use instead of a
//! Mongo collection.

use super::scale::{humanize_string, Scale, BINARY_SCALES, SI_SCALES, UNSCALED};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasurementUnits {
    /// Short machine code, e.g. `"percent"`, `"ms"`, `"byte"`.
    pub code: &'static str,
    /// Suffix appended after the scaled value, e.g. `"%"`, `"ms"`, `"B"`.
    pub suffix: &'static str,
    ladder: UnitLadder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitLadder {
    Si,
    Binary,
    None,
}

impl MeasurementUnits {
    fn ladder(&self) -> &'static [Scale] {
        match self.ladder {
            UnitLadder::Si => SI_SCALES,
            UnitLadder::Binary => BINARY_SCALES,
            UnitLadder::None => UNSCALED,
        }
    }

    /// Render `value` (already expressed in this unit's base, e.g. raw
    /// milliseconds) as a human string, e.g. `"210.0ms"`.
    pub fn humanize(&self, value: f64, precision: usize) -> String {
        format!("{}{}", humanize_string(value, self.ladder(), precision), self.suffix)
    }
}

pub const SCALAR: MeasurementUnits = MeasurementUnits {
    code: "scalar",
    suffix: "",
    ladder: UnitLadder::None,
};

pub const PERCENT: MeasurementUnits = MeasurementUnits {
    code: "percent",
    suffix: "%",
    ladder: UnitLadder::None,
};

pub const MILLISECOND: MeasurementUnits = MeasurementUnits {
    code: "ms",
    suffix: "ms",
    ladder: UnitLadder::None,
};

pub const BYTE: MeasurementUnits = MeasurementUnits {
    code: "byte",
    suffix: "B",
    ladder: UnitLadder::Binary,
};

/// Bits per second, decimal-scaled (e.g. `12.3Mbit/s`) -- for a future
/// throughput metric type; uses the SI ladder rather than the binary one
/// since network link speeds are conventionally quoted in decimal Mbit/Gbit.
pub const BITS_PER_SECOND: MeasurementUnits = MeasurementUnits {
    code: "bit/s",
    suffix: "bit/s",
    ladder: UnitLadder::Si,
};

/// Look up one of the units above by its `code`.
pub fn by_code(code: &str) -> Option<MeasurementUnits> {
    [SCALAR, PERCENT, MILLISECOND, BYTE, BITS_PER_SECOND]
        .into_iter()
        .find(|u| u.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_never_gets_an_si_prefix() {
        assert_eq!(PERCENT.humanize(3.5, 1), "3.5%");
        assert_eq!(PERCENT.humanize(12000.0, 1), "12000.0%");
    }

    #[test]
    fn millisecond_prints_raw_value_with_suffix() {
        assert_eq!(MILLISECOND.humanize(210.4, 1), "210.4ms");
    }

    #[test]
    fn byte_uses_the_binary_ladder() {
        assert_eq!(BYTE.humanize(1500.0, 2), "1.46KiB");
    }

    #[test]
    fn by_code_finds_known_units_and_rejects_unknown() {
        assert_eq!(by_code("percent"), Some(PERCENT));
        assert_eq!(by_code("nonsense"), None);
    }

    #[test]
    fn bits_per_second_uses_the_si_ladder() {
        assert_eq!(BITS_PER_SECOND.humanize(12_300_000.0, 1), "12.3Mbit/s");
    }
}
