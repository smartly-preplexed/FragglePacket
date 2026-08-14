//! Metric type registry, ported from NOC's `pm.models.metrictype`
//! (noc-master `pm/models/metrictype.py`).
//!
//! NOC defines every measurable quantity (interface load, CPU usage,
//! latency, ...) as a `MetricType` document: a name, a field type, a unit,
//! whether the raw counter is a delta (needs rate conversion) or a gauge,
//! and free-text documentation. FragglePacket adopts the same idea for its
//! own measurements so that a `ThresholdProfile` (see `threshold.rs`) can
//! refer to a metric by name instead of a bare string, and so the unit used
//! to *display* a value is defined in exactly one place.

use super::units::{self, MeasurementUnits};

#[derive(Debug, Clone, Copy)]
pub struct MetricType {
    /// Dotted name, following NOC's `Category | Name` convention, e.g.
    /// `"Network | RTT"`.
    pub name: &'static str,
    pub units: MeasurementUnits,
    /// True for a running counter that must be rate-converted before use
    /// (NOC's `is_counter`); false for an already-instantaneous gauge.
    pub is_counter: bool,
    pub description: &'static str,
}

pub const RTT_MS: MetricType = MetricType {
    name: "Network | RTT",
    units: units::MILLISECOND,
    is_counter: false,
    description: "Round-trip time to the target, as reported by ping's avg_ms",
};

pub const PACKET_LOSS_PERCENT: MetricType = MetricType {
    name: "Network | Packet Loss",
    units: units::PERCENT,
    is_counter: false,
    description: "Share of probes that received no reply",
};

pub const JITTER_MS: MetricType = MetricType {
    name: "Network | Jitter",
    units: units::MILLISECOND,
    is_counter: false,
    description: "Variation in round-trip time between consecutive probes",
};

pub const INTERFACE_MTU_BYTES: MetricType = MetricType {
    name: "Interface | MTU",
    units: units::BYTE,
    is_counter: false,
    description: "Configured or measured interface MTU",
};

pub const TCP_SEGMENT_LIMIT_BYTES: MetricType = MetricType {
    name: "TCP | Segment Limit",
    units: units::BYTE,
    is_counter: false,
    description: "Largest TCP segment observed to pass a middlebox unmodified",
};

pub const DNS_RESOLUTION_MS: MetricType = MetricType {
    name: "DNS | Resolution Time",
    units: units::MILLISECOND,
    is_counter: false,
    description: "Wall-clock time to resolve the target hostname",
};

/// Every metric type FragglePacket knows about, for lookup/documentation
/// purposes (mirrors iterating NOC's `MetricType` collection).
pub const ALL: &[MetricType] = &[
    RTT_MS,
    PACKET_LOSS_PERCENT,
    JITTER_MS,
    INTERFACE_MTU_BYTES,
    TCP_SEGMENT_LIMIT_BYTES,
    DNS_RESOLUTION_MS,
];

pub fn by_name(name: &str) -> Option<MetricType> {
    ALL.iter().copied().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_metric_type_is_findable_by_name() {
        for m in ALL {
            assert_eq!(by_name(m.name).map(|f| f.name), Some(m.name));
        }
    }

    #[test]
    fn rtt_and_loss_use_the_units_the_diagnosis_engine_expects() {
        assert_eq!(RTT_MS.units.code, "ms");
        assert_eq!(PACKET_LOSS_PERCENT.units.code, "percent");
    }
}
