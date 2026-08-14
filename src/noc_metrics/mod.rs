//! `noc_metrics` -- performance-management concepts adapted from
//! [NOC](https://getnoc.com) (`pm/models/*.py`, `core/window.py`), reused
//! here to give FragglePacket's diagnosis engine configurable, windowed,
//! hysteresis-aware thresholds instead of scattered magic numbers.
//!
//! This is a deliberate *adaptation*, not a line-for-line port: NOC's
//! versions are Mongo-backed Django documents wired into a full alarm/NOC
//! stack, which has no equivalent here. What's kept is the *modeling*:
//!
//! * [`scale`] / [`units`] -- human-friendly rendering of raw values via an
//!   SI or binary scale ladder (`pm.models.scale.Scale`,
//!   `pm.models.measurementunits.MeasurementUnits`).
//! * [`metric_type`] -- a small typed registry of the metrics
//!   FragglePacket measures, each with a name, unit, and description
//!   (`pm.models.metrictype.MetricType`).
//! * [`window`] -- pure aggregation functions (`last`, `avg`, percentiles,
//!   step deltas, exponential decay) run over a recent set of samples
//!   before thresholding (`core.window`).
//! * [`threshold`] -- `ThresholdProfile`/`ThresholdConfig`, with distinct
//!   open and clear conditions per severity rung, plus `ThresholdState` for
//!   stateful hysteresis across repeated evaluations
//!   (`pm.models.thresholdprofile.ThresholdProfile`).

pub mod metric_type;
pub mod scale;
pub mod threshold;
pub mod units;
pub mod window;

pub use metric_type::MetricType;
pub use threshold::{CompareOp, ThresholdConfig, ThresholdProfile, ThresholdState, WindowType};
pub use units::MeasurementUnits;
pub use window::Sample;
