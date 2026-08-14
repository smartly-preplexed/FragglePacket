# NOC integration

FragglePacket now reuses performance-management concepts from
[NOC](https://getnoc.com) (the `noc-master` codebase this was integrated
against) in a new `src/noc_metrics/` module. This is an *adaptation*, not a
vendored copy: NOC's originals are Mongo-backed Django documents wired into
a full alarm/NMS stack, which has no equivalent here. What's kept is the
modeling, re-implemented in plain Rust with no new dependencies.

## What was ported

| FragglePacket module | Ported from (noc-master) | What it does |
|---|---|---|
| `noc_metrics::scale` | `pm/models/scale.py` | SI / binary scale-ladder humanization (e.g. `1_500_000` → `"1.5M"`) |
| `noc_metrics::units` | `pm/models/measurementunits.py` | Ties a metric to a display unit + scale ladder |
| `noc_metrics::metric_type` | `pm/models/metrictype.py` | Small typed registry of FragglePacket's own metrics (RTT, packet loss, jitter, MTU, TCP segment limit, DNS resolution time) |
| `noc_metrics::window` | `core/window.py` | Pure aggregation functions run over recent samples before thresholding: `last`, `sum`, `avg`, `q1`/`q2`/`q3`, `p95`, `p99`, `step_inc`/`step_dec`/`step_abs`, `exp_decay` |
| `noc_metrics::threshold` | `pm/models/thresholdprofile.py` | `ThresholdProfile`/`ThresholdConfig` (open condition + a separate, looser clear condition per severity rung) and `ThresholdState` (stateful hysteresis across repeated evaluations) |

NOC's `window.py` also has a `handler` window function that dispatches to an
arbitrary Python plugin; that's intentionally not ported, since there's no
equivalent "arbitrary plugin" concept here.

## Why this is more than decoration

Two consumers of this were changed, both in `src/diagnosis/mod.rs`:

- **`HighPacketLossRule` / `HighLatencyRule`** used to compare a single
  scalar against a hardcoded number (`loss_percent >= 10.0`, `rtt_ms >
  200.0`). They now evaluate a `ThresholdProfile` instead:
  - Thresholds are data (`packet_loss_profile()` / `latency_profile()` in
    the same file) instead of literals buried in `if`/`else` chains.
  - A window function (`avg` by default) runs over however many samples
    the caller has -- one sample behaves identically to the old point
    check (see `high_packet_loss_rule_matches_the_old_point_thresholds_from_a_single_sample`
    and the sibling latency test), but a real multi-sample window (e.g.
    `packet_loss_samples: vec![(t0, 0.0), (t1, 30.0), (t2, 0.0), ...]`)
    now gets smoothed instead of alarming on one spike --
    see `packet_loss_rule_windows_multiple_samples_instead_of_only_looking_at_the_last_one`.
  - `ThresholdState` gives any future repeated-evaluation caller (a
    monitoring loop, the TUI dashboard, a future `serve`-style long-running
    mode) hysteresis for free: once a rung opens, only its clear condition
    -- not just dipping back under the open value -- closes it, so a
    metric oscillating right around the threshold doesn't flap. See
    `threshold_state_hysteresis_is_available_for_repeated_evaluation`.

- **`report.rs` had a live bug this surfaced**: `DiagnosisEvidence.packet_loss_percent`
  and `.rtt_ms` were only ever populated by hand in unit tests --
  `run_unified_report` never actually ran an RTT/loss probe, so
  `HighPacketLossRule`/`HighLatencyRule` were unreachable in the shipped
  `report` command. `RttTest` is now run as part of the unified report and
  its `loss_percent`/`avg_ms` metrics feed the evidence, so those two rules
  are live in production, not just in tests. Verified end-to-end against
  loopback (`fraggle-packet report 127.0.0.1 --json`): the RTT test result
  now appears in `probe_results`, and (correctly) triggers no false
  diagnosis against clean loopback traffic.

## Tests

`src/noc_metrics/` ships 26 unit tests of its own (scale/unit humanization,
every window function, threshold open/clear matching, windowed smoothing,
and the hysteresis dead-zone behavior). `src/diagnosis/mod.rs` adds 6 more
covering backward compatibility with the old point-threshold behavior, the
windowing improvement, and hysteresis. All existing tests were left
untouched and still pass.

## Sandbox build notes (not part of the integration itself)

Verifying the build in this environment required unrelated fixes, kept
separate from the NOC work above:

- `dioxus`/`rfd` (used only by the `fraggle-desktop` GUI binary) are now
  gated behind an opt-in `desktop` Cargo feature, with
  `required-features = ["desktop"]` on that binary target. `cargo build`/
  `cargo test` on the library, CLI, and TUI no longer need GTK/webkit at
  all; build with `--features desktop` for the GUI.
- `Cargo.lock` has a handful of dependencies pinned to slightly older
  patch/minor versions (`quinn`/`quinn-proto`, `clap`, `native-tls`/
  `openssl`/`openssl-sys`, `rayon`/`rayon-core`, `time`, `zeroize`,
  `rustc-hash`, `unicode-segmentation`, `instability`) because this
  sandbox's available Rust toolchain (1.75, via apt; newer toolchains were
  unreachable over the network here) is older than several dependencies'
  current MSRV. On a machine with a modern Rust toolchain (1.85+) these
  pins are unnecessary and `cargo update` can move them back to latest.
- `fraggle-desktop` (the Dioxus GUI) could not be built or tested in this
  sandbox at all, regardless of the above -- it needs Rust 1.85+, which
  wasn't reachable here. Everything else (library: 695 tests, CLI/TUI
  binary: 14 tests, integration tests: 10 tests) builds and passes.
