#![allow(missing_docs)]
//! Cheap per-function timing instrumentation for the halo2 witness-gen hot path.
//!
//! Each `Timer` records elapsed nanoseconds on drop into a static `Stats` block.
//! `Stats` blocks self-register with a global registry on first use so callers can
//! later iterate every instrumented site via `snapshot_all()`.
//!
//! Intended usage — attach one line to the top of a function:
//!
//! ```ignore
//! pub fn foo(&self, ...) -> ... {
//!     let _t = crate::instrument!("foo");
//!     // ...body...
//! }
//! ```
//!
//! Overhead per call is one `Instant::now()`, one `elapsed()`, three
//! `AtomicU64::fetch_add(Relaxed)`, plus a single `OnceLock` fast path.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex, OnceLock,
};
use std::time::Instant;

pub struct Stats {
    pub count: AtomicU64,
    pub sum_ns: AtomicU64,
    pub sum_ns_sq: AtomicU64,
}

impl Stats {
    pub const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            sum_ns: AtomicU64::new(0),
            sum_ns_sq: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record(&self, ns: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_ns.fetch_add(ns, Ordering::Relaxed);
        // Saturating so a single very large sample can't wrap the sum-of-squares.
        let sq = (ns as u128).saturating_mul(ns as u128);
        let sq = sq.min(u64::MAX as u128) as u64;
        self.sum_ns_sq.fetch_add(sq, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            count: self.count.load(Ordering::Relaxed),
            sum_ns: self.sum_ns.load(Ordering::Relaxed),
            sum_ns_sq: self.sum_ns_sq.load(Ordering::Relaxed),
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct StatsSnapshot {
    pub count: u64,
    pub sum_ns: u64,
    pub sum_ns_sq: u64,
}

pub struct Timer<'a> {
    start: Instant,
    stats: &'a Stats,
}

impl<'a> Timer<'a> {
    #[inline]
    pub fn new(stats: &'a Stats) -> Self {
        Self { start: Instant::now(), stats }
    }
}

impl Drop for Timer<'_> {
    #[inline]
    fn drop(&mut self) {
        let ns = self.start.elapsed().as_nanos() as u64;
        self.stats.record(ns);
    }
}

static REGISTRY: OnceLock<Mutex<Vec<(&'static str, &'static Stats)>>> = OnceLock::new();

pub fn register(name: &'static str, stats: &'static Stats) {
    let m = REGISTRY.get_or_init(|| Mutex::new(Vec::new()));
    let mut g = m.lock().unwrap();
    if !g.iter().any(|(n, _)| *n == name) {
        g.push((name, stats));
    }
}

pub fn snapshot_all() -> Vec<(&'static str, StatsSnapshot)> {
    REGISTRY
        .get()
        .map(|m| m.lock().unwrap().iter().map(|(n, s)| (*n, s.snapshot())).collect())
        .unwrap_or_default()
}

/// Instrument a function. Expands to a `Timer` bound in the enclosing scope; drop
/// records elapsed ns into a static `Stats` block for `$name`.
#[macro_export]
macro_rules! instrument {
    ($name:literal) => {{
        static STATS: $crate::instrument::Stats = $crate::instrument::Stats::new();
        static REGISTERED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        REGISTERED.get_or_init(|| $crate::instrument::register($name, &STATS));
        $crate::instrument::Timer::new(&STATS)
    }};
}
