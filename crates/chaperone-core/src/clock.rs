use chrono::{DateTime, SecondsFormat, Utc};

/// The injected time source (Law 6): evaluation never reads the wall clock and
/// there is no randomness in the decision path. Services take a `Clock`.
/// `FixedClock` is the ONLY clock used in unit tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Wall-clock time — production only.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Deterministic time — tests, replay, and any clocked simulation.
#[derive(Debug, Clone)]
pub struct FixedClock(DateTime<Utc>);

impl FixedClock {
    pub fn new(at: DateTime<Utc>) -> Self {
        FixedClock(at)
    }

    /// Moves the fixed time forward (e.g. simulating TTL expiry in sweeper tests).
    pub fn advance(&mut self, by: chrono::Duration) {
        self.0 += by;
    }
}

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// The single RFC3339 formatting path: UTC, seconds precision, `Z` suffix —
/// matches the frozen wire examples (docs/api-contracts.md).
pub fn rfc3339_utc(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    #[test]
    fn fixed_clock_advances() {
        let mut c = FixedClock::new(Utc.with_ymd_and_hms(2026, 8, 25, 14, 0, 0).unwrap());
        let t0 = c.now();
        assert_eq!(rfc3339_utc(t0), "2026-08-25T14:00:00Z");
        c.advance(Duration::minutes(15));
        assert_eq!(c.now(), t0 + Duration::minutes(15));
        assert_eq!(rfc3339_utc(c.now()), "2026-08-25T14:15:00Z");
    }
}
