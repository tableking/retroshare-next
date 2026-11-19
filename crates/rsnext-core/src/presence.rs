//! Peer presence (upstream: `libretroshare/src/retroshare/rsstatus.h`).
//!
//! Scope stated honestly: there is no heartbeat protocol yet. Presence is derived from the last
//! time a peer made authenticated contact, which is the only fact this node actually holds. A
//! periodic status broadcast would add the peer's self-reported idle state on top of this; the
//! derivation below is written so that adding it cannot change the storage or the call sites.

use crate::store::Store;
use anyhow::Result;
use rusqlite::params;

/// Thresholds, in seconds, for "still around". These are presentation constants, not protocol
/// timeouts: nothing is dropped or refused because of them.
pub const ONLINE_SECS: i64 = 120;
pub const AWAY_SECS: i64 = 900;

pub const ONLINE: &str = "online";
pub const AWAY: &str = "away";
pub const OFFLINE: &str = "offline";
pub const NEVER: &str = "never contacted";

/// The one clock used for recording contact. Kept separate from the derivation so the thresholds
/// stay testable against a caller-supplied `now` instead of the wall clock.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Pure so the boundary conditions are testable without a clock, a peer, or a database.
pub fn derive_state(age: i64) -> &'static str {
    if age <= ONLINE_SECS {
        ONLINE
    } else if age <= AWAY_SECS {
        AWAY
    } else {
        OFFLINE
    }
}

impl Store {
    pub fn ensure_presence(&self) -> Result<()> {
        let db = self.conn();
        db.execute(
            "CREATE TABLE IF NOT EXISTS peer_presence(\
               fp TEXT PRIMARY KEY, last_seen INTEGER NOT NULL)",
            [],
        )?;
        db.execute(
            "CREATE TABLE IF NOT EXISTS peer_declared(\
               fp TEXT PRIMARY KEY, state TEXT NOT NULL, idle INTEGER NOT NULL, ts INTEGER NOT NULL)",
            [],
        )?;
        Ok(())
    }

    /// Record authenticated contact. Monotonic on purpose: a late-arriving frame carrying an older
    /// timestamp must not make a peer look less reachable than we already knew.
    pub fn peer_seen(&self, fp: &str, ts: i64) -> Result<()> {
        self.ensure_presence()?;
        let db = self.conn();
        db.execute(
            "INSERT INTO peer_presence(fp,last_seen) VALUES(?1,?2) \
             ON CONFLICT(fp) DO UPDATE SET last_seen=MAX(peer_presence.last_seen, excluded.last_seen)",
            params![fp, ts],
        )?;
        Ok(())
    }

    pub fn last_seen(&self, fp: &str) -> Option<i64> {
        let Ok(db) = self.guard() else { return None };
        db.query_row("SELECT last_seen FROM peer_presence WHERE fp=?1", params![fp], |r| r.get::<_, i64>(0))
            .ok()
    }

    /// (state, last_seen) as of `now`. Absent peers report no timestamp rather than epoch 0, so a
    /// UI cannot display "1970" as if it were a real observation.
    pub fn presence(&self, fp: &str, now: i64) -> (String, Option<i64>) {
        match self.last_seen(fp) {
            Some(t) => (derive_state(now.saturating_sub(t)).to_string(), Some(t)),
            None => (NEVER.to_string(), None),
        }
    }

    /// What a peer said about itself, as reported at `ts`.
    pub fn declare(&self, fp: &str, state: &str, idle: i64, ts: i64) -> Result<()> {
        self.ensure_presence()?;
        let db = self.conn();
        db.execute(
            "INSERT INTO peer_declared(fp,state,idle,ts) VALUES(?1,?2,?3,?4) \
             ON CONFLICT(fp) DO UPDATE SET state=excluded.state, idle=excluded.idle, ts=excluded.ts \
             WHERE peer_declared.ts <= excluded.ts",
            params![fp, state, idle, ts],
        )?;
        Ok(())
    }

    /// Declared state is only trusted while it is fresher than `stale_secs`; after that the peer's
    /// own claim tells us nothing and the observed contact time is the better evidence.
    pub fn declared(&self, fp: &str, now: i64, stale_secs: i64) -> Option<(String, i64)> {
        let db = self.guard().ok()?;
        let row = db.query_row(
            "SELECT state, ts FROM peer_declared WHERE fp=?1",
            params![fp], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).ok()?;
        if now - row.1 <= stale_secs { Some((row.0, row.1)) } else { None }
    }

    /// The answer a UI should show: a fresh self-report wins, otherwise we fall back to what our
    /// own observations support. Both are reported so a client can tell them apart.
    pub fn presence_merged(&self, fp: &str, now: i64, stale_secs: i64) -> (String, String, Option<i64>) {
        let (derived, seen) = self.presence(fp, now);
        match self.declared(fp, now, stale_secs) {
            Some((st, _)) => (st, "declared".to_string(), seen),
            None => (derived, "observed".to_string(), seen),
        }
    }

    /// Presence for everyone we have ever contacted, aged against `now` (the caller's clock, so the
    /// listing is testable without sleeping).
    pub fn all_presence(&self, now: i64) -> Vec<(String, String, Option<i64>)> {
        let Ok(db) = self.guard() else { return Vec::new() };
        let Ok(mut st) = db.prepare("SELECT fp,last_seen FROM peer_presence ORDER BY last_seen DESC") else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))) else { return Vec::new() };
        rows.flatten()
            .map(|(fp, t)| (fp, derive_state(now.saturating_sub(t)).to_string(), Some(t)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_are_the_documented_boundaries() {
        assert_eq!(derive_state(0), ONLINE);
        assert_eq!(derive_state(ONLINE_SECS), ONLINE, "the boundary is inclusive");
        assert_eq!(derive_state(ONLINE_SECS + 1), AWAY);
        assert_eq!(derive_state(AWAY_SECS), AWAY);
        assert_eq!(derive_state(AWAY_SECS + 1), OFFLINE);
        // a clock skew that puts contact in the future must read as online, not as a wrap-around
        assert_eq!(derive_state(-30), ONLINE);
    }

    #[test]
    fn contact_is_recorded_and_never_moves_backwards() {
        let st = Store::open(":memory:").unwrap();
        st.peer_seen("AAAA-1111", 1000).unwrap();
        assert_eq!(st.last_seen("AAAA-1111"), Some(1000));
        st.peer_seen("AAAA-1111", 900).unwrap();
        assert_eq!(st.last_seen("AAAA-1111"), Some(1000), "a stale frame must not degrade presence");
        st.peer_seen("AAAA-1111", 1500).unwrap();
        assert_eq!(st.last_seen("AAAA-1111"), Some(1500));
        // state is computed against the caller's clock, so it is testable without sleeping
        assert_eq!(st.presence("AAAA-1111", 1500).0, ONLINE);
        assert_eq!(st.presence("AAAA-1111", 1500 + AWAY_SECS + 1).0, OFFLINE);
    }

    #[test]
    fn listing_ages_every_entry_against_the_caller_clock() {
        let st = Store::open(":memory:").unwrap();
        st.peer_seen("BBBB-2222", 5_000).unwrap();
        st.peer_seen("AAAA-1111", 5_000 + AWAY_SECS + 10).unwrap();
        let rows = st.all_presence(5_000 + AWAY_SECS + 10);
        assert_eq!(rows.len(), 2);
        // most recently seen first, and each row's state computed from the same `now`
        assert_eq!(rows[0].0, "AAAA-1111");
        assert_eq!(rows[0].1, ONLINE);
        assert_eq!(rows[1].0, "BBBB-2222");
        assert_eq!(rows[1].1, OFFLINE, "the older contact is {} seconds stale", AWAY_SECS + 10);
        assert!(st.all_presence(0).iter().all(|(_, s, _)| s == ONLINE), "a clock before every contact reads as fresh, not negative-garbage");
    }

    #[test]
    fn a_fresh_self_report_wins_and_a_stale_one_is_ignored() {
        let st = Store::open(":memory:").unwrap();
        st.peer_seen("AAAA-1111", 1_000).unwrap();
        st.declare("AAAA-1111", "away", 60, 1_000).unwrap();
        // at now=1010 the report is 10s old -> trusted; the derived state would say online
        let (state, kind, _) = st.presence_merged("AAAA-1111", 1_010, 120);
        assert_eq!((state.as_str(), kind.as_str()), ("away", "declared"));
        // far beyond staleness the claim is dropped rather than guessed at
        let (state2, kind2, _) = st.presence_merged("AAAA-1111", 100_000, 120);
        assert_eq!((state2.as_str(), kind2.as_str()), (OFFLINE, "observed"));
        // an out-of-order older report must not overwrite a newer one
        st.declare("AAAA-1111", "online", 0, 900).unwrap();
        let (state3, _, _) = st.presence_merged("AAAA-1111", 1_010, 120);
        assert_eq!(state3, "away", "stale declaration must not clobber the fresh one");
    }

    #[test]
    fn an_unknown_peer_has_no_timestamp_rather_than_epoch_zero() {
        let st = Store::open(":memory:").unwrap();
        let (state, seen) = st.presence("ZZZZ-0000", 1500);
        assert_eq!(state, NEVER);
        assert_eq!(seen, None, "reporting 1970 implies we observed them once - we did not");
    }
}
