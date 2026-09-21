//! An advisory, local-only rate limit on token issuance per parent identity.
//!
//! Read this module's doc comment before reaching for it: it is not a security boundary.
//! It tracks issuance counts in a plain file on the machine running this CLI, keyed by
//! parent `client_id`. Anyone who can delete that file, run this CLI from a different
//! machine, or call the underlying NerdGraph mutation directly bypasses it entirely. Its
//! purpose is to catch an accidental runaway loop in a caller's own automation — a bug,
//! not an attacker — before it mints far more tokens than anyone intended. A real,
//! unbypassable cap on children minted per parent has to be enforced server-side; see
//! the parent-mints-child CDD's Open Questions for the ask to IAM this module does not
//! and cannot substitute for.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const WINDOW_SECS: u64 = 3600;

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error(
        "advisory rate limit exceeded: {count} token(s) already issued for this parent in the last hour (limit: {limit})"
    )]
    Exceeded { count: u32, limit: u32 },
    #[error("failed to read/write rate limit state at {path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("failed to (de)serialize rate limit state: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RateLimitState {
    /// Unix timestamps (seconds) of each recorded issuance still inside the tracked window.
    issuances: Vec<u64>,
}

pub struct LocalRateLimiter {
    state_dir: PathBuf,
}

impl LocalRateLimiter {
    pub fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    /// `~/.newrelic-auth-cli/rate-limit`, falling back to a relative directory in the
    /// current working directory if `HOME` isn't set (e.g. some CI runners).
    pub fn default_state_dir() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(".newrelic-auth-cli").join("rate-limit"))
            .unwrap_or_else(|| PathBuf::from(".newrelic-auth-cli-rate-limit"))
    }

    fn state_path(&self, parent_client_id: &str) -> PathBuf {
        // Defensive sanitization before using this as a filename component. Client IDs
        // are expected to already be filesystem-safe, but this never trusts that.
        let safe_id: String = parent_client_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.state_dir.join(format!("{safe_id}.json"))
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Checks whether issuing one more token for `parent_client_id` would exceed `limit`
    /// within the trailing hour. If not, records this issuance and returns `Ok(())`. If
    /// it would, returns `Err(RateLimitError::Exceeded)` without recording anything, so a
    /// caller that retries later isn't penalized for the refused attempt itself.
    pub fn check_and_record(
        &self,
        parent_client_id: &str,
        limit: u32,
    ) -> Result<(), RateLimitError> {
        fs::create_dir_all(&self.state_dir).map_err(|e| RateLimitError::Io {
            path: self.state_dir.to_string_lossy().into_owned(),
            source: e,
        })?;

        let path = self.state_path(parent_client_id);
        let mut state = Self::load(&path)?;

        let now = Self::now_secs();
        let window_start = now.saturating_sub(WINDOW_SECS);
        state.issuances.retain(|&t| t >= window_start);

        let count = state.issuances.len() as u32;
        if count >= limit {
            return Err(RateLimitError::Exceeded { count, limit });
        }

        state.issuances.push(now);
        Self::save(&path, &state)
    }

    fn load(path: &Path) -> Result<RateLimitState, RateLimitError> {
        match fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(RateLimitState::default()),
            Err(e) => Err(RateLimitError::Io {
                path: path.to_string_lossy().into_owned(),
                source: e,
            }),
        }
    }

    fn save(path: &Path, state: &RateLimitState) -> Result<(), RateLimitError> {
        let contents = serde_json::to_string(state)?;
        fs::write(path, contents).map_err(|e| RateLimitError::Io {
            path: path.to_string_lossy().into_owned(),
            source: e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state_dir(test_name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nr-auth-rate-limit-test-{test_name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn allows_calls_under_the_limit() {
        let limiter = LocalRateLimiter::new(temp_state_dir("under-limit"));
        for _ in 0..5 {
            limiter.check_and_record("parent-1", 5).unwrap();
        }
    }

    #[test]
    fn refuses_the_call_that_would_exceed_the_limit() {
        let limiter = LocalRateLimiter::new(temp_state_dir("exceed-limit"));
        for _ in 0..3 {
            limiter.check_and_record("parent-1", 3).unwrap();
        }
        let err = limiter.check_and_record("parent-1", 3).unwrap_err();
        match err {
            RateLimitError::Exceeded { count, limit } => {
                assert_eq!(count, 3);
                assert_eq!(limit, 3);
            }
            other => panic!("expected Exceeded, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_call_is_not_itself_recorded() {
        let limiter = LocalRateLimiter::new(temp_state_dir("refused-not-recorded"));
        limiter.check_and_record("parent-1", 1).unwrap();
        assert!(limiter.check_and_record("parent-1", 1).is_err());
        // Still refused, not "recorded twice then allowed a third time" — the count
        // should stay pinned at 1, not climb from the refused attempts themselves.
        assert!(limiter.check_and_record("parent-1", 1).is_err());
    }

    #[test]
    fn tracks_different_parents_independently() {
        let limiter = LocalRateLimiter::new(temp_state_dir("independent-parents"));
        limiter.check_and_record("parent-a", 1).unwrap();
        // parent-b has its own, independent budget — parent-a's usage doesn't affect it.
        limiter.check_and_record("parent-b", 1).unwrap();
        assert!(limiter.check_and_record("parent-a", 1).is_err());
        assert!(limiter.check_and_record("parent-b", 1).is_err());
    }

    #[test]
    fn old_issuances_outside_the_window_are_not_counted() {
        let dir = temp_state_dir("old-issuances-expire");
        let limiter = LocalRateLimiter::new(dir.clone());
        limiter.check_and_record("parent-1", 1).unwrap();
        assert!(limiter.check_and_record("parent-1", 1).is_err());

        // Simulate the recorded issuance having happened over an hour ago by rewriting
        // the state file directly, rather than sleeping the test for real.
        let path = limiter.state_path("parent-1");
        let stale_state = RateLimitState {
            issuances: vec![LocalRateLimiter::now_secs() - WINDOW_SECS - 1],
        };
        LocalRateLimiter::save(&path, &stale_state).unwrap();

        limiter.check_and_record("parent-1", 1).unwrap();
    }

    #[test]
    fn sanitizes_client_id_used_as_a_filename() {
        let limiter = LocalRateLimiter::new(temp_state_dir("sanitize-filename"));
        // A client_id containing path-unsafe characters must not escape state_dir or
        // otherwise break the on-disk layout.
        limiter
            .check_and_record("../../etc/passwd", 5)
            .expect("should sanitize rather than fail or escape the state directory");
        let entries: Vec<_> = fs::read_dir(&limiter.state_dir).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }
}
