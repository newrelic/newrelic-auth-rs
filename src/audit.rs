//! Structured audit logging for identity-affecting operations.
//!
//! This module exists specifically for the operations this crate's own guardrails CDD
//! flags as audit-worthy: creating a parent identity, and issuing a token from one.
//! Every function here logs at `info` (or `warn` on failure/refusal) so operators don't
//! need a non-default log level to see these events. None of these functions ever log a
//! private key, an API key, a client secret, or a token's value — only identifiers
//! (client IDs, organization IDs) and metadata about the operation.

use crate::system_identity::SystemIdentity;
use crate::system_identity::input_data::environment::NewRelicEnvironment;

/// Logs successful creation of a bootstrap identity (L1 or L2, including a parent identity
/// created via `create-bootstrap-identity key`).
///
/// Takes the whole `SystemIdentity` rather than individual fields so this can log
/// `identity_type` via its `Debug` impl, which redacts the L1 client secret
/// (`ClientSecret`'s `Debug` prints "redacted" — see `system_identity.rs`). Do not change
/// this to log `identity_type`'s `Serialize` output instead; that one intentionally
/// includes the real secret, for the CLI's own stdout output.
pub fn log_bootstrap_identity_created(identity: &SystemIdentity) {
    tracing::info!(
        audit = true,
        event = "bootstrap_identity_created",
        identity_type = ?identity.identity_type,
        client_id = %identity.client_id,
        organization_id = %identity.organization_id,
        "system identity created"
    );
}

/// Logs a successful token issuance from a parent identity (`authenticate`).
pub fn log_token_issued(parent_client_id: &str, environment: &NewRelicEnvironment) {
    tracing::info!(
        audit = true,
        event = "token_issued",
        parent_client_id,
        environment = ?environment,
        "authentication token issued from parent identity"
    );
}

/// Logs a failed token issuance attempt.
pub fn log_token_issuance_failed(
    parent_client_id: &str,
    environment: &NewRelicEnvironment,
    reason: &str,
) {
    tracing::warn!(
        audit = true,
        event = "token_issuance_failed",
        parent_client_id,
        environment = ?environment,
        reason,
        "authentication token issuance failed"
    );
}

/// Logs a token issuance refused by the local advisory rate limit.
///
/// This is not a security event on its own — it means the local, single-machine
/// advisory limit refused the call, not that anything was compromised. It's logged at
/// `warn` because an operator who didn't expect to hit this limit should notice it.
pub fn log_rate_limited(parent_client_id: &str, count: u32, limit: u32) {
    tracing::warn!(
        audit = true,
        event = "rate_limited",
        parent_client_id,
        count,
        limit,
        "token issuance refused: advisory local rate limit exceeded"
    );
}
