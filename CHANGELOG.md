# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Unreleased section should follow [Release Toolkit](https://github.com/newrelic/release-toolkit/blob/main/README.md).

## Unreleased

## v0.5.1 - 2026-06-16

### ⛓️ Dependencies
- Updated rust crate jsonwebtoken to 10.4.0
- Updated rust crate serde_json to 1.0.150
- Updated rust crate reqwest to 0.13.4
- Updated rust crate http to 1.4.2
- Updated rust to v1.96.0
- Updated rust crate uuid to 1.23.3
- Updated rust crate chrono to 0.4.45

## v0.5.0 - 2026-05-11

### 🚀 Enhancements
- Support JP endpoints

## v0.4.2 - 2026-04-30

### 🐛 Bug fixes
- Log oauth client errors

### ⛓️ Dependencies
- Upgraded github actions (major version bumps)
- Upgraded Rust to v1.95.0
- Upgraded uuid and other minor crates

## v0.4.1 - 2026-04-16

### ⛓️ Dependencies
- Upgraded github actions
- Upgraded uuid to 1.23.1
- Upgraded tokio to 1.52.0
- Upgraded clap to 4.6.1
- Lock file maintenance

## v0.4.0 - 2026-04-08

### ⚠️ Breaking Changes
- Identity generation simplification: Removes intermediate generator module (L1SystemIdentityGenerator, L2SystemIdentityGenerator) and Creator trait abstraction
- Callers can now invoke `iam_client.create_l1_system_identity()` and `iam_client.create_l2_system_identity()` directly
- The `key::creator` module is renamed to `key::generation` and components are renamed accordingly

## v0.3.0 - 2026-04-02

### 🚀 Enhancements
- `create-identity` command now supports New Relic User API Key as an alternative to bearer tokens
- Added `create-bootstrap-identity` command to create an identity capable of creating other identities

### ⚠️ Breaking Changes
- Internal library breaking changes leveraged to the agent control

## v0.2.0 - 2026-03-18

### 🚀 Enhancements
- Windows build support via CI/CD improvements

## v0.1.4 - 2026-03-02

### 🚀 Enhancements
- Replace ring with aws_lc_rs in rcgen dependency

### ⛓️ Dependencies
- Upgraded reqwest to 0.13.2
- Upgraded chrono, clap, uuid, tempfile and other minor crates
- Upgraded github actions and rust toolchain

## v0.1.3 - 2026-02-05

### ⛓️ Dependencies
- Upgraded multiple minor and patch dependencies

## v0.1.2 - 2026-01-09

### 🚀 Enhancements
- Add usage hints documentation
- Switch vaultrs to use rustls instead of native-tls
- Bump Rust edition to minimum supported version
- Pin action digests for improved supply-chain security

### ⛓️ Dependencies
- Upgraded reqwest to 0.13.1
- Upgraded mockall, http, rcgen, uuid, clap and other minor crates
- Upgraded github actions (including major version bumps)

## v0.1.1 - 2025-10-16

### 🐛 Bug fixes
- Make credential module public

## v0.1.0 - 2025-10-16

### 🚀 Enhancements
- Public API improvements
