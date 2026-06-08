# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/secret-sharing/releases).

## [Unreleased]

### Added

- Public machine-checkable error classes for downstream callers, including too few shares, malformed cryptographic input,
  invalid registries, invalid key/share material, unknown shares, and key encoding/decoding failures.
- Group-pinned JSON decoding constructors for key shares, public key shares, and public key share registries.
- Group-pinned compact decoding through the same receiver constructors.
- Validated key-share, public-share, and complete-registry constructors with defensive-copy accessors.
- Threshold-aware `CombineShares` and registry-backed `CombineVerifiedShares`.
- Verified reconstruction examples built around `ShardAndCommit`, `PublicKeyShareRegistry`, and
  `CombineVerifiedShares`.
- Nightly fuzzing and expanded hardening tests for share validation, registry decoding, polynomial operations, and JSON
  context handling.
- Table, property-style, and fuzz tests for self-describing and group-pinned JSON decoding.

### Changed

- Documentation now presents verified reconstruction as the recommended path and clearly labels raw `CombineShares` as a
  trusted-share primitive.
- `KeyShare` serialization documentation now warns that JSON, compact, and hex encodings contain secret share material
  and must be handled like private keys.
- JSON decoding now uses structured parsing and validates group consistency instead of inferring groups with regexes.
- Zero-value JSON receivers infer their group from the encoded top-level group, while pre-set groups pin the expected
  decoding context.
- Compact registry decoding now validates group binding, registry parameters, identifiers, commitment lengths, VSS
  shares, and verification-key consistency.
- Compact registry encodings are canonical and sorted by participant identifier. Non-canonical compact registry inputs
  are rejected.
- Key-share, public-share, and registry trust-bearing fields are private and preserve validated state after construction.
- Registry construction validates cryptographic invariants and stores defensive copies instead of caller-owned aliases.
- `Commit` now returns an error for malformed input instead of panicking.
- Polynomial validation now separates coefficient validation from interpolation-identifier validation. Explicit
  non-leading zero coefficients are accepted, while zero secrets, zero leading coefficients, and invalid interpolation
  identifiers remain rejected.
- Ephemeral polynomial cleanup clears every coefficient, including the copied secret term.
- The primary Go test workflow now runs the root package, `keys`, and `tests` packages with race and vet enabled.
- CI and release workflows were refreshed with pinned actions, hardened runners, dependency review, ORT configuration,
  and SLSA release integrity checks.

### Removed

- Regex and shadow-struct based JSON decoding internals.
- Mutable registry construction through `Add`.
- The equality-only `VerifyPublicKey` registry name; use `ContainsPublicKey`.

### Breaking

- Nested ECC JSON values now follow the `github.com/bytemare/ecc` v0.10.0 object encoding. Legacy nested hex-string
  JSON values are no longer accepted.
- `CombineShares` now requires an explicit threshold argument.
- `Commit` now returns `(VssCommitment, error)`.
- Key-share, public-share, and registry fields are no longer directly mutable. Use validated constructors and
  defensive-copy accessors.
- The minimum Go version is now `1.26.3`.
