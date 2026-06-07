# Secure Secret Sharing
[![secret-sharing](https://github.com/bytemare/secret-sharing/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/secret-sharing/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secret-sharing.svg)](https://pkg.go.dev/github.com/bytemare/secret-sharing)
[![codecov](https://codecov.io/gh/bytemare/secret-sharing/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/secret-sharing)

```go
import (
	"github.com/bytemare/secret-sharing"
	"github.com/bytemare/secret-sharing/keys"
)
```

This package implements Shamir's Secret Sharing extended with Feldman's Verifiable Secret Sharing over elliptic curve groups.
It is made to be very easy to use.

Secret sharing enables to _shard_ (or _split_) a secret key into an arbitrary number of _n_ shares and to recover that
same key with any subset of at minimum _t_ of these key shares in a _(t,n)_-threshold scheme.

Note that the key distribution (sharding) algorithm used in this package is a _trusted dealer_ (i.e. centralised). If
you need a truly decentralized key generation, you can use the [dkg package](https://github.com/bytemare/dkg) which builds on this package.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secret-sharing.svg)](https://pkg.go.dev/github.com/bytemare/secret-sharing)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/secret-sharing).

## Reconstruction

The recommended reconstruction path is registry-backed verification: create committed shares with `ShardAndCommit`,
build a validated `keys.PublicKeyShareRegistry` from the public share material, then reconstruct with
`CombineVerifiedShares`.

```go
shares, err := secretsharing.ShardAndCommit(group, secret, threshold, total)
if err != nil {
    return err
}

publicShares := make([]*keys.PublicKeyShare, 0, len(shares))
for _, share := range shares {
    publicShares = append(publicShares, share.PublicKeyShare())
}

registry, err := keys.NewPublicKeyShareRegistry(
    group,
    threshold,
    total,
    shares[0].VerificationKey(),
    publicShares,
)
if err != nil {
    return err
}

recovered, err := secretsharing.CombineVerifiedShares(registry, submittedShares)
if err != nil {
    return err
}
```

`CombineShares` remains available for trusted/local shares only:

```go
recovered, err := secretsharing.CombineShares(trustedShares, threshold)
```

Raw reconstruction does not authenticate share membership or detect well-formed tampering. Use
`CombineVerifiedShares` when public registry material is available.

## Decoding

Encoded values are self-describing: the top-level `group` field is used to initialize zero-value receivers before nested
scalars and elements are decoded.

Prefer serializing public-only `keys.PublicKeyShare` or `keys.PublicKeyShareRegistry` values when distributing registry
metadata. A `keys.KeyShare` contains a participant's secret share; its JSON, compact byte encoding, and hex encoding must
be handled like private keys: no logs, public transport, telemetry, unauthenticated storage, or accidental publication.

```go
var decoded keys.PublicKeyShareRegistry
if err := json.Unmarshal(data, &decoded); err != nil {
    return err
}
```

If the group is already fixed by protocol or configuration, use a pinned receiver to reject payloads for any other
group:

```go
decoded := keys.NewPublicKeyShareRegistryReceiver(g) // or NewPublicKeyShareReceiver for one public share
if err := json.Unmarshal(data, decoded); err != nil {
    return err
}
```

Use `keys.NewKeyShareReceiver(g)` only for protected storage or transport paths that are specifically intended to carry
secret shares.

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/secret-sharing/tags).

## Release Integrity (SLSA Level 3)
Releases are built with the reusable [bytemare/slsa](https://github.com/bytemare/slsa) workflow and ship the evidence required for SLSA Level 3 compliance:

- 📦 Artifacts are uploaded to the release page, and include the deterministic source archive plus subjects.sha256, signed SBOM (sbom.cdx.json), GitHub provenance (*.intoto.jsonl), a reproducibility report (verification.json), and a signed Verification Summary Attestation (verification-summary.attestation.json[.bundle]).
- ✍️ All artifacts are signed using [Sigstore](https://sigstore.dev) with transparency via [Rekor](https://rekor.sigstore.dev).
- ✅ Verification (or see the latest docs at [bytemare/slsa](https://github.com/bytemare/slsa)):
```shell
curl -sSL https://raw.githubusercontent.com/bytemare/slsa/main/verify-release.sh -o verify-release.sh
chmod +x verify-release.sh
./verify-release.sh --repo <owner>/<repo> --tag <tag> --mode full --signer-repo bytemare/slsa
```
Run again with `--mode reproduce` to build in a container, or `--mode vsa` to validate just the verification summary.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
