# Secure Secret Sharing
[![secret-sharing](https://github.com/bytemare/secret-sharing/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/secret-sharing/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secret-sharing.svg)](https://pkg.go.dev/github.com/bytemare/secret-sharing)
[![codecov](https://codecov.io/gh/bytemare/secret-sharing/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/secret-sharing)

```
  import "github.com/bytemare/secret-sharing"
```

This package implements Shamir's Secret Sharing extended with Feldman's Verifiable Secret Sharing over elliptic curve groups.
It is made to be very easy to use.

Secret sharing enables to _shard_ (or _split_) a secret key into an arbitrary number of _n_ shares and to recover that
same key with any subset of at minimum _t_ of these key shares in a _(t,n)_-threshold scheme.

Note that the key distribution (sharding) algorithm used in this package is a _trusted dealer_ (i.e. centralised). If
you need a truly decentralized key generation, you can use the [dkg package](https://github.com/bytemare/dkg) which builds on this package.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secret-sharing.svg)](https://pkg.go.dev/github.com/bytemare/secret-sharing)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/secret-sharing).

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

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
