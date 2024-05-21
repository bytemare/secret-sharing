# Secure Secret Sharing
[![secret-sharing](https://github.com/bytemare/secret-sharing/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/secret-sharing/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secret-sharing.svg)](https://pkg.go.dev/github.com/bytemare/secret-sharing)
[![codecov](https://codecov.io/gh/bytemare/secret-sharing/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/secret-sharing)

```
  import "github.com/bytemare/secret-sharing"
```

This package implements Shamir's Secret Sharing extended with Verifiable Secret Sharing over elliptic curve groups.

Secret sharing enables to _shard_ (or _split_) a secret key into an arbitrary number of shares _n_ and to recover that
same key using only a subset _t+1_ of these key shares, where _t_ represents the threshold of allowed missing or
compromised key shares. This allows for distributed usage of that sharded key useful in threshold schemes.

Note that the key distribution (sharding) algorithm used in this package is a _trusted dealer_ (i.e. centralised). 

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secret-sharing.svg)](https://pkg.go.dev/github.com/bytemare/secret-sharing)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/secret-sharing).

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/secret-sharing/tags).


## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
