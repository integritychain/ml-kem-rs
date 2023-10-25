# [IntegrityChain] FIPS 203 (Initial Public Draft): Module-Lattice-Based Key-Encapsulation Mechanism Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[mlKem] Module-Lattice-Based Key-Encapsulation Mechanism Standard written in pure Rust.

[Documentation][docs-link]

## Security Notes

This crate is under construction.

USE AT YOUR OWN RISK!

## Supported Algorithms

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1023

## Minimum Supported Rust Version

Rust **1.72** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

All crates licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/ml-kem-rs

[crate-link]: https://crates.io/crates/ml-kem-rs

[docs-image]: https://docs.rs/ml-kem-rs/badge.svg

[docs-link]: https://docs.rs/ml-kem-rs/

[build-image]: https://github.com/integritychain/ml-kem-rs/workflows/ml-kem-rs/badge.svg?branch=master&event=push

[build-link]: https://github.com/integritychain/ml-kem-rs/actions?query=workflow%3Aml-kem-rs

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg

[rustc-image]: https://img.shields.io/badge/rustc-1.72+-blue.svg

[//]: # (general links)

[IntegrityChain]: https://github.com/integritychain/

[mlKem]: https://csrc.nist.gov/pubs/fips/203/ipd
