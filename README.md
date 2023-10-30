# [IntegrityChain]: FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]

[FIPS 203] (Initial Public Draft) Module-Lattice-Based Key-Encapsulation Mechanism
Standard written in pure Rust.

This library implements the FIPS 203 **draft** standard in pure Rust with minimal and
mainstream dependencies. All three security parameter sets are fully functional. The
code does not require the standard library, e.g. `#[no_std]`, and has no heap
allocations so will be suitable for WASM, embedded and bare-metal applications.
Significant performance optimizations are forthcoming.

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf> for a full
description of the target functionality.

The functionality is extremely simple to use, as demonstrated by the following example.

~~~rust
// Use the desired target parameter set.
use ml_kem_rs::ml_kem_512; // Could also be ml_kem_768 or ml_kem_1024. 

// Alice runs `key_gen()` and then serializes the encaps key `ek` for Bob (to bytes).
let (alice_ek, alice_dk) = ml_kem_512::key_gen();
let alice_ek_bytes = alice_ek.to_bytes();

// Alice sends the encaps key `ek_bytes` to Bob.
let bob_ek_bytes = alice_ek_bytes;

// Bob deserializes the encaps `ek_bytes` and then runs `encaps() to get the shared 
// secret `ssk` and ciphertext `ct`. He serializes the ciphertext `ct` for Alice (to bytes).
let bob_ek = ml_kem_512::new_ek(bob_ek_bytes);
let (bob_ssk_bytes, bob_ct) = bob_ek.encaps();
let bob_ct_bytes = bob_ct.to_bytes();

// Bob sends the ciphertext `ct_bytes` to Alice
let alice_ct_bytes = bob_ct_bytes;

// Alice deserializes the ciphertext `ct` and runs `decaps()` with her decaps key
let alice_ct = ml_kem_512::new_ct(alice_ct_bytes);
let alice_ssk_bytes = alice_dk.decaps(&alice_ct);

// Alice and Bob will now have the same secret key
assert_eq!(bob_ssk_bytes, alice_ssk_bytes);
~~~

Rust [Documentation][docs-link]

## Security Notes

This crate is functional and corresponds to the first initial public draft of FIPS 203.
This crate is still under construction/refinement -- USE AT YOUR OWN RISK!

## Supported Parameter Sets

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

[build-image]: https://github.com/integritychain/ml-kem-rs/workflows/test/badge.svg

[build-link]: https://github.com/integritychain/ml-kem-rs/actions?query=workflow%3Atest

[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg

[rustc-image]: https://img.shields.io/badge/rustc-1.72+-blue.svg

[//]: # (general links)

[IntegrityChain]: https://github.com/integritychain/

[FIPS 203]: https://csrc.nist.gov/pubs/fips/203/ipd
