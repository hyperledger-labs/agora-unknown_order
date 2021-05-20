# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.1.2

### Fixes

- Fix bug in gmp_backend to_bytes

## v0.1.1

### Added

- README.md updates
- Code doc updates
- Require openssl = 0.10.34+
- Added Group to easier operations
- Added std::iter::{Sum, Product} implementations to BigNumber
- Added modneg to BigNumber

## v0.1.0

### Added

- `gmp_backend::Bn` - A Big Number implementation backed by Gnu's MP Library
- `openssl_backend::Bn` - A Big Number implementation backed by Openssl's BigNum Library
- `rust_backend::Bn` - A Big Number implementation backed by Rust's BigInt crate
- `gcd_result::GcdResult` - A GCD result that contains the gcd value and the Bézout coefficients
