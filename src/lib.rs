/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! This crate handles groups of unknown order.
//!
//! I've seen this commonly across multiple projects where they need a multiprecision library
//! and use one of three libraries: [Gnu MP BigNum Library](https://gmplib.org/), [OpenSSL's BigNum Library](https://www.openssl.org/docs/man1.0.2/man3/bn.html)
//! and [Rust's BigInt Library](https://crates.io/crates/num-bigint), depending on the needs and requirements (licensing, performance, platform target).
//!
//! This library wraps them all into a common API, so they can be used interchangeably.
//!
//! Groups of unknown order require using a modulus that is the composite of two big prime numbers. This
//! library is designed to facilitate these use cases such as RSA, [Paillier](https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_16.pdf), [Hyperelliptic Curves](https://eprint.iacr.org/2020/196),
//! [Accumulators](https://eprint.iacr.org/2018/1188), [CL signatures](http://cs.brown.edu/people/alysyans/papers/camlys02b.pdf).
//!
//! The modulus is not known at compile time which excludes using certain traits like `ff::PrimeField`, so
//! unfortunately, the caller needs to remember to use methods prefixed with `mod` to achieve the desired results.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    missing_docs,
    trivial_casts,
    unconditional_recursion,
    unsafe_code,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    unused_extern_crates,
    unused_parens,
    while_true,
    warnings
)]

#[macro_use]
mod macros;

#[cfg(all(feature = "openssl", feature = "rust"))]
compile_error!(r#"Cannot compile both features "openssl" and "rust""#);
#[cfg(all(feature = "openssl", feature = "gmp"))]
compile_error!(r#"Cannot compile both features "openssl" and "gmp""#);
#[cfg(all(feature = "rust", feature = "gmp"))]
compile_error!(r#"Cannot compile both features "rust" and "gmp""#);

#[cfg(feature = "gmp")]
mod gmp_backend;
#[cfg(feature = "openssl")]
mod openssl_backend;
#[cfg(feature = "rust")]
mod rust_backend;

#[cfg(feature = "gmp")]
use gmp_backend as b;
#[cfg(feature = "openssl")]
use openssl_backend as b;
#[cfg(feature = "rust")]
use rust_backend as b;

mod gcd_result;
mod group;

#[cfg(any(feature = "rust", feature = "gmp"))]
pub(crate) fn get_mod(n: &BigNumber) -> BigNumber {
    if n < &BigNumber::zero() {
        -n.clone()
    } else {
        n.clone()
    }
}

pub use b::Bn as BigNumber;
pub use gcd_result::*;
pub use group::*;
