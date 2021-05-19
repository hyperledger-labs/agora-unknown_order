#!/bin/zsh

echo "Building w/Gnu MP Lib"
cargo build --no-default-features --features=gmp
echo "Building w/OpenSSL"
cargo build --no-default-features --features=openssl
echo "Building w/Rust"
cargo build --no-default-features --features=rust
