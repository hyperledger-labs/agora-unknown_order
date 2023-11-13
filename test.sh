#!/bin/zsh

echo "Testing w/Gnu MP Lib"
cargo test --no-default-features --features=gmp
echo "Testing w/OpenSSL"
cargo test --no-default-features --features=openssl
echo "Testing w/Rust"
cargo test --no-default-features --features=rust
