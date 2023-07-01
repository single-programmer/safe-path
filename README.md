# safe-path

An "opiniated" TLS library that only negociates TLS v1.3 with TLS_CHACHA20_POLY1305_SHA256 encryption, x25519 ECDH and curve25519 signatures.
It uses the all-Rust no-unsafe [solid-pillar](https://github.com/single-programmer/solid-pillar) cryptography libary.
