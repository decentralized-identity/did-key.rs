# Rust implementation of the `did:key` method

[`did:key` Method Spec](https://w3c-ccg.github.io/did-method-key/)

This crate is intended to provide basic support for `did:key` methods. It has no external dependencies and can be compiled for any target.
It was originally designed for use with [DIDComm Extension for gRPC](https://github.com/trinsic-id/didcomm-extension-grpc), but we recognized it may be useful if this was an independent library.

## Supported Key Types

- Ed25519
- X25519
- P256
- BLS12381G1/G2

## Usage

[Install from crates.io](https://crates.io/crates/did-key)

```rust
did-key = "0.0.1"
```

To resolve a did formatted URI:

```rust
use did_key::*;

let key = DIDKey::resolve("did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL").unwrap();

```

Generate new key:

```rust
let key = DIDKey::new(DIDKeyType::Ed25519);

println!("{}", key.fingerprint());
```

Sign and verify:

```rust
let key = DIDKey::new(DIDKeyType::P256);
let message = b"message to be signed";

let signature = key.sign(Payload::Buffer(message.to_vec()));
let valid = key.verify(Payload::Buffer(message.to_vec()), &signature);

assert!(valid);
```

## License

[Apache License 2.0](https://github.com/trinsic-id/did-key.rs/blob/main/LICENSE)

## Contributions

...are most welcome! 🙌