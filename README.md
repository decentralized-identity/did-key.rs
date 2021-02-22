# Rust implementation of the `did:key` method

[`did:key` Method Spec](https://w3c-ccg.github.io/did-method-key/)

This crate is intended to provide basic support for `did:key` methods. It has no external dependencies and can be compiled for any target.
It was originally designed for use with [DIDComm Extension for gRPC](https://github.com/trinsic-id/didcomm-extension-grpc), but we recognized it may be useful if this was an independent library.

[![Rust](https://github.com/decentralized-identity/did-key.rs/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/decentralized-identity/did-key.rs/actions/workflows/rust.yml)

# History and Governance

Originally [donated](https://medium.com/decentralized-identity/trinsic-donates-did-key-rs-to-i-d-wg-8a278f37bcd0) to DIF by [Trinsic](trinsic.id). Ongoing management and governance done through the [Identifier and Discovery WG](https://github.com/decentralized-identity/identifiers-discovery).

## Supported Key Types

- Ed25519
- X25519
- P256
- SECP256K1
- BLS12381G1/G2

## Usage

[Install from crates.io](https://crates.io/crates/did-key)

```rust
did-key = "*"
```

To resolve a did formatted URI:

```rust
use did_key::*;

let key = resolve("did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL").unwrap();
let did_doc = key.get_did_document(Config::default());

```

Generate new key:

```rust
let key = generate::<Ed25519KeyPair>(None);

println!("{}", key.fingerprint());
```

Sign and verify:

```rust
let key = generate::<P256KeyPair>(None);
let message = b"message to be signed";

let signature = key.sign(Payload::Buffer(message.to_vec()));
let valid = key.verify(Payload::Buffer(message.to_vec()), &signature);

assert!(valid);
```

Create DID Document

```rust
let key = generate::<Ed25519KeyPair>(None);
let did_doc = key.get_did_document(Config::default());

let doc_json = serde_json::to_string_pretty(&did_doc).unwrap();
```

The default json format for key data is JSON-LD. To serialize a document using JOSE key format (using JWK), configure the input
parameter or use one of the static configurations ex. `CONFIG_JOSE_PUBLIC`.

```rust
let did_doc = key.get_did_document(Config {
  use_jose_format: true,    // toggle to switch between LD and JOSE key format
  serialize_secrets: false  // toggle to serialize private keys
});

// or use predefined configs

let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
```

Example JSON-LD output

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
  "assertionMethod": [
    "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
  ],
  "authentication": [
    "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
  ],
  "capabilityDelegation": [
    "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
  ],
  "capabilityInvocation": [
    "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL"
  ],
  "keyAgreement": [
    "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6LSrdqo4M24WRDJj1h2hXxgtDTyzjjKCiyapYVgrhwZAySn"
  ],
  "verificationMethod": [
    {
      "id": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
      "publicKeyBase58": "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx"
    },
    {
      "id": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6LSrdqo4M24WRDJj1h2hXxgtDTyzjjKCiyapYVgrhwZAySn",
      "type": "X25519KeyAgreementKey2019",
      "controller": "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL",
      "publicKeyBase58": "FxfdY3DCQxVZddKGAtSjZdFW9bCCW7oRwZn1NFJ2Tbg2"
    }
  ]
}
```

Example JSON output

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6LSfaBhhoYmAMX11m9xYCaeaU99KPtYnzHpsWD6iNWbJDr2",
  "keyAgreement": [
    "did:key:z6LSfaBhhoYmAMX11m9xYCaeaU99KPtYnzHpsWD6iNWbJDr2#z6LSfaBhhoYmAMX11m9xYCaeaU99KPtYnzHpsWD6iNWbJDr2"
  ],
  "verificationMethod": [
    {
      "id": "did:key:z6LSfaBhhoYmAMX11m9xYCaeaU99KPtYnzHpsWD6iNWbJDr2#z6LSfaBhhoYmAMX11m9xYCaeaU99KPtYnzHpsWD6iNWbJDr2",
      "controller": "did:key:z6LSfaBhhoYmAMX11m9xYCaeaU99KPtYnzHpsWD6iNWbJDr2",
      "type": "JsonWebKey2020",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "X25519",
        "x": "OeXe54Y0Dnk0WNWsQ6PqKUBB2x6bos0DZ_WkdFNdt3M"
      }
    }
  ]
}
```

## Benchmarks

Crate includes some basic benchmarks for key generation and exchange comparison, using `criterion`. To run the benchmarks:

```bash
cargo bench
```

## License

[Apache License 2.0](https://github.com/trinsic-id/did-key.rs/blob/main/LICENSE)

## Contributions

...are most welcome! 🙌
