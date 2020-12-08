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
did-key = "0.0.2"
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

Create DID Document

```rust
let key = DIDKey::new(DIDKeyType::Ed25519);
let did_doc = key.to_did_document();

let doc_json = serde_json::to_string_pretty(&did_doc).unwrap();
```

> The output `Document` struct will create JSON+LD in compact form.

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
  "keyAggrement": [
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

## License

[Apache License 2.0](https://github.com/trinsic-id/did-key.rs/blob/main/LICENSE)

## Contributions

...are most welcome! 🙌