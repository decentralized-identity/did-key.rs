#![feature(trait_alias)]

use did_url::DID;

use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
};
use traits::{DIDCore, Ecdh, Ecdsa, Fingerprint, KeyMaterial};

pub enum KeyPair {
    Ed25519(Ed25519KeyPair),
    X25519(X25519KeyPair),
    P256(P256KeyPair),
    Bls12381G1G2(Bls12381KeyPair),
    Secp256k1(Secp256k1KeyPair),
}

pub struct AsymmetricKey<P, S> {
    public_key: P,
    secret_key: Option<S>,
}

pub enum Payload {
    Buffer(Vec<u8>),
    BufferArray(Vec<Vec<u8>>),
}

#[derive(Debug)]
pub enum Error<'a> {
    SignatureError,
    ResolutionFailed,
    InvalidKey,
    Unknown(&'a str),
}

pub trait DIDKey = KeyMaterial + Ecdsa + Ecdh + DIDCore + Fingerprint;

pub fn generate<T: DIDKey>() -> impl DIDKey {
    T::new()
}

pub fn generate_with_seed<T: DIDKey>(seed: &[u8]) -> impl DIDKey {
    T::new_with_seed(seed)
}

pub fn resolve(did_uri: &str) -> Result<KeyPair, String> {
    KeyPair::try_from(did_uri)
}

impl Ecdsa for KeyPair {
    fn sign(&self, payload: Payload) -> Vec<u8> {
        match self {
            KeyPair::Ed25519(x) => x.sign(payload),
            KeyPair::X25519(x) => x.sign(payload),
            KeyPair::P256(x) => x.sign(payload),
            KeyPair::Bls12381G1G2(x) => x.sign(payload),
            KeyPair::Secp256k1(x) => x.sign(payload),
        }
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Error> {
        match self {
            KeyPair::Ed25519(x) => x.verify(payload, signature),
            KeyPair::X25519(x) => x.verify(payload, signature),
            KeyPair::P256(x) => x.verify(payload, signature),
            KeyPair::Bls12381G1G2(x) => x.verify(payload, signature),
            KeyPair::Secp256k1(x) => x.verify(payload, signature),
        }
    }
}

impl DIDCore for KeyPair {
    fn get_verification_methods(&self, config: didcore::Config, controller: &str) -> Vec<VerificationMethod> {
        match self {
            KeyPair::Ed25519(x) => x.get_verification_methods(config, controller),
            KeyPair::X25519(x) => x.get_verification_methods(config, controller),
            KeyPair::P256(x) => x.get_verification_methods(config, controller),
            KeyPair::Bls12381G1G2(x) => x.get_verification_methods(config, controller),
            KeyPair::Secp256k1(x) => x.get_verification_methods(config, controller),
        }
    }

    fn get_did_document(&self, config: didcore::Config) -> Document {
        match self {
            KeyPair::Ed25519(x) => x.get_did_document(config),
            KeyPair::X25519(x) => x.get_did_document(config),
            KeyPair::P256(x) => x.get_did_document(config),
            KeyPair::Bls12381G1G2(x) => x.get_did_document(config),
            KeyPair::Secp256k1(x) => x.get_did_document(config),
        }
    }
}

pub(crate) fn generate_seed(initial_seed: &[u8]) -> Result<[u8; 32], &str> {
    let mut seed = [0u8; 32];
    if initial_seed.is_empty() || initial_seed.len() != 32 {
        getrandom::getrandom(&mut seed).expect("couldn't generate random seed");
    } else {
        seed = match initial_seed.try_into() {
            Ok(x) => x,
            Err(_) => return Err("invalid seed size"),
        };
    }
    Ok(seed)
}

impl TryFrom<&str> for KeyPair {
    type Error = String;

    fn try_from(did_uri: &str) -> Result<Self, Self::Error> {
        // let re = Regex::new(r"did:key:[\w]*#[\w]*\??[\w]*").unwrap();

        let url = match DID::from_str(did_uri) {
            Ok(url) => url,
            Err(_) => return Err("couldn't parse DID URI".to_string()),
        };

        let pub_key = match url
            .fragment()
            .map_or(url.to_string().replace("did:key:", ""), |x| x.to_string())
            .strip_prefix("z")
        {
            Some(url) => match bs58::decode(url).into_vec() {
                Ok(url) => url,
                Err(_) => return Err("invalid base58 encoded data in DID URI".to_string()),
            },
            None => return Err("invalid URI data".to_string()),
        };

        return Ok(match pub_key[0..2] {
            [0xed, 0x1] => KeyPair::Ed25519(Ed25519KeyPair::from_public_key(&pub_key[2..])),
            [0xec, 0x1] => KeyPair::X25519(X25519KeyPair::from_public_key(&pub_key[2..])),
            [0xea, 0x1] => KeyPair::Bls12381G1G2(Bls12381KeyPair::from_public_key(&pub_key[2..])),
            [0x12, 0x0] => KeyPair::P256(P256KeyPair::from_public_key(&pub_key[3..])),
            [0xe7, 0x0] => KeyPair::Secp256k1(Secp256k1KeyPair::from_public_key(&pub_key[2..])),
            _ => unimplemented!("unsupported key type"),
        });
    }
}

impl From<&[u8]> for Payload {
    fn from(data: &[u8]) -> Self {
        Payload::Buffer(data.to_vec())
    }
}

impl From<Vec<u8>> for Payload {
    fn from(data: Vec<u8>) -> Self {
        Payload::Buffer(data)
    }
}

mod bls12381;
mod didcore;
mod ed25519;
mod p256;
mod secp256k1;
mod traits;
mod x25519;
pub use {
    crate::p256::P256KeyPair,
    crate::secp256k1::Secp256k1KeyPair,
    bls12381::Bls12381KeyPair,
    didcore::{
        Document, VerificationMethod, CONFIG_JOSE_PRIVATE, CONFIG_JOSE_PUBLIC, CONFIG_LD_PRIVATE, CONFIG_LD_PUBLIC,
    },
    ed25519::Ed25519KeyPair,
    x25519::X25519KeyPair,
};

#[cfg(test)]
pub mod test {
    use crate::{didcore::Config, KeyPair, Payload};

    use super::*;
    #[test]
    fn test_demo() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message";

        let signature = sk.sign(Payload::Buffer(message.to_vec()));

        let pk = Ed25519KeyPair::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valid = pk.verify(Payload::Buffer(message.to_vec()), &signature).unwrap();

        matches!(is_valid, ());
    }

    #[test]
    fn test_did_doc_ld() {
        let key = generate::<Ed25519KeyPair>();
        let did_doc = key.get_did_document(Config::default());

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_did_doc_json() {
        let key = generate::<X25519KeyPair>();
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_did_doc_json_bls() {
        let key = generate::<Bls12381KeyPair>();
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_key_from_uri() {
        let uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri);

        assert!(matches!(key.unwrap(), KeyPair::Ed25519(_)));
    }

    #[test]
    fn test_key_from_uri_fragment() {
        let uri =
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri);

        assert!(matches!(key.unwrap(), KeyPair::Ed25519(_)));
    }

    #[test]
    fn test_generate_new_key() {
        let key = generate::<P256KeyPair>();
        let message = b"secret message";

        println!("{}", key.fingerprint());

        let signature = key.sign(Payload::Buffer(message.to_vec()));
        let valid = key.verify(Payload::Buffer(message.to_vec()), &signature);

        matches!(valid, Ok(()));
    }

    #[test]
    fn test_key_resolve() {
        let key = resolve("did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL").unwrap();

        assert!(matches!(key, KeyPair::Ed25519(_)));
    }
}
