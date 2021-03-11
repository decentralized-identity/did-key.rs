use base64::URL_SAFE;
use did_url::DID;

use std::{
    convert::{TryFrom, TryInto},
    str::FromStr,
    todo,
};

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
pub enum Error {
    SignatureError,
    ResolutionFailed,
    InvalidKey,
    Unknown(String),
}

pub type DIDKey = KeyPair;

/// Generate new `did:key` of the specified type
pub fn generate<T: Generate + Ecdsa + Ecdh + DIDCore + Fingerprint + Into<KeyPair>>(seed: Option<&[u8]>) -> KeyPair {
    T::new_with_seed(seed.map_or(vec![].as_slice(), |x| x)).into()
}

/// Resolve a `did:key` from a URI
pub fn resolve(did_uri: &str) -> Result<KeyPair, Error> {
    KeyPair::try_from(did_uri)
}

/// Generate key pair from existing key material
pub fn from_existing_key<T: Generate + Ecdsa + Ecdh + DIDCore + Fingerprint + Into<KeyPair>>(
    public_key: &[u8],
    private_key: Option<&[u8]>,
) -> KeyPair {
    if private_key.is_some() {
        T::from_secret_key(private_key.unwrap()).into()
    } else {
        T::from_public_key(public_key).into()
    }
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

impl Ecdh for KeyPair {
    fn key_exchange(&self, their_public: &Self) -> Vec<u8> {
        match (self, their_public) {
            (KeyPair::X25519(me), KeyPair::X25519(them)) => me.key_exchange(them),
            (KeyPair::P256(me), KeyPair::P256(them)) => me.key_exchange(them),
            _ => unimplemented!("ECDH not supported for this key combination"),
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

impl KeyMaterial for KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyPair::Ed25519(x) => x.public_key_bytes(),
            KeyPair::X25519(x) => x.public_key_bytes(),
            KeyPair::P256(x) => x.public_key_bytes(),
            KeyPair::Bls12381G1G2(x) => x.public_key_bytes(),
            KeyPair::Secp256k1(x) => x.public_key_bytes(),
        }
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        match self {
            KeyPair::Ed25519(x) => x.private_key_bytes(),
            KeyPair::X25519(x) => x.private_key_bytes(),
            KeyPair::P256(x) => x.private_key_bytes(),
            KeyPair::Bls12381G1G2(x) => x.private_key_bytes(),
            KeyPair::Secp256k1(x) => x.private_key_bytes(),
        }
    }
}

impl Fingerprint for KeyPair {
    fn fingerprint(&self) -> String {
        match self {
            KeyPair::Ed25519(x) => x.fingerprint(),
            KeyPair::X25519(x) => x.fingerprint(),
            KeyPair::P256(x) => x.fingerprint(),
            KeyPair::Bls12381G1G2(x) => x.fingerprint(),
            KeyPair::Secp256k1(x) => x.fingerprint(),
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
    type Error = Error;

    fn try_from(did_uri: &str) -> Result<Self, Self::Error> {
        // let re = Regex::new(r"did:key:[\w]*#[\w]*\??[\w]*").unwrap();

        let url = match DID::from_str(did_uri) {
            Ok(url) => url,
            Err(_) => return Err(Error::Unknown("couldn't parse DID URI".into())),
        };

        let pub_key = match url.method_id().strip_prefix("z") {
            Some(url) => match bs58::decode(url).into_vec() {
                Ok(url) => url,
                Err(_) => return Err(Error::Unknown("invalid base58 encoded data in DID URI".into())),
            },
            None => return Err(Error::Unknown("invalid URI data".into())),
        };

        return Ok(match pub_key[0..2] {
            [0xed, 0x1] => KeyPair::Ed25519(Ed25519KeyPair::from_public_key(&pub_key[2..])),
            [0xec, 0x1] => KeyPair::X25519(X25519KeyPair::from_public_key(&pub_key[2..])),
            [0xee, 0x1] => KeyPair::Bls12381G1G2(Bls12381KeyPair::from_public_key(&pub_key[2..])),
            [0x12, 0x0] => KeyPair::P256(P256KeyPair::from_public_key(&pub_key[3..])),
            [0xe7, 0x0] => KeyPair::Secp256k1(Secp256k1KeyPair::from_public_key(&pub_key[2..])),
            _ => unimplemented!("unsupported key type"),
        });
    }
}

impl From<&VerificationMethod> for KeyPair {
    fn from(vm: &VerificationMethod) -> Self {
        if vm.private_key.is_some() {
            vm.private_key.as_ref().unwrap().into()
        } else {
            vm.public_key.as_ref().unwrap().into()
        }
    }
}

impl From<&KeyFormat> for KeyPair {
    fn from(key_format: &KeyFormat) -> Self {
        match key_format {
            KeyFormat::Base58(_) => todo!(),
            KeyFormat::Multibase(_) => todo!(),
            KeyFormat::JWK(jwk) => match jwk.curve.as_str() {
                "Ed25519" => {
                    if jwk.d.is_some() {
                        Ed25519KeyPair::from_secret_key(
                            base64::decode_config(jwk.d.as_ref().unwrap(), URL_SAFE)
                                .unwrap()
                                .as_slice(),
                        )
                        .into()
                    } else {
                        Ed25519KeyPair::from_public_key(
                            base64::decode_config(jwk.x.as_ref().unwrap(), URL_SAFE)
                                .unwrap()
                                .as_slice(),
                        )
                        .into()
                    }
                }
                "X25519" => {
                    if jwk.d.is_some() {
                        X25519KeyPair::from_secret_key(
                            base64::decode_config(jwk.d.as_ref().unwrap(), URL_SAFE)
                                .unwrap()
                                .as_slice(),
                        )
                        .into()
                    } else {
                        X25519KeyPair::from_public_key(
                            base64::decode_config(jwk.x.as_ref().unwrap(), URL_SAFE)
                                .unwrap()
                                .as_slice(),
                        )
                        .into()
                    }
                }
                _ => unimplemented!("method not supported"),
            },
        }
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
        Document, KeyFormat, VerificationMethod, CONFIG_JOSE_PRIVATE, CONFIG_JOSE_PUBLIC, CONFIG_LD_PRIVATE,
        CONFIG_LD_PUBLIC, JWK,
    },
    ed25519::Ed25519KeyPair,
    traits::{DIDCore, Ecdh, Ecdsa, Fingerprint, Generate, KeyMaterial},
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
        let key = generate::<Ed25519KeyPair>(None);
        let did_doc = key.get_did_document(Config::default());

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_did_doc_json() {
        let key = generate::<X25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_did_doc_json_bls() {
        let key = generate::<Bls12381KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_key_from_uri() {
        let uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri).unwrap();

        assert!(matches!(key, KeyPair::Ed25519(_)));
        assert_eq!("z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL", key.fingerprint())
    }

    #[test]
    fn test_key_from_uri_fragment() {
        let uri =
            "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri);

        assert!(matches!(key.unwrap(), KeyPair::Ed25519(_)));
    }

    #[test]
    fn test_key_from_uri_fragment_x25519() {
        let uri =
            "did:key:z6Mkt6QT8FPajKXDrtMefkjxRQENd9wFzKkDFomdQAVFzpzm#z6LSfDq6DuofPeZUqNEmdZsxpvfHvSoUXGEWFhw7JHk4cynN";

        let key = resolve(uri).unwrap();

        assert!(matches!(key, KeyPair::Ed25519(_)));
        assert_eq!("z6Mkt6QT8FPajKXDrtMefkjxRQENd9wFzKkDFomdQAVFzpzm", key.fingerprint())
    }

    #[test]
    fn test_generate_new_key() {
        let key = generate::<P256KeyPair>(None);
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

    #[test]
    fn serialize_to_verification_method_and_back() {
        let expected = generate::<Ed25519KeyPair>(None);
        let vm = expected.get_verification_methods(super::CONFIG_JOSE_PRIVATE, "");

        let actual: KeyPair = vm.first().unwrap().into();

        assert!(matches!(actual, KeyPair::Ed25519(_)));
        assert_eq!(actual.fingerprint(), expected.fingerprint());

        assert_eq!(
            expected.get_did_document(Config::default()),
            actual.get_did_document(Config::default())
        );
    }
}
