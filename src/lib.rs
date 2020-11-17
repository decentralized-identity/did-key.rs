use crate::p256::P256Key;
use ed25519::Ed25519Key;
use std::convert::TryInto;
use x25519::X25519Key;

pub enum Payload<'a> {
    Buffer(&'a Vec<u8>),
    BufferArray(Vec<Vec<u8>>),
}

pub struct KeyMaterial<P, S> {
    public_key: P,
    secret_key: Option<S>,
}

pub trait Ecdsa {
    type Err;

    fn sign(&self, payload: &[u8]) -> Vec<u8>;
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Self::Err>;
}

pub trait Ecdh {
    fn key_exchange(&self, their_public: &Self) -> Vec<u8>;
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

pub enum DIDKey {
    Ed25519(Ed25519Key),
    X25519(X25519Key),
    P256(P256Key),
}

pub enum DIDKeyType {
    Ed25519,
    X25519,
    P256,
}

impl DIDKey {
    pub fn fingerprint(&self) -> String {
        let data = [&[0xec, 0x01], self.public_key().as_slice()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }

    pub fn from_seed(key_type: DIDKeyType, seed: &[u8]) -> DIDKey {
        match key_type {
            DIDKeyType::Ed25519 => DIDKey::Ed25519(Ed25519Key::from_seed(seed)),
            DIDKeyType::X25519 => DIDKey::X25519(X25519Key::from_seed(seed)),
            DIDKeyType::P256 => DIDKey::P256(P256Key::from_seed(seed)),
        }
    }

    pub fn from_public_key(key_type: DIDKeyType, seed: &[u8]) -> DIDKey {
        match key_type {
            DIDKeyType::Ed25519 => DIDKey::Ed25519(Ed25519Key::from_public_key(seed)),
            DIDKeyType::X25519 => DIDKey::X25519(X25519Key::from_public_key(seed)),
            DIDKeyType::P256 => DIDKey::P256(P256Key::from_public_key(seed)),
        }
    }

    pub fn key_exchange(&self, key: &Self) -> Vec<u8> {
        match (self, key) {
            (DIDKey::X25519(sk), DIDKey::X25519(pk)) => sk.key_exchange(pk),
            _ => todo!(),
        }
    }

    pub fn sign(&self, payload: Payload) -> Vec<u8> {
        match payload {
            Payload::Buffer(buf) => match self {
                DIDKey::Ed25519(x) => x.sign(buf.as_slice()),
                DIDKey::P256(x) => x.sign(buf.as_slice()),
                _ => unimplemented!(),
            },
            Payload::BufferArray(_) => todo!(),
        }
    }

    pub fn verify(&self, payload: Payload, signature: &Vec<u8>) -> bool {
        match payload {
            Payload::Buffer(buf) => match self {
                DIDKey::Ed25519(x) => x.verify(buf.as_slice(), signature.as_slice()),
                DIDKey::P256(x) => x.verify(buf.as_slice(), signature.as_slice()),
                _ => unimplemented!(),
            },
            Payload::BufferArray(_) => todo!(),
        }
        .map_or(false, |()| true)
    }

    pub fn public_key(&self) -> Vec<u8> {
        match self {
            DIDKey::Ed25519(x) => x.public_key.as_bytes().to_vec(),
            DIDKey::X25519(x) => x.public_key.to_bytes().to_vec(),
            DIDKey::P256(x) => x.public_key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    pub fn secret_key(&self) -> Option<Vec<u8>> {
        match self {
            DIDKey::Ed25519(key) => (&key.secret_key).as_ref().map_or(None, |x| Some(x.to_bytes().to_vec())),
            DIDKey::X25519(key) => (&key.secret_key).as_ref().map_or(None, |x| Some(x.to_bytes().to_vec())),
            DIDKey::P256(key) => (&key.secret_key).as_ref().map_or(None, |x| Some(x.to_bytes().to_vec())),
        }
    }
}

pub mod ed25519;
pub mod p256;
pub mod x25519;

#[cfg(test)]
pub mod test {
    use crate::{DIDKey, Payload};

    use super::*;
    #[test]
    fn test_demo() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = DIDKey::Ed25519(Ed25519Key::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice()));
        let message = b"super secret message";

        let signature = sk.sign(Payload::Buffer(&message.to_vec()));

        let pk = DIDKey::Ed25519(Ed25519Key::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice()));
        let is_valid = pk.verify(Payload::Buffer(&message.to_vec()), &signature);

        assert!(is_valid);
    }
}
