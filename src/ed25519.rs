use super::{generate_seed, Ecdsa};
use crate::{AsymmetricKey, Payload};
use ed25519_dalek::*;
use std::convert::{TryFrom, TryInto};

pub type Ed25519KeyPair = AsymmetricKey<PublicKey, SecretKey>;

impl Ed25519KeyPair {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk: SecretKey = SecretKey::from_bytes(&secret_seed).expect("cannot generate secret key");
        let pk: PublicKey = (&sk).try_into().expect("cannot generate public key");

        Ed25519KeyPair {
            secret_key: Some(sk),
            public_key: pk,
        }
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        Ed25519KeyPair {
            public_key: PublicKey::from_bytes(public_key).expect("invalid byte data"),
            secret_key: None,
        }
    }
}

impl Ecdsa for Ed25519KeyPair {
    type Err = String;

    fn sign(&self, payload: Payload) -> Vec<u8> {
        let esk: ExpandedSecretKey = match &self.secret_key {
            Some(x) => x,
            None => panic!("secret key not found"),
        }
        .into();

        match payload {
            Payload::Buffer(payload) => esk.sign(payload.as_slice(), &self.public_key).to_bytes().to_vec(),
            Payload::BufferArray(_) => unimplemented!("payload type not supported for this key"),
        }
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Self::Err> {
        let sig = Signature::try_from(signature).expect("invalid signature data");
        match payload {
            Payload::Buffer(payload) => match self.public_key.verify(payload.as_slice(), &sig) {
                Ok(_) => Ok(()),
                _ => Err(String::from("verify failed")),
            },
            _ => unimplemented!("payload type not supported for this key"),
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::{DIDKey, DIDKeyType, Payload};

    use super::*;
    #[test]
    fn test_demo() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message".to_vec();

        let signature = sk.sign(Payload::Buffer(message.clone()));

        let pk = Ed25519KeyPair::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valud = pk.verify(Payload::Buffer(message), signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }

    #[test]
    fn test_demo_did_key() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = DIDKey::from_seed(
            DIDKeyType::Ed25519,
            bs58::decode(secret_key).into_vec().unwrap().as_slice(),
        );
        let message = b"super secret message";

        let signature = sk.sign(Payload::Buffer(message.to_vec()));

        let pk = DIDKey::from_public_key(
            DIDKeyType::Ed25519,
            bs58::decode(public_key).into_vec().unwrap().as_slice(),
        );
        let is_valud = pk.verify(Payload::Buffer(message.to_vec()), &signature);

        assert!(is_valud);
    }
}
