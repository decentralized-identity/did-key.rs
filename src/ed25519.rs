use crate::KeyMaterial;

use super::{generate_seed, Ecdsa};
use ed25519_dalek::*;
use std::convert::{TryFrom, TryInto};
use url::Url;

pub type Ed25519Key = KeyMaterial<PublicKey, SecretKey>;

impl Ed25519Key {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk: SecretKey = SecretKey::from_bytes(&secret_seed).expect("cannot generate secret key");
        let pk: PublicKey = (&sk).try_into().expect("cannot generate public key");

        Ed25519Key {
            secret_key: Some(sk),
            public_key: pk,
        }
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        Ed25519Key {
            public_key: PublicKey::from_bytes(public_key).expect("invalid byte data"),
            secret_key: None,
        }
    }
}

impl TryFrom<String> for Ed25519Key {
    type Error = String;

    fn try_from(did_uri: String) -> Result<Self, Self::Error> {
        // let re = Regex::new(r"did:key:[\w]*#[\w]*\??[\w]*").unwrap();

        let url = Url::parse(did_uri.as_ref()).unwrap();

        let fingerprint = bs58::decode(url.fragment().unwrap().strip_prefix("z").unwrap()).into_vec().unwrap();
        let fingerprint_data = fingerprint.as_slice();

        let codec = &fingerprint_data[..2];
        if codec != &[0xed, 0x1] {
            return Err("invalid multicodec bytes".to_string());
        }
        let public_key = &fingerprint_data[2..];

        Ok(Ed25519Key::from_public_key(public_key))
    }
}

impl Ecdsa for Ed25519Key {
    type Err = String;

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let esk: ExpandedSecretKey = match &self.secret_key {
            Some(x) => x,
            None => panic!("secret key not found"),
        }
        .into();

        esk.sign(payload, &self.public_key).to_bytes().to_vec()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Self::Err> {
        let sig = Signature::try_from(signature).expect("invalid signature data");
        match self.public_key.verify(payload, &sig) {
            Ok(_) => Ok(()),
            _ => Err(String::from("verify failed")),
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

        let sk = Ed25519Key::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message";

        let signature = sk.sign(message);

        let pk = Ed25519Key::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valud = pk.verify(message, signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }

    #[test]
    fn test_demo_did_key() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = DIDKey::from_seed(DIDKeyType::Ed25519, bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message";

        let signature = sk.sign(Payload::Buffer(&message.to_vec()));

        let pk = DIDKey::from_public_key(DIDKeyType::Ed25519, bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valud = pk.verify(Payload::Buffer(&message.to_vec()), &signature);

        assert!(is_valud);
    }
}
