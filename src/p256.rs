use super::{generate_seed, Ecdsa};
use crate::{AsymmetricKey, Payload};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyKey},
    EncodedPoint,
};
use std::convert::TryFrom;

pub type P256KeyPair = AsymmetricKey<VerifyKey, SigningKey>;

impl std::fmt::Debug for P256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.public_key))
    }
}

impl P256KeyPair {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk = SigningKey::new(&secret_seed).expect("Couldn't create key");
        let pk = VerifyKey::from(&sk);

        P256KeyPair {
            public_key: pk, //.to_encoded_point(false),
            secret_key: Some(sk),
        }
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        let pk: Vec<u8> = match public_key.len() == 65 {
            true => public_key.to_vec(),
            false => {
                let mut pkk = public_key.to_vec();
                pkk.insert(0, 0x04);
                pkk
            }
        };
        P256KeyPair {
            secret_key: None, //.to_encoded_point(false),
            public_key: VerifyKey::from_encoded_point(&EncodedPoint::from_bytes(pk.as_slice()).expect("invalid key"))
                .expect("invalid point"),
        }
    }
}

impl Ecdsa for P256KeyPair {
    type Err = String;

    fn sign(&self, payload: Payload) -> Vec<u8> {
        match payload {
            Payload::Buffer(payload) => {
                let signature = match &self.secret_key {
                    Some(sig) => sig.sign(&payload),
                    None => panic!("secret key not found"),
                };
                signature.as_ref().to_vec()
            }
            _ => unimplemented!("payload type not supported for this key"),
        }
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Self::Err> {
        match payload {
            Payload::Buffer(payload) => match self
                .public_key
                .verify(&payload, &Signature::try_from(signature).unwrap())
                .is_ok()
            {
                true => Ok(()),
                false => Err("invalid signature".to_string()),
            },
            _ => unimplemented!("payload type not supported for this key"),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    fn test_demo() {
        let key = P256KeyPair::from_seed(vec![].as_slice());
        let message = b"super secret message".to_vec();

        let signature = key.sign(Payload::Buffer(message.clone()));

        let is_valud = key.verify(Payload::Buffer(message), signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }
}
