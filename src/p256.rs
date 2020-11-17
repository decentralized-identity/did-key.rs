use std::convert::TryFrom;

use crate::KeyMaterial;

use super::{generate_seed, Ecdsa};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyKey},
    EncodedPoint,
};
use url::Url;

pub type P256Key = KeyMaterial<VerifyKey, SigningKey>;

impl std::fmt::Debug for P256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.public_key))
    }
}

impl P256Key {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk = SigningKey::new(&secret_seed).expect("Couldn't create key");
        let pk = VerifyKey::from(&sk);

        P256Key {
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
        P256Key {
            secret_key: None, //.to_encoded_point(false),
            public_key: VerifyKey::from_encoded_point(&EncodedPoint::from_bytes(pk.as_slice()).expect("invalid key")).expect("invalid point"),
        }
    }
}

// impl From<Key> for P256Key {
//     fn from(key: Key) -> Self {
//         match key.secret_key.is_empty() {
//             true => P256Key::from_public_key(key.public_key.as_slice()),
//             false => P256Key::from_seed(vec![].as_slice()),
//         }
//     }
// }

impl TryFrom<String> for P256Key {
    type Error = String;

    fn try_from(did_uri: String) -> Result<Self, Self::Error> {
        // let re = Regex::new(r"did:key:[\w]*#[\w]*\??[\w]*").unwrap();

        let url = Url::parse(did_uri.as_ref()).unwrap();

        let fingerprint = bs58::decode(url.fragment().unwrap().strip_prefix("z").unwrap()).into_vec().unwrap();
        let fingerprint_data = fingerprint.as_slice();

        let codec = &fingerprint_data[..3];
        if codec != &[0x12, 0x0, 0x1] {
            return Err("invalid multicodec bytes".to_string());
        }
        Ok(P256Key::from_public_key(&fingerprint_data[3..]))
    }
}

impl Ecdsa for P256Key {
    type Err = String;

    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signature = match &self.secret_key {
            Some(sig) => sig.sign(payload),
            None => panic!("secret key not found"),
        };
        signature.as_ref().to_vec()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Self::Err> {
        match self.public_key.verify(payload, &Signature::try_from(signature).unwrap()).is_ok() {
            true => Ok(()),
            false => Err("invalid signature".to_string()),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    fn test_demo() {
        let key = P256Key::from_seed(vec![].as_slice());
        let message = b"super secret message";

        let signature = key.sign(message);

        let is_valud = key.verify(message, signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }
}
