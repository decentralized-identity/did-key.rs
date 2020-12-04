use crate::{ed25519::Ed25519KeyPair, AsymmetricKey};

use super::{generate_seed, Ecdh};
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha512};
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

pub type X25519Key = AsymmetricKey<PublicKey, StaticSecret>;

impl X25519Key {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk = StaticSecret::from(secret_seed);
        let pk: PublicKey = (&sk).try_into().expect("invalid public key");

        X25519Key {
            public_key: pk,
            secret_key: Some(sk),
        }
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut pk: [u8; 32] = [0; 32];
        pk.clone_from_slice(public_key);

        X25519Key {
            public_key: PublicKey::from(pk),
            secret_key: None,
        }
    }
}

impl Ecdh for X25519Key {
    fn key_exchange(&self, key: &Self) -> Vec<u8> {
        match &(self.secret_key) {
            Some(x) => x.diffie_hellman(&key.public_key).as_bytes().to_vec(),
            None => panic!("secret key not present"),
        }
    }
}

impl From<Ed25519KeyPair> for X25519Key {
    fn from(key: Ed25519KeyPair) -> Self {
        match key.secret_key {
            Some(sk) => {
                let hash = Sha512::digest(&sk.as_ref()[..32]);
                let mut output = [0u8; 32];
                output.copy_from_slice(&hash[..32]);
                output[0] &= 248;
                output[31] &= 127;
                output[31] |= 64;

                X25519Key::from_seed(&output)
            }
            None => {
                let var_name: [u8; 32] = key.public_key.as_bytes().to_vec().as_slice().try_into().unwrap();
                let compressed = CompressedEdwardsY(var_name).decompress().unwrap();
                let montgomery = compressed.to_montgomery();

                X25519Key::from_public_key(montgomery.as_bytes())
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    fn test_demo() {
        let alice = X25519Key::from_seed(vec![].as_slice());
        let bob = X25519Key::from_seed(vec![].as_slice());

        let ex1 = alice.key_exchange(&bob);
        let ex2 = bob.key_exchange(&alice);

        assert_eq!(ex1, ex2);
    }
}
