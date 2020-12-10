use crate::{didcore::*, ed25519::Ed25519KeyPair, AsymmetricKey, DIDKeyTypeInternal};

use super::{generate_seed, Ecdh};
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

pub type X25519KeyPair = AsymmetricKey<PublicKey, StaticSecret>;

impl X25519KeyPair {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk = StaticSecret::from(secret_seed);
        let pk: PublicKey = (&sk).try_into().expect("invalid public key");

        X25519KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }

    pub fn from_public_key(public_key: &[u8]) -> Self {
        let mut pk: [u8; 32] = [0; 32];
        pk.clone_from_slice(public_key);

        X25519KeyPair {
            public_key: PublicKey::from(pk),
            secret_key: None,
        }
    }
}

impl Ecdh for X25519KeyPair {
    fn key_exchange(&self, key: &Self) -> Vec<u8> {
        match &(self.secret_key) {
            Some(x) => x.diffie_hellman(&key.public_key).as_bytes().to_vec(),
            None => panic!("secret key not present"),
        }
    }
}

impl From<Ed25519KeyPair> for X25519KeyPair {
    fn from(key: Ed25519KeyPair) -> Self {
        key.get_x25519()
    }
}

impl DIDCore for X25519KeyPair {
    fn to_verification_method(&self, controller: &str) -> Vec<VerificationMethod> {
        vec![VerificationMethod {
            id: format!("{}#{}", controller, self.get_fingerprint()),
            key_type: DIDKeyTypeInternal::X25519,
            controller: controller.to_string(),
            public_key: Some(self.public_key.as_bytes().to_vec()),
            private_key: None,
        }]
    }

    fn get_did_document(&self) -> Document {
        let fingerprint = self.get_fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let vm = self.to_verification_method(&controller);

        Document {
            context: "https://www.w3.org/ns/did/v1".to_string(),
            id: controller.to_string(),
            key_agreement: Some(vm.iter().map(|x| x.id.to_string()).collect()),
            authentication: None,
            assertion_method: None,
            capability_delegation: None,
            capability_invocation: None,
            verification_method: vm,
        }
    }

    fn get_fingerprint(&self) -> String {
        let codec: &[u8] = &[0xec, 0x1];
        let data = [codec, self.public_key.as_bytes()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    fn test_demo() {
        let alice = X25519KeyPair::from_seed(vec![].as_slice());
        let bob = X25519KeyPair::from_seed(vec![].as_slice());

        let ex1 = alice.key_exchange(&bob);
        let ex2 = bob.key_exchange(&alice);

        assert_eq!(ex1, ex2);
    }
}
