use crate::{
    didcore::*,
    ed25519::Ed25519KeyPair,
    traits::{DIDCore, Ecdsa, Fingerprint, KeyMaterial},
    AsymmetricKey, Error,
};

use super::{generate_seed, Ecdh};
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

pub type X25519KeyPair = AsymmetricKey<PublicKey, StaticSecret>;

impl KeyMaterial for X25519KeyPair {
    fn new_with_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk = StaticSecret::from(secret_seed);
        let pk: PublicKey = (&sk).try_into().expect("invalid public key");

        X25519KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }

    fn from_public_key(public_key: &[u8]) -> Self {
        let mut pk: [u8; 32] = [0; 32];
        pk.clone_from_slice(public_key);

        X25519KeyPair {
            public_key: PublicKey::from(pk),
            secret_key: None,
        }
    }

    fn new() -> Self {
        Self::new_with_seed(vec![].as_slice())
    }

    fn from_secret_key(_: &[u8]) -> Self {
        todo!()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    fn private_key_bytes(&self) -> &[u8] {
        todo!()
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

impl Ecdsa for X25519KeyPair {
    fn sign(&self, _: crate::Payload) -> Vec<u8> {
        unimplemented!("ECDSA is not supported for this key type")
    }

    fn verify(&self, _: crate::Payload, _: &[u8]) -> Result<(), Error> {
        unimplemented!("ECDSA is not supported for this key type")
    }
}

impl From<Ed25519KeyPair> for X25519KeyPair {
    fn from(key: Ed25519KeyPair) -> Self {
        key.get_x25519()
    }
}

impl DIDCore for X25519KeyPair {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod> {
        vec![VerificationMethod {
            id: format!("{}#{}", controller, self.fingerprint()),
            key_type: match config.use_jose_format {
                false => "X25519KeyAgreementKey2019".into(),
                true => "OKP".into(),
            },
            controller: controller.to_string(),
            public_key: Some(match config.use_jose_format {
                false => KeyFormat::Base58(bs58::encode(self.public_key.as_bytes()).into_string()),
                true => KeyFormat::JWK(JWK {
                    key_type: "OKP".into(),
                    curve: "X25519".into(),
                    x: Some(base64::encode_config(
                        self.public_key.as_bytes(),
                        base64::URL_SAFE_NO_PAD,
                    )),
                    y: None,
                    d: None,
                }),
            }),
            private_key: None,
        }]
    }

    fn get_did_document(&self, config: Config) -> Document {
        let fingerprint = self.fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let vm = self.get_verification_methods(config, &controller);

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
}
impl Fingerprint for X25519KeyPair {
    fn fingerprint(&self) -> String {
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
        let alice = X25519KeyPair::new_with_seed(vec![].as_slice());
        let bob = X25519KeyPair::new_with_seed(vec![].as_slice());

        let ex1 = alice.key_exchange(&bob);
        let ex2 = bob.key_exchange(&alice);

        assert_eq!(ex1, ex2);
    }
}
