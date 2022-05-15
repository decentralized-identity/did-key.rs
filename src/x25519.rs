use crate::{
    didcore::*,
    ed25519::Ed25519KeyPair,
    traits::{CoreSign, DIDCore, Fingerprint, Generate, KeyMaterial},
    AsymmetricKey, Error, KeyPair,
};

use super::{generate_seed, ECDH};
use std::convert::TryInto;
use x25519_dalek::{PublicKey, StaticSecret};

pub type X25519KeyPair = AsymmetricKey<PublicKey, StaticSecret>;

impl Generate for X25519KeyPair {
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

    fn from_secret_key(secret_key: &[u8]) -> Self {
        let sized_data: [u8; 32] = clone_into_array(&secret_key[..32]);

        let sk = StaticSecret::from(sized_data);
        let pk: PublicKey = (&sk).try_into().expect("invalid public key");

        X25519KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }
}

impl KeyMaterial for X25519KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_bytes().to_vec()
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_ref().unwrap().to_bytes().to_vec()
    }
}

impl ECDH for X25519KeyPair {
    fn key_exchange(&self, key: &Self) -> Vec<u8> {
        match &(self.secret_key) {
            Some(x) => x.diffie_hellman(&key.public_key).as_bytes().to_vec(),
            None => panic!("secret key not present"),
        }
    }
}

impl CoreSign for X25519KeyPair {
    fn sign(&self, _: &[u8]) -> Vec<u8> {
        unimplemented!("signing is not supported for this key type")
    }

    fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), Error> {
        unimplemented!("verifiying is not supported for this key type")
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
                false => KeyFormat::Base58(bs58::encode(self.public_key_bytes()).into_string()),
                true => KeyFormat::JWK(JWK {
                    key_type: "OKP".into(),
                    curve: "X25519".into(),
                    x: Some(base64::encode_config(self.public_key_bytes(), base64::URL_SAFE_NO_PAD)),
                    ..Default::default()
                }),
            }),
            private_key: match config.serialize_secrets {
                true => self.secret_key.as_ref().map(|_| match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.private_key_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "OKP".into(),
                        curve: "X25519".into(),
                        x: Some(base64::encode_config(self.public_key_bytes(), base64::URL_SAFE_NO_PAD)),
                        d: Some(base64::encode_config(self.private_key_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                false => None,
            },
            ..Default::default()
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

impl From<X25519KeyPair> for KeyPair {
    fn from(key_pair: X25519KeyPair) -> Self {
        KeyPair::X25519(key_pair)
    }
}

fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
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

    #[test]
    fn test_did_doc() {
        let key = X25519KeyPair::new_with_seed(vec![].as_slice());

        let json = key.get_did_document(CONFIG_LD_PRIVATE);
        assert!(json.verification_method[0].private_key.is_some());

        println!("{}", serde_json::to_string_pretty(&json).unwrap());

        let json = key.get_did_document(CONFIG_LD_PUBLIC);
        assert!(json.verification_method[0].private_key.is_none());
    }
}
