use crate::{
    didcore::*,
    traits::{DIDCore, Fingerprint, Generate, KeyMaterial},
    AsymmetricKey, Error, KeyPair,
};

use super::{generate_seed, CoreSign, ECDH};
use libsecp256k1::{Message, PublicKey, SecretKey, SharedSecret, Signature};
use sha2::{Digest, Sha256};

pub type Secp256k1KeyPair = AsymmetricKey<PublicKey, SecretKey>;

impl Generate for Secp256k1KeyPair {
    fn new_with_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");
        let sk = SecretKey::parse(&secret_seed).expect("Couldn't create key");
        let pk = PublicKey::from_secret_key(&sk);

        Secp256k1KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }

    fn from_public_key(pk: &[u8]) -> Self {
        let pk = PublicKey::parse_slice(pk, None).expect("Could not parse public key");

        Secp256k1KeyPair {
            secret_key: None,
            public_key: pk,
        }
    }

    fn new() -> Self {
        Self::new_with_seed(vec![].as_slice())
    }

    fn from_secret_key(secret_key: &[u8]) -> Self {
        let sk = SecretKey::parse_slice(secret_key).unwrap();
        let pk = PublicKey::from_secret_key(&sk);

        Secp256k1KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }
}

impl KeyMaterial for Secp256k1KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_ref().map_or(vec![], |x| x.serialize().to_vec())
    }
}

impl CoreSign for Secp256k1KeyPair {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signature = match &self.secret_key {
            Some(sig) => {
                let message = Message::parse(&get_hash(payload));
                libsecp256k1::sign(&message, &sig).0
            }
            None => panic!("secret key not found"),
        };
        let signature = signature.serialize();
        signature.as_ref().to_vec()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        let message = Message::parse(&get_hash(&payload));
        let signature = Signature::parse_standard_slice(&signature)?;

        match libsecp256k1::verify(&message, &signature, &self.public_key) {
            true => Ok(()),
            false => Err(Error::SignatureError),
        }
    }
}

impl ECDH for Secp256k1KeyPair {
    fn key_exchange(&self, key: &Self) -> Vec<u8> {
        match &(self.secret_key) {
            Some(x) => SharedSecret::<Sha256>::new(&key.public_key, &x)
                .expect("Couldn't create shared key")
                .as_ref()
                .to_vec(),
            None => panic!("secret key not present"),
        }
    }
}

impl DIDCore for Secp256k1KeyPair {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod> {
        let pk: [u8; 65] = self.public_key.serialize();

        vec![VerificationMethod {
            id: format!("{}#{}", controller, self.fingerprint()),
            key_type: match config.use_jose_format {
                false => "EcdsaSecp256k1VerificationKey2019".into(),
                true => "JsonWebKey2020".into(),
            },
            controller: controller.to_string(),
            public_key: Some(match config.use_jose_format {
                false => KeyFormat::Base58(bs58::encode(self.public_key.serialize()).into_string()),
                true => KeyFormat::JWK(JWK {
                    key_type: "EC".into(),
                    curve: "secp256k1".into(),
                    x: Some(base64::encode_config(&pk[1..33], base64::URL_SAFE_NO_PAD)),
                    y: Some(base64::encode_config(&pk[33..65], base64::URL_SAFE_NO_PAD)),
                    ..Default::default()
                }),
            }),
            private_key: match config.serialize_secrets {
                true => self.secret_key.as_ref().map(|_| match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.private_key_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "secp256k1".into(),
                        x: Some(base64::encode_config(&pk[1..33], base64::URL_SAFE_NO_PAD)),
                        y: Some(base64::encode_config(&pk[33..65], base64::URL_SAFE_NO_PAD)),
                        d: Some(base64::encode_config(self.private_key_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                false => None,
            },
            ..Default::default()
        }]
    }

    fn get_did_document(&self, config: Config) -> crate::Document {
        let fingerprint = self.fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let vm = self.get_verification_methods(config, &controller);

        Document {
            context: "https://www.w3.org/ns/did/v1".to_string(),
            id: controller.to_string(),
            key_agreement: Some(vm.iter().map(|x| x.id.to_string()).collect()),
            authentication: Some(vec![vm[0].id.clone()]),
            assertion_method: Some(vec![vm[0].id.clone()]),
            capability_delegation: Some(vec![vm[0].id.clone()]),
            capability_invocation: Some(vec![vm[0].id.clone()]),
            verification_method: vm,
        }
    }
}
impl Fingerprint for Secp256k1KeyPair {
    fn fingerprint(&self) -> String {
        let codec: &[u8] = &[0xe7, 0x1];
        let data = [codec, self.public_key.serialize_compressed().as_ref()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl From<Secp256k1KeyPair> for KeyPair {
    fn from(key_pair: Secp256k1KeyPair) -> Self {
        KeyPair::Secp256k1(key_pair)
    }
}

impl From<libsecp256k1::Error> for Error {
    fn from(err: libsecp256k1::Error) -> Self {
        match err {
            libsecp256k1::Error::InvalidSignature => Self::SignatureError,
            libsecp256k1::Error::InvalidPublicKey => Self::InvalidKey,
            libsecp256k1::Error::InvalidSecretKey => Self::InvalidKey,
            _ => Self::Unknown(format!("{}", err)),
        }
    }
}

fn get_hash(payload: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(&payload);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash[..32]);
    output
}

#[cfg(test)]
pub mod test {
    use super::*;

    //Are these tests sufficient? Or do I need more?
    #[test]
    fn generate_key() {
        let key_pair = Secp256k1KeyPair::new_with_seed(vec![].as_slice());
        assert_eq!(key_pair.public_key.serialize_compressed().len(), 33);
    }

    #[test]
    fn sign_and_verify() {
        let message = b"super secret message";
        let key_pair = Secp256k1KeyPair::new_with_seed(vec![].as_slice());

        let signature = key_pair.sign(message);

        let verified = match key_pair.verify(message, &signature) {
            Ok(_) => true,
            Err(_) => false,
        };

        assert!(verified);
    }

    #[test]
    fn key_exchange() {
        let key_pair1 = Secp256k1KeyPair::new_with_seed(vec![].as_slice());
        let key_pair2 = Secp256k1KeyPair::new_with_seed(vec![].as_slice());

        assert_eq!(key_pair1.key_exchange(&key_pair2), key_pair2.key_exchange(&key_pair1));
    }

    #[test]
    fn did_document() {
        let key = Secp256k1KeyPair::new();

        let did_doc = key.get_did_document(Config {
            use_jose_format: true,
            serialize_secrets: true,
        });
        assert!(did_doc.verification_method[0].private_key.is_some());

        println!("{}", serde_json::to_string_pretty(&did_doc).unwrap());

        let did_doc = key.get_did_document(Config {
            use_jose_format: true,
            serialize_secrets: false,
        });

        assert!(did_doc.verification_method[0].private_key.is_none());
    }
}
