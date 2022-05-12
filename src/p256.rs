use super::{generate_seed, CoreSign};
use crate::{
    didcore::{Config, KeyFormat, JWK},
    traits::{DIDCore, Fingerprint, Generate, KeyMaterial, ECDH},
    AsymmetricKey, Document, Error, KeyPair, VerificationMethod,
};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};
use std::convert::TryFrom;

pub type P256KeyPair = AsymmetricKey<VerifyingKey, SigningKey>;

impl std::fmt::Debug for P256KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.public_key))
    }
}

impl Generate for P256KeyPair {
    fn new_with_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk = SigningKey::from_bytes(&secret_seed).expect("Couldn't create key");
        let pk = VerifyingKey::from(&sk);

        P256KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }

    fn from_public_key(public_key: &[u8]) -> Self {
        P256KeyPair {
            secret_key: None,
            public_key: VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(public_key).expect("invalid key")).expect("invalid point"),
        }
    }

    fn new() -> Self {
        Self::new_with_seed(vec![].as_slice())
    }

    fn from_secret_key(secret_key_bytes: &[u8]) -> Self {
        let sk = SigningKey::from_bytes(&secret_key_bytes).expect("couldn't initialize secret key");
        let pk = VerifyingKey::from(&sk);

        P256KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }
}

impl KeyMaterial for P256KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_encoded_point(true).as_bytes().to_vec()
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_ref().map_or(vec![], |x| x.to_bytes().as_slice().to_vec())
    }
}

impl CoreSign for P256KeyPair {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let signature = match &self.secret_key {
            Some(sig) => sig.sign(&payload),
            None => panic!("secret key not found"),
        };
        signature.as_ref().to_vec()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.public_key
            .verify(&payload, &Signature::try_from(signature).unwrap())
            .map_err(|_e| Error::SignatureError)
    }
}

impl DIDCore for P256KeyPair {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod> {
        vec![VerificationMethod {
            id: format!("{}#{}", controller, self.fingerprint()),
            key_type: match config.use_jose_format {
                false => "UnsupportedVerificationMethod2020".into(),
                true => "JsonWebKey2020".into(),
            },
            controller: controller.to_string(),
            public_key: Some(match config.use_jose_format {
                false => KeyFormat::Base58(bs58::encode(self.public_key_bytes()).into_string()),
                true => KeyFormat::JWK(JWK {
                    key_type: "EC".into(),
                    curve: "P-256".into(),
                    x: Some(base64::encode_config(self.public_key_bytes(), base64::URL_SAFE_NO_PAD)),
                    ..Default::default()
                }),
            }),
            private_key: match config.serialize_secrets {
                true => self.secret_key.as_ref().map(|_| match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.private_key_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "P-256".into(),
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

impl Fingerprint for P256KeyPair {
    fn fingerprint(&self) -> String {
        let codec: &[u8] = &[0x80, 0x24];
        let data = [codec, self.public_key.to_encoded_point(true).as_ref()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl ECDH for P256KeyPair {
    fn key_exchange(&self, _: &Self) -> Vec<u8> {
        unimplemented!("ECDH not supported for this key type")
    }
}

impl From<P256KeyPair> for KeyPair {
    fn from(key_pair: P256KeyPair) -> Self {
        KeyPair::P256(key_pair)
    }
}

#[cfg(test)]
pub mod test {
    use base64::URL_SAFE;

    use crate::resolve;

    use super::*;
    #[test]
    fn test_demo() {
        let key = P256KeyPair::new_with_seed(vec![].as_slice());
        let message = b"super secret message";

        let signature = key.sign(message);

        let is_valud = key.verify(message, signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }

    #[test]
    fn did_document() {
        let key = P256KeyPair::new();

        let did_doc = key.get_did_document(Config {
            use_jose_format: false,
            serialize_secrets: true,
        });
        assert!(did_doc.verification_method[0].private_key.is_some());

        println!("{}", serde_json::to_string_pretty(&did_doc).unwrap());

        let did_doc = key.get_did_document(Config {
            use_jose_format: false,
            serialize_secrets: false,
        });
        assert!(did_doc.verification_method[0].private_key.is_none());
    }

    #[test]
    fn resolve_key() {
        let did_uri = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";

        let resolved = resolve(did_uri).unwrap();

        matches!(resolved.key_pair, KeyPair::P256(_));
    }

    #[test]
    fn from_secret_key() {
        let sk = base64::decode_config("gPh-VvVS8MbvKQ9LSVVmfnxnKjHn4Tqj0bmbpehRlpc", URL_SAFE).unwrap();

        let keypair = P256KeyPair::from_secret_key(&sk);
        let did_doc = keypair.get_did_document(Config::default());

        assert_eq!(keypair.fingerprint(), "zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv");
        assert_eq!(did_doc.id, "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv");
    }
}
