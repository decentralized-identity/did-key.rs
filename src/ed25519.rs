use super::{generate_seed, CoreSign};
use crate::{
    didcore::{Config, Document, KeyFormat, VerificationMethod, JWK},
    traits::{DIDCore, Fingerprint, Generate, ECDH},
    x25519::X25519KeyPair,
    AsymmetricKey, Error, KeyMaterial, KeyPair,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::*;
use std::convert::{TryFrom, TryInto};

pub type Ed25519KeyPair = AsymmetricKey<PublicKey, SecretKey>;

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self.public_key))
    }
}

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

    pub fn get_x25519(&self) -> X25519KeyPair {
        match &self.secret_key {
            Some(sk) => {
                let hash = Sha512::digest(&sk.as_ref()[..32]);
                let mut output = [0u8; 32];
                output.copy_from_slice(&hash[..32]);
                output[0] &= 248;
                output[31] &= 127;
                output[31] |= 64;

                X25519KeyPair::new_with_seed(&output)
            }
            None => {
                let var_name: [u8; 32] = self.public_key.as_bytes().to_vec().as_slice().try_into().unwrap();
                let compressed = CompressedEdwardsY(var_name).decompress().unwrap();
                let montgomery = compressed.to_montgomery();

                X25519KeyPair::from_public_key(montgomery.as_bytes())
            }
        }
    }
}

impl Fingerprint for Ed25519KeyPair {
    fn fingerprint(&self) -> String {
        let codec: &[u8] = &[0xed, 0x1];
        let data = [codec, self.public_key.as_bytes()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl DIDCore for Ed25519KeyPair {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod> {
        vec![
            VerificationMethod {
                id: format!("{}#{}", controller, self.fingerprint()),
                key_type: match config.use_jose_format {
                    false => "Ed25519VerificationKey2018".into(),
                    true => "JsonWebKey2020".into(),
                },
                controller: controller.to_string(),
                public_key: Some(match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.public_key_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "OKP".into(),
                        curve: "Ed25519".into(),
                        x: Some(base64::encode_config(self.public_key_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                private_key: match config.serialize_secrets {
                    true => self.secret_key.as_ref().map(|_| match config.use_jose_format {
                        false => KeyFormat::Base58(bs58::encode(self.private_key_bytes()).into_string()),
                        true => KeyFormat::JWK(JWK {
                            key_type: "OKP".into(),
                            curve: "Ed25519".into(),
                            x: Some(base64::encode_config(self.public_key_bytes(), base64::URL_SAFE_NO_PAD)),
                            d: Some(base64::encode_config(self.private_key_bytes(), base64::URL_SAFE_NO_PAD)),
                            ..Default::default()
                        }),
                    }),
                    false => None,
                },
            },
            self.get_x25519().get_verification_methods(config, controller).first().unwrap().to_owned(),
        ]
    }

    fn get_did_document(&self, config: Config) -> Document {
        let fingerprint = self.fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let ed_vm = &self.get_verification_methods(config, &controller)[0];
        let x_vm = &self.get_x25519().get_verification_methods(config, &controller)[0];

        Document {
            context: "https://www.w3.org/ns/did/v1".to_string(),
            id: controller.to_string(),
            key_agreement: Some(vec![x_vm.id.clone()]),
            authentication: Some(vec![ed_vm.id.clone()]),
            assertion_method: Some(vec![ed_vm.id.clone()]),
            capability_delegation: Some(vec![ed_vm.id.clone()]),
            capability_invocation: Some(vec![ed_vm.id.clone()]),
            verification_method: vec![ed_vm.clone(), x_vm.clone()],
        }
    }
}

impl Generate for Ed25519KeyPair {
    fn new() -> Ed25519KeyPair {
        Self::new_with_seed(vec![].as_slice())
    }

    fn new_with_seed(seed: &[u8]) -> Ed25519KeyPair {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk: SecretKey = SecretKey::from_bytes(&secret_seed).expect("cannot generate secret key");
        let pk: PublicKey = (&sk).try_into().expect("cannot generate public key");

        Ed25519KeyPair {
            secret_key: Some(sk),
            public_key: pk,
        }
    }

    fn from_public_key(public_key: &[u8]) -> Ed25519KeyPair {
        Ed25519KeyPair {
            public_key: PublicKey::from_bytes(public_key).expect("invalid byte data"),
            secret_key: None,
        }
    }

    fn from_secret_key(secret_key: &[u8]) -> Ed25519KeyPair {
        let sk: SecretKey = SecretKey::from_bytes(&secret_key).expect("cannot generate secret key");
        let pk: PublicKey = (&sk).try_into().expect("cannot generate public key");

        Ed25519KeyPair {
            secret_key: Some(sk),
            public_key: pk,
        }
    }
}
impl KeyMaterial for Ed25519KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_ref().map_or(vec![], |x| x.to_bytes().to_vec())
    }
}

impl CoreSign for Ed25519KeyPair {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let esk: ExpandedSecretKey = match &self.secret_key {
            Some(x) => x,
            None => panic!("secret key not found"),
        }
        .into();

        esk.sign(payload, &self.public_key).to_bytes().to_vec()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = Signature::try_from(signature)?;
        match self.public_key.verify(payload, &sig) {
            Ok(_) => Ok(()),
            _ => Err(Error::Unknown("verify failed".into())),
        }
    }
}

impl ECDH for Ed25519KeyPair {
    fn key_exchange(&self, _: &Self) -> Vec<u8> {
        unimplemented!("ECDH is not supported for this key type")
    }
}

impl From<Ed25519KeyPair> for KeyPair {
    fn from(key_pair: Ed25519KeyPair) -> Self {
        KeyPair::Ed25519(key_pair)
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(_: ed25519_dalek::ed25519::Error) -> Self {
        Self::SignatureError
    }
}

#[cfg(test)]
pub mod test {
    use crate::didcore::{CONFIG_LD_PRIVATE, CONFIG_LD_PUBLIC};

    use super::*;
    #[test]
    fn test_demo() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message";

        let signature = sk.sign(message);

        let pk = Ed25519KeyPair::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valud = pk.verify(message, signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }

    #[test]
    fn test_demo_did_key() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = Ed25519KeyPair::new_with_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message";

        let signature = sk.sign(message);

        let pk = Ed25519KeyPair::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valud = pk.verify(message, &signature).unwrap();

        matches!(is_valud, ());
    }

    #[test]
    fn test_did_doc() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let key = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());

        let json = key.get_did_document(CONFIG_LD_PRIVATE);
        assert!(json.verification_method[0].private_key.is_some());

        println!("{}", serde_json::to_string_pretty(&json).unwrap());

        let json = key.get_did_document(CONFIG_LD_PUBLIC);
        assert!(json.verification_method[0].private_key.is_none());
    }
}
