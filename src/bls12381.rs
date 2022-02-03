use bls12_381_plus::Scalar;
use hkdf::HkdfExtract;
use signature_bls::{PublicKey, PublicKeyVt, SecretKey, Signature};

use crate::{
    didcore::{Config, KeyFormat, JWK},
    generate_seed,
    traits::{CoreSign, DIDCore, Fingerprint, Generate, ECDH},
    Document, Error, KeyMaterial, BaseKeyPair, VerificationMethod,
};

pub struct Bls12381KeyPairs {
    pk_g1: PublicKeyVt,
    pk_g2: PublicKey,
    secret_key: Option<SecretKey>,
}

impl Bls12381KeyPairs {
    fn get_fingerprint_g1(&self) -> String {
        let codec: &[u8] = &[0xea, 0x1];
        let data = [codec, &self.pk_g1.to_bytes()[..]].concat().to_vec();
        format!("z{}", bs58::encode(data).into_string())
    }

    fn get_fingerprint_g2(&self) -> String {
        let codec: &[u8] = &[0xeb, 0x1];
        let data = [codec, &self.pk_g2.to_bytes()[..]].concat().to_vec();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl CoreSign for Bls12381KeyPairs {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        Signature::new(&self.secret_key.as_ref().unwrap(), payload)
            .expect("secret key not present")
            .to_bytes()
            .to_vec()
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != Signature::BYTES {
            return Err(Error::SignatureError);
        }

        let mut sig = [0u8; Signature::BYTES];
        sig.copy_from_slice(signature);

        match Signature::from_bytes(&sig).unwrap().verify(self.pk_g2, payload).unwrap_u8() {
            1 => Ok(()),
            _ => Err(Error::SignatureError),
        }
    }
}

impl Generate for Bls12381KeyPairs {
    fn new() -> Bls12381KeyPairs {
        generate_keypair(None)
    }

    fn new_with_seed(seed: &[u8]) -> Bls12381KeyPairs {
        generate_keypair(Some(seed.into()))
    }

    fn from_public_key(_public_key: &[u8]) -> Bls12381KeyPairs {
        let mut pk_g1 = [0u8; PublicKeyVt::BYTES];
        pk_g1.copy_from_slice(&_public_key[..PublicKeyVt::BYTES]);

        let mut pk_g2 = [0u8; PublicKey::BYTES];
        pk_g2.copy_from_slice(&_public_key[PublicKeyVt::BYTES..]);

        Bls12381KeyPairs {
            pk_g1: PublicKeyVt::from_bytes(&pk_g1).unwrap(),
            pk_g2: PublicKey::from_bytes(&pk_g2).unwrap(),
            secret_key: None,
        }
    }

    fn from_secret_key(secret_key_bytes: &[u8]) -> Bls12381KeyPairs {
        let mut bytes: [u8; 32] = [0; 32];
        bytes.copy_from_slice(secret_key_bytes);

        let sk = SecretKey::from_bytes(&bytes).unwrap();
        let pk_g1 = PublicKeyVt::from(&sk);
        let pk_g2 = PublicKey::from(&sk);

        Bls12381KeyPairs {
            pk_g1: pk_g1,
            pk_g2: pk_g2,
            secret_key: Some(sk),
        }
    }
}
impl KeyMaterial for Bls12381KeyPairs {
    fn public_key_bytes(&self) -> Vec<u8> {
        [self.pk_g1.to_bytes().to_vec(), self.pk_g2.to_bytes().to_vec()].concat().to_vec()
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_ref().unwrap().to_bytes().to_vec()
    }
}

impl DIDCore for Bls12381KeyPairs {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod> {
        vec![
            VerificationMethod {
                id: format!("{}#{}", controller, self.get_fingerprint_g1()),
                key_type: match config.use_jose_format {
                    false => "Bls12381G1Key2020".into(),
                    true => "JsonWebKey2020".into(),
                },
                controller: controller.to_string(),
                public_key: Some(match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.pk_g1.to_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "BLS12381_G1".into(),
                        x: Some(base64::encode_config(self.pk_g1.to_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                private_key: self.secret_key.as_ref().map(|_| match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.pk_g1.to_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "BLS12381_G1".into(),
                        x: Some(base64::encode_config(self.pk_g1.to_bytes(), base64::URL_SAFE_NO_PAD)),
                        d: Some(base64::encode_config(self.private_key_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            },
            VerificationMethod {
                id: format!("{}#{}", controller, self.get_fingerprint_g2()),
                key_type: match config.use_jose_format {
                    false => "Bls12381G2Key2020".into(),
                    true => "JsonWebKey2020".into(),
                },
                controller: controller.to_string(),
                public_key: Some(match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.pk_g2.to_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "BLS12381_G2".into(),
                        x: Some(base64::encode_config(self.pk_g2.to_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                private_key: self.secret_key.as_ref().map(|_| match config.use_jose_format {
                    false => KeyFormat::Base58(bs58::encode(self.private_key_bytes()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "BLS12381_G2".into(),
                        x: Some(base64::encode_config(self.pk_g2.to_bytes(), base64::URL_SAFE_NO_PAD)),
                        d: Some(base64::encode_config(self.private_key_bytes(), base64::URL_SAFE_NO_PAD)),
                        ..Default::default()
                    }),
                }),
                ..Default::default()
            },
        ]
    }

    fn get_did_document(&self, config: Config) -> crate::Document {
        let fingerprint = self.fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let vm = &self.get_verification_methods(config, &controller);
        let vm_ids: Vec<String> = vm.iter().map(|x| x.id.to_string()).collect();

        Document {
            context: "https://www.w3.org/ns/did/v1".to_string(),
            id: controller.to_string(),
            key_agreement: None,
            authentication: Some(vm_ids.clone()),
            assertion_method: Some(vm_ids.clone()),
            capability_delegation: Some(vm_ids.clone()),
            capability_invocation: Some(vm_ids.clone()),
            verification_method: vm.clone(),
        }
    }
}

impl Fingerprint for Bls12381KeyPairs {
    fn fingerprint(&self) -> String {
        let codec: &[u8] = &[0xee, 0x1];
        let data = [codec, &self.pk_g1.to_bytes()[..], &self.pk_g2.to_bytes()[..]].concat().to_vec();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl ECDH for Bls12381KeyPairs {
    fn key_exchange(&self, _: &Self) -> Vec<u8> {
        unimplemented!("ECDH is not supported for this key type")
    }
}

impl From<Bls12381KeyPairs> for BaseKeyPair {
    fn from(key_pair: Bls12381KeyPairs) -> Self {
        BaseKeyPair::Bls12381G1G2(key_pair)
    }
}

fn generate_keypair(seed: Option<Vec<u8>>) -> Bls12381KeyPairs {
    let seed_data = generate_seed(seed.map_or(vec![], |x| x).as_slice()).unwrap();
    let sk = gen_sk(seed_data.to_vec().as_slice()).unwrap();

    let pk_g1 = PublicKeyVt::from(&sk);
    let pk_g2 = PublicKey::from(&sk);

    Bls12381KeyPairs {
        pk_g1: pk_g1,
        pk_g2: pk_g2,
        secret_key: Some(sk),
    }
}

fn gen_sk(ikm: &[u8]) -> Option<SecretKey> {
    const SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";
    const INFO: [u8; 2] = [0u8, 48u8];

    let mut extracter = HkdfExtract::<sha2::Sha256>::new(Some(SALT));
    extracter.input_ikm(ikm);
    extracter.input_ikm(&[0u8]);
    let (_, h) = extracter.finalize();

    let mut output = [0u8; 48];
    if let Err(_) = h.expand(&INFO, &mut output) {
        None
    } else {
        let mut bytes = Scalar::from_okm(&output).to_bytes();
        bytes.reverse();
        Some(SecretKey::from_bytes(&bytes).unwrap())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::CONFIG_LD_PRIVATE;

    #[test]
    fn test_signature() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(&payload);

        assert_eq!(signature.len(), Signature::BYTES);
    }

    #[test]
    fn test_public_key() {
        let keypair = generate_keypair(None);

        let from = Bls12381KeyPairs::from_public_key(&keypair.public_key_bytes());

        assert!(from.pk_g1.eq(&keypair.pk_g1));
        assert!(from.pk_g2.eq(&keypair.pk_g2));
    }

    #[test]
    fn test_signature_and_verify() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(&payload.clone());

        let verify_result = keypair.verify(&payload.clone(), signature.as_slice());

        assert!(matches!(verify_result, Ok(_)));
    }

    #[test]
    fn test_signature_and_verify_fails_invalid_signature() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();
        let invalid_payload = b"incorrect secret message".to_vec();

        let signature = keypair.sign(&payload.clone());

        let verify_result = keypair.verify(&invalid_payload.clone(), signature.as_slice());

        assert!(matches!(verify_result, Err(_)));
    }

    #[test]
    fn test_signature_and_verify_fails_signature_parse() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(&payload.clone());

        let verify_result = keypair.verify(&payload.clone(), signature[1..].as_ref());

        assert!(matches!(verify_result, Err(_)));
    }

    #[test]
    fn test_generate_public_key() {
        let key = Bls12381KeyPairs::new_with_seed(vec![].as_slice());
        let pk = key.public_key_bytes();

        assert_eq!(PublicKeyVt::BYTES + PublicKey::BYTES, pk.len());
    }

    #[test]
    fn test_generate_public_key_from_bytes() {
        let key = Bls12381KeyPairs::new_with_seed(vec![].as_slice());
        let pk = key.public_key_bytes();

        let actual = Bls12381KeyPairs::from_public_key(&pk);
        let pk1 = actual.public_key_bytes();

        assert_eq!(pk, pk1);
    }

    #[test]
    fn test_resolve() {
        let key = Bls12381KeyPairs::new();
        let doc = key.get_did_document(CONFIG_LD_PRIVATE);
        let g2 = doc.authentication.unwrap()[1].clone();

        let resolved = crate::resolve(g2.as_str());

        let doc2 = resolved.unwrap().get_did_document(CONFIG_LD_PRIVATE);

        assert_eq!(doc.id, doc2.id)
    }

    #[test]
    fn secret_key_size() {
        let key = Bls12381KeyPairs::new();
        let sk_bytes = key.private_key_bytes();

        assert_eq!(sk_bytes.len(), 32);
        let key = Bls12381KeyPairs::from_secret_key(&sk_bytes);
        assert_eq!(key.private_key_bytes().len(), 32)
    }
}
