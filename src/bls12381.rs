use std::convert::TryFrom;

use crate::{
    didcore::{Config, KeyFormat, JWK},
    generate_seed, AsymmetricKey, Document, KeyMaterial, Payload, VerificationMethod,
};
use crate::{
    traits::{DIDCore, Ecdh, Ecdsa, Fingerprint},
    Error,
};
use bbs::prelude::*;

use pairing_plus::{
    bls12_381::{Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};

pub type Bls12381KeyPair = AsymmetricKey<CyclicGroup, SecretKey>;

#[derive(Debug, Clone)]
pub struct CyclicGroup {
    pub g1: Vec<u8>,
    pub g2: DeterministicPublicKey,
}

impl Bls12381KeyPair {
    fn get_fingerprint_g1(&self) -> String {
        let codec: &[u8] = &[0xea, 0x1];
        let data = [codec, self.public_key.g1.as_slice()].concat().to_vec();
        format!("z{}", bs58::encode(data).into_string())
    }

    fn get_fingerprint_g2(&self) -> String {
        let codec: &[u8] = &[0xeb, 0x1];
        let data = [codec, self.public_key.g2.to_bytes_compressed_form().as_ref()]
            .concat()
            .to_vec();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl Ecdsa for Bls12381KeyPair {
    fn sign(&self, payload: Payload) -> Vec<u8> {
        let messages: Vec<SignatureMessage> = match payload {
            Payload::Buffer(_) => unimplemented!("payload type not supported"),
            Payload::BufferArray(m) => m.iter().map(|x| SignatureMessage::hash(x)).collect(),
        };
        let dpk = DeterministicPublicKey::try_from(self.public_key.g2).unwrap();
        let pk = dpk.to_public_key(messages.len()).unwrap();
        match &self.secret_key {
            Some(sk) => Signature::new(&messages, sk, &pk),
            None => panic!("secret key not found"),
        }
        .unwrap()
        .to_bytes_compressed_form()
        .to_vec()
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Error> {
        let messages: Vec<SignatureMessage> = match payload {
            Payload::Buffer(_) => unimplemented!("payload type not supported"),
            Payload::BufferArray(m) => m.iter().map(|x| SignatureMessage::hash(x)).collect(),
        };

        let pk = self.public_key.g2.to_public_key(messages.len()).unwrap();
        let sig = match Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return Err(Error::Unknown("unable to parse signature")),
        };

        match sig.verify(&messages, &pk) {
            Ok(x) => {
                if x {
                    Ok(())
                } else {
                    Err(Error::Unknown("invalid signature"))
                }
            }
            Err(_) => Err(Error::Unknown("unexpected error")),
        }
    }
}

impl KeyMaterial for Bls12381KeyPair {
    fn new() -> Bls12381KeyPair {
        generate_keypair(None)
    }

    fn new_with_seed(seed: &[u8]) -> Bls12381KeyPair {
        generate_keypair(Some(seed.into()))
    }

    fn from_public_key(public_key: &[u8]) -> Bls12381KeyPair {
        Bls12381KeyPair {
            secret_key: None,
            public_key: CyclicGroup {
                g1: public_key[..48].to_vec(),
                g2: DeterministicPublicKey::try_from(public_key[48..].to_vec()).unwrap(),
            },
        }
    }

    fn from_secret_key(_: &[u8]) -> Bls12381KeyPair {
        todo!()
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        [
            self.public_key.g1.as_slice(),
            self.public_key.g2.to_bytes_compressed_form().as_ref(),
        ]
        .concat()
        .to_vec()
    }

    fn private_key_bytes(&self) -> &[u8] {
        todo!()
    }
}

impl DIDCore for Bls12381KeyPair {
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
                    false => KeyFormat::Base58(bs58::encode(self.public_key.g1.as_slice()).into_string()),
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "BLS12381_G1".into(),
                        x: Some(base64::encode_config(
                            self.public_key.g1.as_slice(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                        y: None,
                        d: None,
                    }),
                }),
                private_key: None,
            },
            VerificationMethod {
                id: format!("{}#{}", controller, self.get_fingerprint_g2()),
                key_type: match config.use_jose_format {
                    false => "Bls12381G2Key2020".into(),
                    true => "JsonWebKey2020".into(),
                },
                controller: controller.to_string(),
                public_key: Some(match config.use_jose_format {
                    false => {
                        KeyFormat::Base58(bs58::encode(self.public_key.g2.to_bytes_compressed_form()).into_string())
                    }
                    true => KeyFormat::JWK(JWK {
                        key_type: "EC".into(),
                        curve: "BLS12381_G2".into(),
                        x: Some(base64::encode_config(
                            self.public_key.g2.to_bytes_compressed_form(),
                            base64::URL_SAFE_NO_PAD,
                        )),
                        y: None,
                        d: None,
                    }),
                }),
                private_key: None,
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

impl Fingerprint for Bls12381KeyPair {
    fn fingerprint(&self) -> String {
        let codec: &[u8] = &[0xee, 0x1];
        let data = [
            codec,
            self.public_key.g1.as_slice(),
            self.public_key.g2.to_bytes_compressed_form().as_ref(),
        ]
        .concat()
        .to_vec();
        format!("z{}", bs58::encode(data).into_string())
    }
}

impl Ecdh for Bls12381KeyPair {
    fn key_exchange(&self, _: &Self) -> Vec<u8> {
        unimplemented!("ECDH is not supported for this key type")
    }
}

fn generate_keypair(seed: Option<Vec<u8>>) -> Bls12381KeyPair {
    let seed_data = generate_seed(seed.map_or(vec![], |x| x).as_slice()).unwrap();

    let sk = gen_sk(seed_data.to_vec().as_slice());
    let mut pk1 = G1::one();
    pk1.mul_assign(sk);

    let mut pk1_bytes = Vec::new();
    pk1.serialize(&mut pk1_bytes, true).unwrap();

    let mut pk2 = G2::one();
    pk2.mul_assign(sk);

    let mut pk2_bytes = Vec::new();
    pk2.serialize(&mut pk2_bytes, true).unwrap();

    Bls12381KeyPair {
        public_key: CyclicGroup {
            g1: pk1_bytes.to_vec(),
            g2: DeterministicPublicKey::try_from(pk2_bytes).unwrap(),
        },
        secret_key: Some(SecretKey::from(sk)),
    }
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    Fr::from_okm(&result)
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn test_signature() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload]));

        assert_eq!(signature.len(), SIGNATURE_COMPRESSED_SIZE);
    }

    #[test]
    fn test_signature_and_verify() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload.clone()]));

        let verify_result = keypair.verify(Payload::BufferArray(vec![payload.clone()]), signature.as_slice());

        assert!(matches!(verify_result, Ok(_)));
    }

    #[test]
    fn test_signature_and_verify_fails_invalid_signature() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();
        let invalid_payload = b"incorrect secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload.clone()]));

        let verify_result = keypair.verify(
            Payload::BufferArray(vec![invalid_payload.clone()]),
            signature.as_slice(),
        );

        assert!(matches!(verify_result, Err(_)));
    }

    #[test]
    fn test_signature_and_verify_fails_signature_parse() {
        let keypair = generate_keypair(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload.clone()]));

        let verify_result = keypair.verify(Payload::BufferArray(vec![payload.clone()]), signature[1..].as_ref());

        assert!(matches!(verify_result, Err(_)));
    }

    #[test]
    fn test_generate_public_key() {
        let key = Bls12381KeyPair::new_with_seed(vec![].as_slice());
        let pk = key.public_key_bytes();

        assert_eq!(G1_COMPRESSED_SIZE + G2_COMPRESSED_SIZE, pk.len());
    }

    #[test]
    fn test_generate_public_key_from_bytes() {
        let key = Bls12381KeyPair::new_with_seed(vec![].as_slice());
        let pk = key.public_key_bytes();

        let actual = Bls12381KeyPair::from_public_key(&pk);
        let pk1 = actual.public_key_bytes();

        assert_eq!(pk, pk1);
    }
}
