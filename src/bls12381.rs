use std::convert::TryFrom;

use crate::{generate_seed, AsymmetricKey, Ecdsa, Payload};
use bbs::prelude::*;
use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};

pub type Bls12381KeyPair = AsymmetricKey<Vec<u8>, SecretKey>;

impl Ecdsa for Bls12381KeyPair {
    type Err = String;

    fn sign(&self, payload: Payload) -> Vec<u8> {
        let messages: Vec<SignatureMessage> = match payload {
            Payload::Buffer(_) => unimplemented!("payload type not supported"),
            Payload::BufferArray(m) => m.iter().map(|x| SignatureMessage::hash(x)).collect(),
        };
        let dpk = DeterministicPublicKey::try_from(self.public_key.clone()).unwrap();
        let pk = dpk.to_public_key(messages.len()).unwrap();
        match &self.secret_key {
            Some(sk) => Signature::new(&messages, sk, &pk),
            None => panic!("secret key not found"),
        }
        .unwrap()
        .to_bytes_compressed_form()
        .to_vec()
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Self::Err> {
        let messages: Vec<SignatureMessage> = match payload {
            Payload::Buffer(_) => unimplemented!("payload type not supported"),
            Payload::BufferArray(m) => m.iter().map(|x| SignatureMessage::hash(x)).collect(),
        };
        let dpk = DeterministicPublicKey::try_from(self.public_key.clone()).unwrap();
        let pk = dpk.to_public_key(messages.len()).unwrap();
        let sig = match Signature::try_from(signature) {
            Ok(sig) => sig,
            Err(err) => return Err(format!("unable to parse signature: {}", err)),
        };

        match sig.verify(&messages, &pk) {
            Ok(x) => {
                if x {
                    Ok(())
                } else {
                    Err("invalid signature".to_string())
                }
            }
            Err(err) => Err(format!("unexpected error: {}", err)),
        }
    }
}

pub fn generate_g1_key(seed: Option<Vec<u8>>) -> Bls12381KeyPair {
    generate_keypair::<G1>(seed)
}

pub fn generate_g2_key(seed: Option<Vec<u8>>) -> Bls12381KeyPair {
    generate_keypair::<G2>(seed)
}

fn generate_keypair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    seed: Option<Vec<u8>>,
) -> Bls12381KeyPair {
    let seed_data = generate_seed(seed.map_or(vec![], |x| x).as_slice()).unwrap();

    let sk = gen_sk(seed_data.to_vec().as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let mut pk_bytes = Vec::new();
    pk.serialize(&mut pk_bytes, true).unwrap();

    Bls12381KeyPair {
        public_key: pk_bytes.to_vec(),
        secret_key: Some(SecretKey::from(sk)),
    }
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
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
    fn test_generate_g2_key() {
        let keypair = generate_g2_key(None);

        assert!(matches!(keypair.secret_key, Some(_)));
    }

    #[test]
    fn test_generate_g1_key() {
        let keypair = generate_g1_key(None);

        assert!(matches!(keypair.secret_key, Some(_)));
    }

    #[test]
    fn test_g2_signature() {
        let keypair = generate_g2_key(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload]));

        assert_eq!(signature.len(), SIGNATURE_COMPRESSED_SIZE);
    }

    #[test]
    fn test_g2_signature_and_verify() {
        let keypair = generate_g2_key(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload.clone()]));

        let verify_result = keypair.verify(Payload::BufferArray(vec![payload.clone()]), signature.as_slice());

        assert!(matches!(verify_result, Ok(_)));
    }

    #[test]
    fn test_g2_signature_and_verify_fails_invalid_signature() {
        let keypair = generate_g2_key(None);
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
    fn test_g2_signature_and_verify_fails_signature_parse() {
        let keypair = generate_g2_key(None);
        let payload = b"secret message".to_vec();

        let signature = keypair.sign(Payload::BufferArray(vec![payload.clone()]));

        let verify_result = keypair.verify(Payload::BufferArray(vec![payload.clone()]), signature[1..].as_ref());

        assert!(matches!(verify_result, Err(_)));
    }
}
