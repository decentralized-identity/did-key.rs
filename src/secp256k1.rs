use crate::{didcore::*, AsymmetricKey, Payload, DIDKeyTypeInternal};

use super::{generate_seed, Ecdsa, Ecdh};
use secp256k1::{PublicKey, SecretKey, SharedSecret, Message, Signature};
use sha2::{Sha256, Digest};

pub type Secp256k1KeyPair = AsymmetricKey<PublicKey, SecretKey>;

impl Secp256k1KeyPair {
    pub fn from_seed(seed: &[u8]) -> Self {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");
        let sk = SecretKey::parse(&secret_seed).expect("Couldn't create key");
        let pk = PublicKey::from_secret_key(&sk);

        Secp256k1KeyPair {
            public_key: pk,
            secret_key: Some(sk),
        }
    }

    pub fn from_public_key(pk: &[u8]) -> Self {
        let pk = PublicKey::parse_slice(pk, None).expect("Could not parse public key");

        Secp256k1KeyPair {
            secret_key: None,
            public_key: pk,
        }
    }
}

impl Ecdsa for Secp256k1KeyPair {
    type Err = String;

    fn sign(&self, payload: Payload) -> Vec<u8> {
        match payload {
            Payload::Buffer(payload) => {
                let signature = match &self.secret_key {
                    Some(sig) => {
                        let message = Message::parse(&get_hash(&payload));
                        secp256k1::sign(&message, &sig).0
                    },
                    None => panic!("secret key not found"),
                };
                let signature = signature.serialize();
                signature.as_ref().to_vec()
            }
            _ => unimplemented!("payload type not supported for this key"),
        }
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Self::Err> {
        let verified;
        match payload {
            Payload::Buffer(payload) => {
                let message = Message::parse(&get_hash(&payload));
                let signature = Signature::parse_slice(&signature).expect("Couldn't parse signature");

                verified = secp256k1::verify(&message, &signature, &self.public_key);
            }
            _ => unimplemented!("payload type not supported for this key"),
        }

        if verified { return Ok(()); }
        else { return Err(String::from("verify failed")); }
    }
}

impl Ecdh for Secp256k1KeyPair {
    fn key_exchange(&self, key: &Self) -> Vec<u8> {
        match &(self.secret_key) {
            Some(x) => SharedSecret::<Sha256>::new(&key.public_key, &x).expect("Couldn't create shared key").as_ref().to_vec(),
            None => panic!("secret key not present"),
        }
    }
}

impl DIDCore for Secp256k1KeyPair {
    fn to_verification_method(&self, controller: &str) -> Vec<VerificationMethod> {
        vec![VerificationMethod {
            id: format!("{}#{}", controller, self.get_fingerprint()),
            key_type: DIDKeyTypeInternal::Secp256k1,
            controller: controller.to_string(),
            public_key: Some(self.public_key.serialize().to_vec()),
            private_key: None,
        }]
    }

    fn get_did_document(&self) -> crate::Document {
        let fingerprint = self.get_fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let vm = self.to_verification_method(&controller);

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

    fn get_fingerprint(&self) -> String {
        let codec: &[u8] = &[0xe7, 0x1];
        let data = [codec, self.public_key.serialize().as_ref()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }
}

fn get_hash(payload: &Vec<u8>) -> [u8; 32] {
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
        let key_pair = Secp256k1KeyPair::from_seed(vec![].as_slice());
        assert_eq!(key_pair.public_key.serialize().len(), 65);
    }

    #[test]
    fn sign_and_verify() {
        let message = b"super secret message".to_vec();
        let payload = Payload::Buffer(message.clone());
        let key_pair = Secp256k1KeyPair::from_seed(vec![].as_slice());

        let signature = key_pair.sign(payload);
        let payload = Payload::Buffer(message.clone());

        let verified = match key_pair.verify(payload, &signature) {
            Ok(_) => true,
            Err(_) => false,
        };

        assert!(verified);
    }

    #[test]
    fn key_exchange() {
        let key_pair1 = Secp256k1KeyPair::from_seed(vec![].as_slice());
        let key_pair2 = Secp256k1KeyPair::from_seed(vec![].as_slice());

        assert_eq!(key_pair1.key_exchange(&key_pair2), key_pair2.key_exchange(&key_pair1));
    }
}
