use super::{generate_seed, Ecdsa};
use crate::{
    didcore::{DIDCore, Document, VerificationMethod},
    x25519::X25519KeyPair,
    AsymmetricKey, DIDKey, DIDKeyTypeInternal, KeyMaterial, Payload,
};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::*;
use std::convert::{TryFrom, TryInto};

pub type Ed25519KeyPair = AsymmetricKey<PublicKey, SecretKey>;

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

                X25519KeyPair::from_seed(&output)
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

impl DIDCore for Ed25519KeyPair {
    fn get_fingerprint(&self) -> String {
        let codec: &[u8] = &[0xed, 0x1];
        let data = [codec, self.public_key.as_bytes()].concat();
        format!("z{}", bs58::encode(data).into_string())
    }

    fn to_verification_method(&self, controller: &str) -> Vec<VerificationMethod> {
        vec![VerificationMethod {
            id: format!("{}#{}", controller, self.get_fingerprint()),
            key_type: DIDKeyTypeInternal::Ed25519,
            controller: controller.to_string(),
            public_key: Some(self.public_key.as_bytes().to_vec()),
            private_key: self.secret_key.as_ref().map(|x| x.as_bytes().to_vec()),
        }]
    }

    fn get_did_document(&self) -> Document {
        let fingerprint = self.get_fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());

        let ed_vm = &self.to_verification_method(&controller)[0];
        let x_vm = &self.get_x25519().to_verification_method(&controller)[0];

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

impl KeyMaterial for Ed25519KeyPair {
    fn new() -> crate::DIDKey {
        Self::new_from_seed(vec![].as_slice())
    }

    fn new_from_seed(seed: &[u8]) -> crate::DIDKey {
        let secret_seed = generate_seed(&seed.to_vec()).expect("invalid seed");

        let sk: SecretKey = SecretKey::from_bytes(&secret_seed).expect("cannot generate secret key");
        let pk: PublicKey = (&sk).try_into().expect("cannot generate public key");

        DIDKey::Ed25519(Ed25519KeyPair {
            secret_key: Some(sk),
            public_key: pk,
        })
    }

    fn from_public_key(public_key: &[u8]) -> crate::DIDKey {
        DIDKey::Ed25519(Ed25519KeyPair {
            public_key: PublicKey::from_bytes(public_key).expect("invalid byte data"),
            secret_key: None,
        })
    }

    fn from_secret_key(secret_key: &[u8]) -> crate::DIDKey {
        let sk: SecretKey = SecretKey::from_bytes(&secret_key).expect("cannot generate secret key");
        let pk: PublicKey = (&sk).try_into().expect("cannot generate public key");

        DIDKey::Ed25519(Ed25519KeyPair {
            secret_key: Some(sk),
            public_key: pk,
        })
    }
}

impl Ecdsa for Ed25519KeyPair {
    type Err = String;

    fn sign(&self, payload: Payload) -> Vec<u8> {
        let esk: ExpandedSecretKey = match &self.secret_key {
            Some(x) => x,
            None => panic!("secret key not found"),
        }
        .into();

        match payload {
            Payload::Buffer(payload) => esk.sign(payload.as_slice(), &self.public_key).to_bytes().to_vec(),
            Payload::BufferArray(_) => unimplemented!("payload type not supported for this key"),
        }
    }

    fn verify(&self, payload: Payload, signature: &[u8]) -> Result<(), Self::Err> {
        let sig = Signature::try_from(signature).expect("invalid signature data");
        match payload {
            Payload::Buffer(payload) => match self.public_key.verify(payload.as_slice(), &sig) {
                Ok(_) => Ok(()),
                _ => Err(String::from("verify failed")),
            },
            _ => unimplemented!("payload type not supported for this key"),
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::{DIDKey, DIDKeyType, Payload};

    use super::*;
    #[test]
    fn test_demo() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message".to_vec();

        let signature = sk.sign(Payload::Buffer(message.clone()));

        let pk = Ed25519KeyPair::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valud = pk.verify(Payload::Buffer(message), signature.as_slice());

        assert!(is_valud.map_or(false, |_| true));
    }

    #[test]
    fn test_demo_did_key() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = DIDKey::new_from_seed(
            DIDKeyType::Ed25519,
            bs58::decode(secret_key).into_vec().unwrap().as_slice(),
        );
        let message = b"super secret message";

        let signature = sk.sign(Payload::Buffer(message.to_vec()));

        let pk = DIDKey::from_public_key(
            DIDKeyType::Ed25519,
            bs58::decode(public_key).into_vec().unwrap().as_slice(),
        );
        let is_valud = pk.verify(Payload::Buffer(message.to_vec()), &signature);

        assert!(is_valud);
    }

    #[test]
    fn test_did_doc() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let key = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());

        let _ = key.get_did_document();

        assert!(true)
    }
}
