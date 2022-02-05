use base64::URL_SAFE;
use did_url::DID;
use json_patch::{patch, from_value, PatchOperation};
use serde_json::json;

use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    str::FromStr,
    todo,
};

pub enum BaseKeyPair {
    Ed25519(Ed25519KeyPair),
    X25519(X25519KeyPair),
    P256(P256KeyPair),
    Bls12381G1G2(Bls12381KeyPairs),
    Secp256k1(Secp256k1KeyPair),
}

pub type DIDKey = BaseKeyPair;

pub struct AsymmetricKey<P, S> {
    public_key: P,
    secret_key: Option<S>,
}

#[derive(Debug)]
pub enum Error {
    SignatureError,
    ResolutionFailed,
    InvalidKey,
    EncodeError,
    DecodeError,
    Unknown(String),
}

pub struct KeyPair {
    base_key_pair: BaseKeyPair,
    patch: Option<IetfJsonPatch>
}

impl KeyPair {
    fn new(base_key_pair: BaseKeyPair) -> KeyPair {
        KeyPair {
            base_key_pair: base_key_pair,
            patch: None
        }
    }
}

/// Generate new `did:key` of the specified type
pub fn generate<T: Generate + CoreSign + ECDH + DIDCore + Fingerprint + Into<BaseKeyPair>>(seed: Option<&[u8]>) -> KeyPair {
    KeyPair::new(T::new_with_seed(seed.map_or(vec![].as_slice(), |x| x)).into())
}

/// Resolve a `did:key` from a URI
pub fn resolve(did_uri: &str) -> Result<KeyPair, Error> {
    KeyPair::try_from(did_uri)
}

/// Generate key pair from existing key material
pub fn from_existing_key<T: Generate + CoreSign + ECDH + DIDCore + Fingerprint + Into<BaseKeyPair>>(
    public_key: &[u8],
    private_key: Option<&[u8]>,
) -> KeyPair {
    if private_key.is_some() {
        KeyPair::new(T::from_secret_key(private_key.unwrap()).into())
    } else {
        KeyPair::new(T::from_public_key(public_key).into())
    }
}

pub(crate) fn generate_seed(initial_seed: &[u8]) -> Result<[u8; 32], &str> {
    let mut seed = [0u8; 32];
    if initial_seed.is_empty() || initial_seed.len() != 32 {
        getrandom::getrandom(&mut seed).expect("couldn't generate random seed");
    } else {
        seed = match initial_seed.try_into() {
            Ok(x) => x,
            Err(_) => return Err("invalid seed size"),
        };
    }
    Ok(seed)
}

// Decode from a base-64 JWS string into a JWS helper struct
pub fn decode_jws(jws_b64: &str) -> Result<JWS, Error> {
    let mut itr = jws_b64.splitn(3, ".").map(|slice| {
        base64::decode_config(slice, base64::URL_SAFE_NO_PAD).unwrap()
    });

    let (header, payload, signature) = match (itr.next(), itr.next(), itr.next()) {
        (Some(h), Some(p), Some(s)) => (h, p, s),
        _ => return Err(Error::DecodeError)
    };

    Ok(
        JWS {
            header: serde_json::from_slice(&header).unwrap(),
            payload: payload.to_vec(),
            signature: signature.to_vec(),
        }
    )
}

// Translate a JWS helper struct into the IetfJsonPatch serializable struct
pub fn get_json_patch(jws: &JWS) -> Result<IetfJsonPatch, Error> {
    match serde_json::from_slice::<IetfJsonPatch>(&jws.payload) {
        Ok(docs) => Ok(docs),
        Err(_) => Err(Error::DecodeError)
    }
}

// Per the spec (https://bit.ly/34xScAu), verify JWS patch change is from the controller
pub fn verify_json_patch_jws(jws: &JWS, key: &KeyPair) -> bool {
    let kid = &jws.header.key_id;
    let did = key.get_did_document(Config::default());

    if let Some(authentication) = did.authentication {
        if let Some(_key_id) = authentication.iter().find(|&s| *s == kid.clone().unwrap()) {
            match key.verify(&jws.payload, &jws.signature) {
                Ok(()) => { return true; },
                Err(_) => { return false; },
            }
        }
    }
    return false;
}

// use json_patch helpers to update a DID JSON document
pub fn patch_json_document(doc: &Document, json_patch: &IetfJsonPatch) -> Result<Document, Error> {
    let mut new_doc = serde_json::to_value(doc).map_err(|_| Error::EncodeError)?;
    match patch(&mut new_doc, &from_value(json_patch.value.clone()).unwrap()) {
        Ok(()) => {
            serde_json::from_value(new_doc)
                .map_err(|_| Error::DecodeError)?
        }
        Err(e) => Err(Error::Unknown(format!("Couldn't apply patch: {:?}", e))),
    }
}

// Generate a JWS to be used in a JSON patch request
pub fn generate_json_patch_jws(key: &KeyPair, operations: &Vec<PatchOperation>) -> String {
    let controller = format!("did:key:{}", key.fingerprint().clone());
    let vm = key.get_verification_methods(CONFIG_JOSE_PUBLIC, &controller).first().unwrap().to_owned();

    let patch_payload = serde_json::to_vec(&json!({ "ietf-json-patch": operations })).unwrap_or(vec![]);
    let signature = key.sign(&patch_payload);
    let jws = JWS {
        header: JWSHeader { algorithm: vm.key_type.clone(), key_id: Some(vm.id.clone()) },
        payload: patch_payload,
        signature: signature
    };
    format!(
        "{}.{}.{}",
        base64::encode_config(&serde_json::to_string(&jws.header)
            .unwrap().as_bytes(), base64::URL_SAFE_NO_PAD),
        base64::encode_config(&jws.payload, base64::URL_SAFE_NO_PAD),
        base64::encode_config(&jws.signature, base64::URL_SAFE_NO_PAD)
    )
}

// Generate a DID URI with a JSON patch
pub fn generate_json_patch_did_uri(key: &KeyPair, operations: &Vec<PatchOperation>) -> String {
    let base_uri = format!("did:key:{}", key.fingerprint().clone());
    format!("{}?signedIetfJsonPatch={}", base_uri, generate_json_patch_jws(key, operations))
}

impl CoreSign for KeyPair {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        match &self.base_key_pair {
            BaseKeyPair::Ed25519(x) => x.sign(payload),
            BaseKeyPair::X25519(x) => x.sign(payload),
            BaseKeyPair::P256(x) => x.sign(payload),
            BaseKeyPair::Bls12381G1G2(x) => x.sign(payload),
            BaseKeyPair::Secp256k1(x) => x.sign(payload),
        }
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.base_key_pair {
            BaseKeyPair::Ed25519(x) => x.verify(payload, signature),
            BaseKeyPair::X25519(x) => x.verify(payload, signature),
            BaseKeyPair::P256(x) => x.verify(payload, signature),
            BaseKeyPair::Bls12381G1G2(x) => x.verify(payload, signature),
            BaseKeyPair::Secp256k1(x) => x.verify(payload, signature),
        }
    }
}

impl ECDH for KeyPair {
    fn key_exchange(&self, their_public: &Self) -> Vec<u8> {
        match (&self.base_key_pair, &their_public.base_key_pair) {
            (BaseKeyPair::X25519(me), BaseKeyPair::X25519(them)) => me.key_exchange(them),
            (BaseKeyPair::P256(me), BaseKeyPair::P256(them)) => me.key_exchange(them),
            _ => unimplemented!("ECDH not supported for this key combination"),
        }
    }
}

impl DIDCore for KeyPair {
    fn get_verification_methods(&self, config: didcore::Config, controller: &str) -> Vec<VerificationMethod> {
        match &self.base_key_pair{
            BaseKeyPair::Ed25519(x) => x.get_verification_methods(config, controller),
            BaseKeyPair::X25519(x) => x.get_verification_methods(config, controller),
            BaseKeyPair::P256(x) => x.get_verification_methods(config, controller),
            BaseKeyPair::Bls12381G1G2(x) => x.get_verification_methods(config, controller),
            BaseKeyPair::Secp256k1(x) => x.get_verification_methods(config, controller),
        }
    }

    fn get_did_document(&self, config: didcore::Config) -> Document {
        let doc = match &self.base_key_pair {
            BaseKeyPair::Ed25519(x) => x.get_did_document(config),
            BaseKeyPair::X25519(x) => x.get_did_document(config),
            BaseKeyPair::P256(x) => x.get_did_document(config),
            BaseKeyPair::Bls12381G1G2(x) => x.get_did_document(config),
            BaseKeyPair::Secp256k1(x) => x.get_did_document(config),
        };
        match &self.patch {
            Some(patch) => patch_json_document(&doc, patch).unwrap_or(doc),
            None => doc
        }
    }
}

impl KeyMaterial for KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        match &self.base_key_pair {
            BaseKeyPair::Ed25519(x) => x.public_key_bytes(),
            BaseKeyPair::X25519(x) => x.public_key_bytes(),
            BaseKeyPair::P256(x) => x.public_key_bytes(),
            BaseKeyPair::Bls12381G1G2(x) => x.public_key_bytes(),
            BaseKeyPair::Secp256k1(x) => x.public_key_bytes(),
        }
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        match &self.base_key_pair {
            BaseKeyPair::Ed25519(x) => x.private_key_bytes(),
            BaseKeyPair::X25519(x) => x.private_key_bytes(),
            BaseKeyPair::P256(x) => x.private_key_bytes(),
            BaseKeyPair::Bls12381G1G2(x) => x.private_key_bytes(),
            BaseKeyPair::Secp256k1(x) => x.private_key_bytes(),
        }
    }
}

impl Fingerprint for KeyPair {
    fn fingerprint(&self) -> String {
        match &self.base_key_pair {
            BaseKeyPair::Ed25519(x) => x.fingerprint(),
            BaseKeyPair::X25519(x) => x.fingerprint(),
            BaseKeyPair::P256(x) => x.fingerprint(),
            BaseKeyPair::Bls12381G1G2(x) => x.fingerprint(),
            BaseKeyPair::Secp256k1(x) => x.fingerprint(),
        }
    }
}

impl TryFrom<&str> for KeyPair {
    type Error = Error;

    fn try_from(did_uri: &str) -> Result<Self, Self::Error> {
        // let re = Regex::new(r"did:key:[\w]*#[\w]*\??[\w]*").unwrap();

        let url = match DID::from_str(did_uri) {
            Ok(url) => url,
            Err(_) => return Err(Error::Unknown("couldn't parse DID URI".into()))
        };

        let pub_key = match url.method_id().strip_prefix("z") {
            Some(url) => match bs58::decode(url).into_vec() {
                Ok(url) => url,
                Err(_) => return Err(Error::Unknown("invalid base58 encoded data in DID URI".into())),
            },
            None => return Err(Error::Unknown("invalid URI data".into())),
        };

        let base_key_pair = match pub_key[0..2] {
            [0xed, 0x1] => Ok(BaseKeyPair::Ed25519(Ed25519KeyPair::from_public_key(&pub_key[2..]))),
            [0xec, 0x1] => Ok(BaseKeyPair::X25519(X25519KeyPair::from_public_key(&pub_key[2..]))),
            [0xee, 0x1] => Ok(BaseKeyPair::Bls12381G1G2(Bls12381KeyPairs::from_public_key(&pub_key[2..]))),
            [0x80, 0x24] => Ok(BaseKeyPair::P256(P256KeyPair::from_public_key(&pub_key[2..]))),
            [0xe7, 0x1] => Ok(BaseKeyPair::Secp256k1(Secp256k1KeyPair::from_public_key(&pub_key[2..]))),
            _ => Err(Error::ResolutionFailed),
        };

        // If presented with a *valid* signed JSON patch, apply it.
        match base_key_pair {
            Ok(key) => {
                let mut key_pair = KeyPair { base_key_pair: key, patch: None};
                let query_pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
                let signed_ietf_json_patch = query_pairs.get("signedIetfJsonPatch");
                match signed_ietf_json_patch {
                    None => Ok(key_pair),
                    Some(patch) => {
                        let decoded = decode_jws(&patch)?;
                        if let Some(parsed_patch) = get_json_patch(&decoded).ok() {
                            if verify_json_patch_jws(&decoded, &key_pair) {
                                key_pair.patch = Some(parsed_patch);
                            }
                        }
                        Ok(key_pair)
                    }
                }
            },
            Err(err) => return Err(err)
        }
    }
}

impl From<&VerificationMethod> for KeyPair {
    fn from(vm: &VerificationMethod) -> Self {
        if vm.private_key.is_some() {
            vm.private_key.as_ref().unwrap().into()
        } else {
            vm.public_key.as_ref().unwrap().into()
        }
    }
}

impl From<&KeyFormat> for KeyPair {
    fn from(key_format: &KeyFormat) -> Self {
        match key_format {
            KeyFormat::Base58(_) => todo!(),
            KeyFormat::Multibase(_) => todo!(),
            KeyFormat::JWK(jwk) => match jwk.curve.as_str() {
                "Ed25519" => {
                    if jwk.d.is_some() {
                        KeyPair::new(
                            Ed25519KeyPair::from_secret_key(
                                base64::decode_config(jwk.d.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()
                            ).into()
                        )
                    } else {
                        KeyPair::new(
                            Ed25519KeyPair::from_public_key(
                                base64::decode_config(jwk.x.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()
                            ).into()
                        )
                    }
                }
                "X25519" => {
                    if jwk.d.is_some() {
                        KeyPair::new(
                            X25519KeyPair::from_secret_key(
                                base64::decode_config(jwk.d.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()
                            ).into()
                        )
                    } else {
                        KeyPair::new(
                            X25519KeyPair::from_public_key(
                                base64::decode_config(jwk.x.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()
                            ).into()
                        ) 
                    }
                }
                _ => unimplemented!("method not supported"),
            },
        }
    }
}

mod bls12381;
mod didcore;
mod ed25519;
mod p256;
mod secp256k1;
mod traits;
mod x25519;
pub use {
    crate::p256::P256KeyPair,
    crate::secp256k1::Secp256k1KeyPair,
    bls12381::Bls12381KeyPairs,
    didcore::{Config, Document, IetfJsonPatch, KeyFormat, VerificationMethod, CONFIG_JOSE_PRIVATE, CONFIG_JOSE_PUBLIC, CONFIG_LD_PRIVATE, CONFIG_LD_PUBLIC, JWK, JWS, JWSHeader},
    ed25519::Ed25519KeyPair,
    traits::{CoreSign, DIDCore, Fingerprint, Generate, KeyMaterial, ECDH},
    x25519::X25519KeyPair,
};

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{didcore::Config, BaseKeyPair};
    use fluid::prelude::*;
    use json_patch::{AddOperation};
    use serde_json::json;

    #[test]
    fn test_demo() {
        let secret_key = "6Lx39RyWn3syuozAe2WiPdAYn1ctMx17t8yrBMGFBmZy";
        let public_key = "6fioC1zcDPyPEL19pXRS2E4iJ46zH7xP6uSgAaPdwDrx";

        let sk = Ed25519KeyPair::from_seed(bs58::decode(secret_key).into_vec().unwrap().as_slice());
        let message = b"super secret message";

        let signature = sk.sign(message);

        let pk = Ed25519KeyPair::from_public_key(bs58::decode(public_key).into_vec().unwrap().as_slice());
        let is_valid = pk.verify(message, &signature).unwrap();

        matches!(is_valid, ());
    }

    #[test]
    fn test_did_doc_ld() {
        let key = generate::<Ed25519KeyPair>(None);
        let did_doc = key.get_did_document(Config::default());

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_did_doc_json() {
        let key = generate::<X25519KeyPair>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_did_doc_json_bls() {
        let key = generate::<Bls12381KeyPairs>(None);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);

        let json = serde_json::to_string_pretty(&did_doc).unwrap();

        println!("{}", json);

        assert!(true)
    }

    #[test]
    fn test_key_from_uri() {
        let uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri).unwrap();

        assert!(matches!(key.base_key_pair, BaseKeyPair::Ed25519(_)));
        assert_eq!("z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL", key.fingerprint());
    }

    #[test]
    fn test_key_from_uri_fragment() {
        let uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri);

        assert!(matches!(key.unwrap().base_key_pair, BaseKeyPair::Ed25519(_)));
    }

    #[test]
    fn test_key_from_uri_fragment_x25519() {
        let uri = "did:key:z6Mkt6QT8FPajKXDrtMefkjxRQENd9wFzKkDFomdQAVFzpzm#z6LSfDq6DuofPeZUqNEmdZsxpvfHvSoUXGEWFhw7JHk4cynN";

        let key = resolve(uri).unwrap();

        assert!(matches!(key.base_key_pair, BaseKeyPair::Ed25519(_)));
        assert_eq!("z6Mkt6QT8FPajKXDrtMefkjxRQENd9wFzKkDFomdQAVFzpzm", key.fingerprint())
    }

    #[test]
    fn test_generate_new_key() {
        let key = generate::<P256KeyPair>(None);
        let message = b"secret message";

        println!("{}", key.fingerprint());

        let signature = key.sign(message);
        let valid = key.verify(message, &signature);

        matches!(valid, Ok(()));
    }

    #[test]
    fn test_key_resolve() {
        let key = resolve("did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL").unwrap();

        assert!(matches!(key.base_key_pair, BaseKeyPair::Ed25519(_)));
    }

    #[theory]
    #[case("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")]
    #[case("did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2")]
    #[case("did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N")]
    fn test_resolve_secp256k1(did_uri: &str) {
        let key = resolve(did_uri).unwrap();

        assert!(matches!(key.base_key_pair, BaseKeyPair::Secp256k1(_)));
    }

    #[test]
    fn serialize_to_verification_method_and_back() {
        let expected = generate::<Ed25519KeyPair>(None);
        let vm = expected.get_verification_methods(super::CONFIG_JOSE_PRIVATE, "");

        let actual: KeyPair = vm.first().unwrap().into();

        assert!(matches!(actual.base_key_pair, BaseKeyPair::Ed25519(_)));
        assert_eq!(actual.fingerprint(), expected.fingerprint());

        assert_eq!(expected.get_did_document(Config::default()), actual.get_did_document(Config::default()));
    }

    #[test]
    fn test_demo_decode_jws() {
        let key = generate::<Ed25519KeyPair>(None);
        let controller = format!("did:key:{}", key.fingerprint().clone());
        let vm = &key.get_verification_methods(CONFIG_JOSE_PUBLIC, &controller).first().unwrap().to_owned();
        let jwk = serde_json::to_string(&vm.public_key.clone().unwrap()).unwrap();

        let patch_value = json!({
            "id": &key.fingerprint(),
            "type": &key.get_verification_methods(CONFIG_JOSE_PRIVATE, &controller).first().unwrap()
                .key_type,
            "controller": &controller,
            "jwk": &jwk
        });
        let patches = vec![
            PatchOperation::Add(AddOperation{ 
                path: "/capabilityDelegation/1".to_string(), 
                value: patch_value.clone()
            }),
        ];
        let patched_uri = generate_json_patch_did_uri(&key, &patches);
        let query_pairs: HashMap<_, _> = DID::from_str(&patched_uri).unwrap()
            .query_pairs().into_owned().collect();
        let jws = query_pairs.get("signedIetfJsonPatch").unwrap();
        let decoded = decode_jws(&jws).unwrap();
        println!("{:?}", &patched_uri);
        println!("{:?}", &decoded);

        let expected_payload = serde_json::to_vec(
            &json!({
                "ietf-json-patch": [
                    {
                        "op": "add",
                        "path": "/capabilityDelegation/1",
                        "value": patch_value.clone()
                    }
                ]
            })
        ).unwrap();
        let expected_signature = key.sign(&expected_payload);
        let expected_jws = JWS {
            header: JWSHeader { algorithm: vm.key_type.clone(), key_id: Some(vm.id.clone()) },
            payload: expected_payload,
            signature: expected_signature,
        };

        assert_eq!(decoded, expected_jws)
    }

    #[test]
    fn test_demo_json_patch() {
        let key = generate::<Ed25519KeyPair>(None);
        let initial_did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let json = serde_json::to_string_pretty(&initial_did_doc).unwrap();
        println!("{}", json);

        let controller = format!("did:key:{}", key.fingerprint().clone());
        let vm = &key.get_verification_methods(CONFIG_JOSE_PUBLIC, &controller).first().unwrap().to_owned();
        let jwk = serde_json::to_string(&vm.public_key.clone().unwrap()).unwrap();
        let patch_value = json!({
            "id": &key.fingerprint(),
            "type": &key.get_verification_methods(CONFIG_JOSE_PRIVATE, &controller).first().unwrap()
                .key_type,
            "controller": &controller,
            "jwk": &jwk
        });
        let patches = vec![
            PatchOperation::Add(AddOperation{ 
                path: "/capabilityDelegation/1".to_string(), 
                value: patch_value.clone()
            }),
        ];

        let patched_uri = generate_json_patch_did_uri(&key, &patches);
        println!("{}", patched_uri);
        let patched_key = resolve(&patched_uri).unwrap();
        let did_doc = patched_key.get_did_document(CONFIG_JOSE_PUBLIC);
        let json = serde_json::to_string_pretty(&did_doc).unwrap();
        println!("{}", json);
    }
}