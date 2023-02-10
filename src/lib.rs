use base64::URL_SAFE;
use did_url::DID;
use json_patch::{from_value, patch, PatchOperation};
use serde_json::json;

use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    str::FromStr,
    todo,
};

pub enum KeyPair {
    Ed25519(Ed25519KeyPair),
    X25519(X25519KeyPair),
    P256(P256KeyPair),
    Bls12381G1G2(Bls12381KeyPairs),
    Secp256k1(Secp256k1KeyPair),
}

pub type DIDKey = KeyPair;

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

pub struct PatchedKeyPair {
    key_pair: KeyPair,
    patches: Option<Vec<PatchOperation>>,
}

impl PatchedKeyPair {
    fn new(key_pair: KeyPair) -> PatchedKeyPair {
        PatchedKeyPair {
            key_pair: key_pair,
            patches: None,
        }
    }
}

/// Generate new `did:key` of the specified type
pub fn generate<T: Generate + ECDH + DIDCore + Fingerprint + Into<KeyPair>>(seed: Option<&[u8]>) -> PatchedKeyPair {
    PatchedKeyPair::new(T::new_with_seed(seed.map_or(vec![].as_slice(), |x| x)).into())
}

/// Resolve a `did:key` from a URI
pub fn resolve(did_uri: &str) -> Result<PatchedKeyPair, Error> {
    PatchedKeyPair::try_from(did_uri)
}

/// Generate key pair from existing key material
pub fn from_existing_key<T: Generate + ECDH + DIDCore + Fingerprint + Into<KeyPair>>(
    public_key: &[u8],
    private_key: Option<&[u8]>,
) -> PatchedKeyPair {
    if private_key.is_some() {
        PatchedKeyPair::new(T::from_secret_key(private_key.unwrap()).into())
    } else {
        PatchedKeyPair::new(T::from_public_key(public_key).into())
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
    let mut itr = jws_b64.splitn(3, ".").map(|slice| base64::decode_config(slice, base64::URL_SAFE_NO_PAD));

    if let (Some(header), Some(payload), Some(signature)) = (itr.next(), itr.next(), itr.next()) {
        if let (Ok(header), Ok(payload), Ok(signature)) = (header, payload, signature) {
            return match serde_json::from_slice(&header) {
                Ok(header_json) => Ok(JWS {
                    header: header_json,
                    payload: payload.to_vec(),
                    signature: signature.to_vec(),
                }),
                Err(_) => Err(Error::DecodeError),
            };
        }
    }
    Err(Error::DecodeError)
}

// Translate from raw JWS payload (in a helper struct) to serializable patch values
pub fn get_json_patches(jws: &JWS) -> Result<Vec<PatchOperation>, Error> {
    if let Ok(patches) = serde_json::from_slice::<serde_json::Value>(&jws.payload) {
        if let Some(value) = patches.get("ietf-json-patch") {
            return match serde_json::from_value(value.to_owned()) {
                Ok(result) => Ok(result),
                Err(_) => Err(Error::DecodeError),
            };
        }
    }
    Err(Error::DecodeError)
}

// Per the spec (https://bit.ly/34xScAu), verify JWS patch change is from the controller
pub fn verify_json_patch_jws(jws: &JWS, key: &PatchedKeyPair) -> bool {
    let kid = &jws.header.key_id;
    let did = key.get_did_document(Config::default());

    if let (Some(kid), Some(authentication)) = (kid, did.authentication) {
        if let Some(_key_id) = authentication.iter().find(|&s| *s == kid.clone()) {
            match key.verify(&jws.payload, &jws.signature) {
                Ok(()) => {
                    return true;
                }
                Err(_) => {
                    return false;
                }
            }
        }
    }
    return false;
}

// Use json_patch helpers to patch a DID JSON document. Upon error, return original document.
pub fn patch_json_document(doc: &Document, patches: Vec<PatchOperation>) -> Document {
    let original = doc.clone();

    fn apply_patch(doc: &Document, patches: Vec<PatchOperation>) -> Result<Document, Box<dyn std::error::Error>> {
        let parsed_patch = from_value(json!(patches))?;
        let mut json_doc = serde_json::to_value(doc)?;
        patch(&mut json_doc, &parsed_patch)?;
        serde_json::from_value(json_doc).map_err(|e| e.into())
    }

    match apply_patch(doc, patches) {
        Ok(result) => result,
        Err(_) => original,
    }
}

// Generate a JWS to be used in a JSON patch request. Signed by the provided PatchedKeyPair.
pub fn generate_json_patch_jws(key: &PatchedKeyPair, operations: Vec<PatchOperation>) -> Result<String, Error> {
    let controller = format!("did:key:{}", key.fingerprint().clone());
    let vm = key
        .get_verification_methods(Config::default(), &controller)
        .first()
        .ok_or(Error::DecodeError)?
        .clone();

    let patch_payload = serde_json::to_vec(&json!({ "ietf-json-patch": operations })).map_err(|_| Error::EncodeError)?;
    let signature = key.sign(&patch_payload);
    let jws = JWS {
        header: JWSHeader {
            algorithm: vm.key_type,
            key_id: Some(vm.id),
        },
        payload: patch_payload,
        signature: signature,
    };
    Ok(format!(
        "{}.{}.{}",
        base64::encode_config(
            &serde_json::to_string(&jws.header).map_err(|_| Error::EncodeError)?.as_bytes(),
            base64::URL_SAFE_NO_PAD
        ),
        base64::encode_config(&jws.payload, base64::URL_SAFE_NO_PAD),
        base64::encode_config(&jws.signature, base64::URL_SAFE_NO_PAD)
    ))
}

// Generate a DID URI with a JSON patch
pub fn generate_json_patch_did_uri(key: &PatchedKeyPair, operations: Vec<PatchOperation>) -> Result<String, Error> {
    let base_uri = format!("did:key:{}", &key.fingerprint());
    let jws = generate_json_patch_jws(key, operations)?;
    Ok(format!("{}?signedIetfJsonPatch={}", base_uri, jws))
}

impl CoreSign for PatchedKeyPair {
    fn sign(&self, payload: &[u8]) -> Vec<u8> {
        match &self.key_pair {
            KeyPair::Ed25519(x) => x.sign(payload),
            KeyPair::X25519(x) => x.sign(payload),
            KeyPair::P256(x) => x.sign(payload),
            KeyPair::Bls12381G1G2(_) => unimplemented!("signing for Bls12381G1G2 is not implemented"),
            KeyPair::Secp256k1(x) => x.sign(payload),
        }
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        match &self.key_pair {
            KeyPair::Ed25519(x) => x.verify(payload, signature),
            KeyPair::X25519(x) => x.verify(payload, signature),
            KeyPair::P256(x) => x.verify(payload, signature),
            KeyPair::Bls12381G1G2(_) => unimplemented!("verifying for Bls12381G1G2 is not implemented"),
            KeyPair::Secp256k1(x) => x.verify(payload, signature),
        }
    }
}

impl ECDH for PatchedKeyPair {
    fn key_exchange(&self, their_public: &Self) -> Vec<u8> {
        match (&self.key_pair, &their_public.key_pair) {
            (KeyPair::X25519(me), KeyPair::X25519(them)) => me.key_exchange(them),
            (KeyPair::P256(me), KeyPair::P256(them)) => me.key_exchange(them),
            _ => unimplemented!("ECDH not supported for this key combination"),
        }
    }
}

impl DIDCore for PatchedKeyPair {
    fn get_verification_methods(&self, config: didcore::Config, controller: &str) -> Vec<VerificationMethod> {
        match &self.key_pair {
            KeyPair::Ed25519(x) => x.get_verification_methods(config, controller),
            KeyPair::X25519(x) => x.get_verification_methods(config, controller),
            KeyPair::P256(x) => x.get_verification_methods(config, controller),
            KeyPair::Bls12381G1G2(x) => x.get_verification_methods(config, controller),
            KeyPair::Secp256k1(x) => x.get_verification_methods(config, controller),
        }
    }

    fn get_did_document(&self, config: didcore::Config) -> Document {
        let doc = match &self.key_pair {
            KeyPair::Ed25519(x) => x.get_did_document(config),
            KeyPair::X25519(x) => x.get_did_document(config),
            KeyPair::P256(x) => x.get_did_document(config),
            KeyPair::Bls12381G1G2(x) => x.get_did_document(config),
            KeyPair::Secp256k1(x) => x.get_did_document(config),
        };
        match &self.patches {
            Some(patches) => patch_json_document(&doc, patches.to_vec()),
            None => doc,
        }
    }
}

impl KeyMaterial for PatchedKeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        match &self.key_pair {
            KeyPair::Ed25519(x) => x.public_key_bytes(),
            KeyPair::X25519(x) => x.public_key_bytes(),
            KeyPair::P256(x) => x.public_key_bytes(),
            KeyPair::Bls12381G1G2(x) => x.public_key_bytes(),
            KeyPair::Secp256k1(x) => x.public_key_bytes(),
        }
    }

    fn private_key_bytes(&self) -> Vec<u8> {
        match &self.key_pair {
            KeyPair::Ed25519(x) => x.private_key_bytes(),
            KeyPair::X25519(x) => x.private_key_bytes(),
            KeyPair::P256(x) => x.private_key_bytes(),
            KeyPair::Bls12381G1G2(x) => x.private_key_bytes(),
            KeyPair::Secp256k1(x) => x.private_key_bytes(),
        }
    }
}

impl Fingerprint for PatchedKeyPair {
    fn fingerprint(&self) -> String {
        match &self.key_pair {
            KeyPair::Ed25519(x) => x.fingerprint(),
            KeyPair::X25519(x) => x.fingerprint(),
            KeyPair::P256(x) => x.fingerprint(),
            KeyPair::Bls12381G1G2(x) => x.fingerprint(),
            KeyPair::Secp256k1(x) => x.fingerprint(),
        }
    }
}

impl AddDIDJsonPatches for PatchedKeyPair {
    fn add_patches(&mut self, patches: Vec<PatchOperation>) {
        if let Some(existing_patches) = self.patches.as_mut() {
            existing_patches.extend(patches);
        } else {
            self.patches = Some(patches);
        }
    }
}

impl TryFrom<&str> for PatchedKeyPair {
    type Error = Error;

    fn try_from(did_uri: &str) -> Result<Self, Self::Error> {
        // let re = Regex::new(r"did:key:[\w]*#[\w]*\??[\w]*").unwrap();

        let url = match DID::from_str(did_uri) {
            Ok(url) => url,
            Err(_) => return Err(Error::Unknown("couldn't parse DID URI".into())),
        };

        let pub_key = match url.method_id().strip_prefix("z") {
            Some(url) => match bs58::decode(url).into_vec() {
                Ok(url) => url,
                Err(_) => return Err(Error::Unknown("invalid base58 encoded data in DID URI".into())),
            },
            None => return Err(Error::Unknown("invalid URI data".into())),
        };

        let key_pair = match pub_key[0..2] {
            [0xed, 0x1] => Ok(KeyPair::Ed25519(Ed25519KeyPair::from_public_key(&pub_key[2..]))),
            [0xec, 0x1] => Ok(KeyPair::X25519(X25519KeyPair::from_public_key(&pub_key[2..]))),
            [0xee, 0x1] => Ok(KeyPair::Bls12381G1G2(Bls12381KeyPairs::from_public_key(&pub_key[2..]))),
            [0x80, 0x24] => Ok(KeyPair::P256(P256KeyPair::from_public_key(&pub_key[2..]))),
            [0xe7, 0x1] => Ok(KeyPair::Secp256k1(Secp256k1KeyPair::from_public_key(&pub_key[2..]))),
            _ => Err(Error::ResolutionFailed),
        };

        // If presented with valid signed JSON patches, apply them. If presented with invalid patches, return an error.
        match key_pair {
            Ok(key) => {
                let mut patched_key_pair = PatchedKeyPair {
                    key_pair: key,
                    patches: None,
                };
                let query_pairs: HashMap<_, _> = url.query_pairs().into_owned().collect();
                let signed_ietf_json_patch = query_pairs.get("signedIetfJsonPatch");
                match signed_ietf_json_patch {
                    None => Ok(patched_key_pair),
                    Some(patch) => {
                        let decoded_patches = decode_jws(&patch).and_then(|decoded: JWS| {
                            get_json_patches(&decoded).and_then(|parsed_patches: Vec<PatchOperation>| {
                                if verify_json_patch_jws(&decoded, &patched_key_pair) {
                                    patched_key_pair.add_patches(parsed_patches);
                                    Ok(())
                                } else {
                                    Err(Error::DecodeError)
                                }
                            })
                        });
                        match decoded_patches {
                            Ok(()) => Ok(patched_key_pair),
                            Err(e) => Err(e),
                        }
                    }
                }
            }
            Err(err) => Err(err),
        }
    }
}

impl From<&VerificationMethod> for PatchedKeyPair {
    fn from(vm: &VerificationMethod) -> Self {
        if vm.private_key.is_some() {
            vm.private_key.as_ref().unwrap().into()
        } else {
            vm.public_key.as_ref().unwrap().into()
        }
    }
}

impl From<&KeyFormat> for PatchedKeyPair {
    fn from(key_format: &KeyFormat) -> Self {
        match key_format {
            KeyFormat::Base58(_) => todo!(),
            KeyFormat::Multibase(_) => todo!(),
            KeyFormat::JWK(jwk) => match jwk.curve.as_str() {
                "Ed25519" => {
                    if jwk.d.is_some() {
                        PatchedKeyPair::new(
                            Ed25519KeyPair::from_secret_key(base64::decode_config(jwk.d.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()).into(),
                        )
                    } else {
                        PatchedKeyPair::new(
                            Ed25519KeyPair::from_public_key(base64::decode_config(jwk.x.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()).into(),
                        )
                    }
                }
                "X25519" => {
                    if jwk.d.is_some() {
                        PatchedKeyPair::new(
                            X25519KeyPair::from_secret_key(base64::decode_config(jwk.d.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()).into(),
                        )
                    } else {
                        PatchedKeyPair::new(
                            X25519KeyPair::from_public_key(base64::decode_config(jwk.x.as_ref().unwrap(), URL_SAFE).unwrap().as_slice()).into(),
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
    didcore::{
        Config, Document, JWSHeader, KeyFormat, VerificationMethod, CONFIG_JOSE_PRIVATE, CONFIG_JOSE_PUBLIC, CONFIG_LD_PRIVATE, CONFIG_LD_PUBLIC,
        JWK, JWS,
    },
    ed25519::Ed25519KeyPair,
    traits::{AddDIDJsonPatches, CoreSign, DIDCore, Fingerprint, Generate, KeyMaterial, ECDH},
    x25519::X25519KeyPair,
};

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{didcore::Config, KeyPair};
    use fluid::prelude::*;
    use json_patch::{AddOperation, ReplaceOperation};
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

        assert!(matches!(key.key_pair, KeyPair::Ed25519(_)));
        assert_eq!("z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL", key.fingerprint());
    }

    #[test]
    fn test_key_from_uri_fragment() {
        let uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";

        let key = resolve(uri);

        assert!(matches!(key.unwrap().key_pair, KeyPair::Ed25519(_)));
    }

    #[test]
    fn test_key_from_uri_fragment_x25519() {
        let uri = "did:key:z6Mkt6QT8FPajKXDrtMefkjxRQENd9wFzKkDFomdQAVFzpzm#z6LSfDq6DuofPeZUqNEmdZsxpvfHvSoUXGEWFhw7JHk4cynN";

        let key = resolve(uri).unwrap();

        assert!(matches!(key.key_pair, KeyPair::Ed25519(_)));
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

        assert!(matches!(key.key_pair, KeyPair::Ed25519(_)));
    }

    #[theory]
    #[case("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")]
    #[case("did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2")]
    #[case("did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N")]
    fn test_resolve_secp256k1(did_uri: &str) {
        let key = resolve(did_uri).unwrap();

        assert!(matches!(key.key_pair, KeyPair::Secp256k1(_)));
    }

    #[test]
    fn serialize_to_verification_method_and_back() {
        let expected = generate::<Ed25519KeyPair>(None);
        let vm = expected.get_verification_methods(super::CONFIG_JOSE_PRIVATE, "");

        let actual: PatchedKeyPair = vm.first().unwrap().into();

        assert!(matches!(actual.key_pair, KeyPair::Ed25519(_)));
        assert_eq!(actual.fingerprint(), expected.fingerprint());

        assert_eq!(expected.get_did_document(Config::default()), actual.get_did_document(Config::default()));
    }

    #[test]
    fn test_decode_jws() {
        // example pulled from did-spec-extensions: https://bit.ly/3rvNmwI
        let jws = "eyJraWQiOiJkaWQ6ZXhhbXBsZTo0NTYjX1FxMFVMMkZxNjUxUTBGamQ2VHZuWUUtZmFIaU9wUmxQVlFjWV8tdEE0QSIsImFsZyI6IkVkRFNBIn0.eyJpZXRmLWpzb24tcGF0Y2giOlt7Im9wIjoiYWRkIiwicGF0aCI6Ii9wdWJsaWNLZXkvMSIsInZhbHVlIjp7ImlkIjoiIzRTWi1TdFhycDVZZDRfNHJ4SFZUQ1lUSHl0NHp5UGZOMWZJdVlzbTZrM0EiLCJ0eXBlIjoiSnNvbldlYktleTIwMjAiLCJjb250cm9sbGVyIjoiZGlkOmtleTp6Nk1rblNRTlo3Ylp3Uzl4dEVuaHZyNTQ5bTh4UEpGWGpOZXBtU2dlSmo4MzdnbVMiLCJwdWJsaWNLZXlKd2siOnsiY3J2Ijoic2VjcDI1NmsxIiwieCI6Ilo0WTNOTk94djBKNnRDZ3FPQkZuSG5hWmhKRjZMZHVsVDd6OEEtMkQ1XzgiLCJ5IjoiaTVhMk50Sm9VS1hrTG02cThuT0V1OVdPa3NvMUFnNkZUVVQ2a19MTW5HayIsImt0eSI6IkVDIiwia2lkIjoiNFNaLVN0WHJwNVlkNF80cnhIVlRDWVRIeXQ0enlQZk4xZkl1WXNtNmszQSJ9fX1dfQ.OgW0DB8SCVSBrSPA4yXcXLH8tcZcC5SbrqKye0qEWytC3gmA7mLU9BrZzT7IWv0S3KNo8Ftkn5X1l8w7TPsQAw";
        let expected_payload = br##"{"ietf-json-patch":[{"op":"add","path":"/publicKey/1","value":{"id":"#4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A","type":"JsonWebKey2020","controller":"did:key:z6MknSQNZ7bZwS9xtEnhvr549m8xPJFXjNepmSgeJj837gmS","publicKeyJwk":{"crv":"secp256k1","x":"Z4Y3NNOxv0J6tCgqOBFnHnaZhJF6LdulT7z8A-2D5_8","y":"i5a2NtJoUKXkLm6q8nOEu9WOkso1Ag6FTUT6k_LMnGk","kty":"EC","kid":"4SZ-StXrp5Yd4_4rxHVTCYTHyt4zyPfN1fIuYsm6k3A"}}}]}"##;
        let expected_signature = b":\x05\xb4\x0c\x1f\x12\tT\x81\xad#\xc0\xe3%\xdc\\\xb1\xfc\xb5\xc6\\\x0b\x94\x9b\xae\xa2\xb2{J\x84[+B\xde\t\x80\xeeb\xd4\xf4\x1a\xd9\xcd>\xc8Z\xfd\x12\xdc\xa3h\xf0[d\x9f\x95\xf5\x97\xcc;L\xfb\x10\x03";
        let expected_jws = JWS {
            header: serde_json::from_str(r#"{"kid":"did:example:456#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A","alg":"EdDSA"}"#).unwrap(),
            payload: expected_payload.to_vec(),
            signature: expected_signature.to_vec(),
        };

        let decoded = decode_jws(&jws).unwrap();
        println!("{:?}", &decoded);

        assert_eq!(decoded, expected_jws)
    }

    #[test]
    fn test_resolve_with_bad_json_patch_should_error() {
        let result = resolve(&"did:example?signedIetfJsonPatch=BadEnCodiNGDonotUse");
        assert!(result.is_err())
    }

    #[test]
    fn test_json_patch_demo() {
        let mut key = generate::<Ed25519KeyPair>(None);
        let initial_did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let json = serde_json::to_string_pretty(&initial_did_doc).unwrap();
        println!("{}", json);

        let shared_capability_key_uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let patches = vec![
            PatchOperation::Add(AddOperation {
                path: "/capabilityDelegation/1".to_string(),
                value: json!(shared_capability_key_uri),
            }),
            PatchOperation::Add(AddOperation {
                path: "/capabilityInvocation/1".to_string(),
                value: json!(shared_capability_key_uri),
            }),
        ];

        key.add_patches(patches);
        let did_doc = key.get_did_document(CONFIG_JOSE_PUBLIC);
        let json = serde_json::to_string_pretty(&did_doc).unwrap();
        println!("{}", json);

        let expected_doc = &mut initial_did_doc.clone();
        let capability_delegation = &mut expected_doc.capability_delegation.as_mut().unwrap();
        let capability_invocation = &mut expected_doc.capability_invocation.as_mut().unwrap();
        capability_delegation.insert(1, shared_capability_key_uri.to_string());
        capability_invocation.insert(1, shared_capability_key_uri.to_string());
        assert_eq!(did_doc, *expected_doc);
    }

    #[test]
    fn test_json_patch_demo_uri_resolutions() {
        let key = generate::<Ed25519KeyPair>(None);
        let resolved_key = resolve(&format!("did:key:{}", (key.fingerprint()))).unwrap();
        let initial_did_doc_resolved = resolved_key.get_did_document(CONFIG_JOSE_PUBLIC);
        let json = serde_json::to_string_pretty(&initial_did_doc_resolved).unwrap();
        println!("{}", json);

        let new_capability_key_uri = "did:key:z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL#z6Mkk7yqnGF3YwTrLpqrW6PGsKci7dNqh1CjnvMbzrMerSeL";
        let patches = vec![PatchOperation::Replace(ReplaceOperation {
            path: "/capabilityDelegation/0".to_string(),
            value: json!(new_capability_key_uri),
        })];

        let patched_uri = generate_json_patch_did_uri(&key, patches).unwrap();
        let did_doc = resolve(&patched_uri).unwrap().get_did_document(CONFIG_JOSE_PUBLIC);
        let json = serde_json::to_string_pretty(&did_doc).unwrap();
        println!("{}", json);

        let mut expected_doc = initial_did_doc_resolved.clone();
        let _ = std::mem::replace(
            &mut expected_doc.capability_delegation.as_mut().unwrap()[0],
            new_capability_key_uri.to_string(),
        );
        assert_eq!(did_doc, expected_doc);
    }
}
