use crate::DIDKeyTypeInternal;
use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};

pub static mut CONTENT_TYPE: ContentType = ContentType::JsonLd;

pub enum ContentType {
    JsonLd,
    Json,
}

pub trait DIDCore {
    fn to_verification_method(&self, controller: &str) -> Vec<VerificationMethod>;
    fn get_did_document(&self) -> Document;
    fn get_fingerprint(&self) -> String;
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<String>>,
    pub verification_method: Vec<VerificationMethod>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct VerificationMethod {
    pub id: String,
    pub(crate) key_type: DIDKeyTypeInternal,
    pub controller: String,
    pub public_key: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
}

impl Serialize for VerificationMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("controller", &self.controller)?;

        unsafe {
            match CONTENT_TYPE {
                ContentType::JsonLd => {
                    map.serialize_entry(
                        "type",
                        match &self.key_type {
                            DIDKeyTypeInternal::Ed25519 => "Ed25519VerificationKey2018",
                            DIDKeyTypeInternal::X25519 => "X25519KeyAgreementKey2019",
                            DIDKeyTypeInternal::Bls12381G1 => "Bls12381G1Key2020",
                            DIDKeyTypeInternal::Bls12381G2 => "Bls12381G2Key2020",
                            _ => todo!(),
                        },
                    )?;
                    match &self.public_key {
                        Some(key) => {
                            map.serialize_entry("publicKeyBase58", &bs58::encode(key.as_slice()).into_string())?
                        }
                        None => {}
                    }
                    match &self.private_key {
                        Some(key) => {
                            map.serialize_entry("privateKeyBase58", &bs58::encode(key.as_slice()).into_string())?
                        }
                        None => {}
                    }
                }
                ContentType::Json => {
                    map.serialize_entry("type", "JsonWebKey2020")?;

                    let config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
                    let jwk = JWK {
                        key_type: match self.key_type {
                            DIDKeyTypeInternal::Ed25519 | DIDKeyTypeInternal::X25519 => "OKP",
                            _ => "EC",
                        }
                        .to_string(),
                        curve: match &self.key_type {
                            DIDKeyTypeInternal::Ed25519 => "Ed25519",
                            DIDKeyTypeInternal::X25519 => "X25519",
                            DIDKeyTypeInternal::P256 => "P-256",
                            DIDKeyTypeInternal::Bls12381G1 => "BLS12381_G1",
                            DIDKeyTypeInternal::Bls12381G2 => "BLS12381_G2",
                            DIDKeyTypeInternal::Secp256k1 => "Secp256k1",
                        }
                        .to_string(),
                        x: self.public_key.as_ref().map(|key| base64::encode_config(key, config)),
                        d: self.private_key.as_ref().map(|key| base64::encode_config(key, config)),
                    };

                    match &jwk.d {
                        Some(_) => map.serialize_entry("privateKeyJwk", &jwk)?,
                        None => map.serialize_entry("publicKeyJwk", &jwk)?,
                    }
                }
            };
        }

        map.end()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct JWK {
    #[serde(rename = "kty")]
    key_type: String,
    #[serde(rename = "crv")]
    curve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
}
