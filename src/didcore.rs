use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub use_jose_format: bool,
    pub serialize_secrets: bool,
}

pub const CONFIG_JOSE_PUBLIC: Config = Config {
    use_jose_format: true,
    serialize_secrets: false,
};
pub const CONFIG_JOSE_PRIVATE: Config = Config {
    use_jose_format: true,
    serialize_secrets: true,
};
pub const CONFIG_LD_PUBLIC: Config = Config {
    use_jose_format: false,
    serialize_secrets: false,
};
pub const CONFIG_LD_PRIVATE: Config = Config {
    use_jose_format: false,
    serialize_secrets: true,
};

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct IetfJsonPatch {
    #[serde(rename = "ietf-json-patch")]
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(alias = "publicKeyBase58")]
    #[serde(alias = "publicKeyMultibase")]
    #[serde(alias = "publicKeyJwk")]
    pub public_key: Option<KeyFormat>,
    #[serde(alias = "privateKeyBase58")]
    #[serde(alias = "privateKeyMultibase")]
    #[serde(alias = "privateKeyJwk")]
    pub private_key: Option<KeyFormat>,
}

#[derive(Serialize, Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum KeyFormat {
    Base58(String),
    Multibase(Vec<u8>),
    JWK(JWK),
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct JWK {
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(rename = "kty")]
    pub key_type: String,
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct JWSHeader {
    #[serde(rename = "alg")]
    pub algorithm: String,
    #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct JWS {
    pub header: JWSHeader,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Serialize for VerificationMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("type", &self.key_type)?;
        map.serialize_entry("controller", &self.controller)?;

        match &self.public_key {
            Some(pk) => match pk {
                KeyFormat::Base58(pk) => map.serialize_entry("publicKeyBase58", &pk)?,
                KeyFormat::Multibase(pk) => map.serialize_entry("publicKeyMultibase", &pk)?,
                KeyFormat::JWK(pk) => map.serialize_entry("publicKeyJwk", &pk)?,
            },
            None => {}
        }
        match &self.private_key {
            Some(pk) => match pk {
                KeyFormat::Base58(pk) => map.serialize_entry("privateKeyBase58", &pk)?,
                KeyFormat::Multibase(pk) => map.serialize_entry("privateKeyMultibase", &pk)?,
                KeyFormat::JWK(pk) => map.serialize_entry("privateKeyJwk", &pk)?,
            },
            None => {}
        }

        map.end()
    }
}

impl Default for Config {
    fn default() -> Self {
        CONFIG_LD_PRIVATE
    }
}

#[cfg(test)]
pub mod tests {
    use super::KeyFormat;

    #[test]
    fn test_key_format() {
        let key = KeyFormat::Base58("key-1".to_string());
        let serialized = serde_json::to_string_pretty(&key).unwrap();

        println!("{}", serialized)
    }
}
