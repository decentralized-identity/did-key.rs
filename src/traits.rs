use crate::{didcore::Config, Document, Error, VerificationMethod};
use json_patch::PatchOperation;

/// Return key material bytes
pub trait KeyMaterial {
    /// Returns the public key bytes as slice
    fn public_key_bytes(&self) -> Vec<u8>;
    /// Returns the secret key bytes as slice
    fn private_key_bytes(&self) -> Vec<u8>;
}

/// Collection of methods to initialize a key pair
/// using random or deterministic manner
pub trait Generate: KeyMaterial {
    /// Generate random key
    fn new() -> Self;
    /// Generate key deterministically using a given seed
    fn new_with_seed(seed: &[u8]) -> Self;
    /// Generate instance from existing public key
    fn from_public_key(public_key: &[u8]) -> Self;
    /// Generate instance from existing secret key
    fn from_secret_key(private_key: &[u8]) -> Self;
}

/// Used for Elliptic Curve Digital Signature Algorithm
pub trait CoreSign {
    /// Performs sign operation
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
    /// Performs verify operation
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<(), Error>;
}

/// Used for Elliptic-curve Diffie–Hellman key exchange operations
pub trait ECDH {
    /// Perform key exchange operation
    fn key_exchange(&self, their_public: &Self) -> Vec<u8>;
}

pub trait DIDCore {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod>;
    fn get_did_document(&self, config: Config) -> Document;
}

pub trait Fingerprint {
    fn fingerprint(&self) -> String;
}

pub trait AddDIDJsonPatches {
    fn add_patches(&mut self, patches: Vec<PatchOperation>);
}
