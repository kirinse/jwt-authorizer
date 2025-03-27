use std::{str::FromStr, sync::Arc};

use jsonwebtoken::{
    jwk::{AlgorithmParameters, Jwk},
    Algorithm, DecodingKey, Header,
};

use crate::error::AuthError;

use self::key_store_manager::KeyStoreManager;

pub mod key_store_manager;

#[derive(Clone)]
pub enum KeySource {
    /// `KeyDataSource` managing a refreshable key sets
    KeyStoreSource(KeyStoreManager),
    /// Manages public key sets, initialized on startup
    MultiKeySource(KeySet),
    /// Manages one public key, initialized on startup
    SingleKeySource(Arc<KeyData>),
}

#[derive(Clone)]
pub struct KeyData {
    pub kid: Option<String>,
    /// valid algorithms
    pub algs: Vec<Algorithm>,
    pub key: DecodingKey,
}

fn get_valid_algs(key: &Jwk) -> Vec<Algorithm> {
    key.common.key_algorithm.map_or_else(
        || match key.algorithm {
            AlgorithmParameters::EllipticCurve(_) => {
                vec![Algorithm::ES256, Algorithm::ES384]
            }
            AlgorithmParameters::RSA(_) => vec![
                Algorithm::RS256,
                Algorithm::RS384,
                Algorithm::RS512,
                Algorithm::PS256,
                Algorithm::PS384,
                Algorithm::PS512,
            ],
            AlgorithmParameters::OctetKey(_) => vec![Algorithm::EdDSA],
            AlgorithmParameters::OctetKeyPair(_) => vec![Algorithm::HS256, Algorithm::HS384, Algorithm::HS512],
        },
        |key_alg| Algorithm::from_str(key_alg.to_string().as_str()).map_or(vec![], |a| vec![a]),
    )
}

impl KeyData {
    /// Create `KeyData` from `Jwk`
    ///
    /// # Errors
    ///
    /// [`jsonwebtoken::errors::Error`]
    pub fn from_jwk(key: &Jwk) -> Result<Self, jsonwebtoken::errors::Error> {
        Ok(Self {
            kid: key.common.key_id.clone(),
            algs: get_valid_algs(key),
            key: DecodingKey::from_jwk(key)?,
        })
    }
}

#[derive(Clone, Default)]
pub struct KeySet(Vec<Arc<KeyData>>);

impl From<Vec<Arc<KeyData>>> for KeySet {
    fn from(value: Vec<Arc<KeyData>>) -> Self {
        Self(value)
    }
}

impl KeySet {
    /// Find the key in the set that matches the given key id, if any.
    #[must_use]
    pub fn find_kid(&self, kid: &str) -> Option<&Arc<KeyData>> {
        self.0.iter().find(|k| k.kid.as_ref().is_some_and(|k| k == kid))
    }

    /// Find the key in the set that matches the given key id, if any.
    #[must_use]
    pub fn find_alg(&self, alg: &Algorithm) -> Option<&Arc<KeyData>> {
        self.0.iter().find(|k| k.algs.contains(alg))
    }

    /// Find first key.
    #[must_use]
    pub fn first(&self) -> Option<&Arc<KeyData>> {
        self.0.first()
    }

    pub(crate) fn get_key(&self, header: &Header) -> Result<&Arc<KeyData>, AuthError> {
        let key = if let Some(ref kid) = header.kid {
            self.find_kid(kid).ok_or_else(|| AuthError::InvalidKid(kid.to_owned()))?
        } else {
            self.find_alg(&header.alg).ok_or(AuthError::InvalidKeyAlg(header.alg))?
        };
        Ok(key)
    }
}

impl KeySource {
    /// get key
    ///
    /// # Errors
    ///
    /// [`AuthError`]
    pub async fn get_key(&self, header: Header) -> Result<Arc<KeyData>, AuthError> {
        match self {
            Self::KeyStoreSource(kstore) => kstore.get_key(&header).await,
            Self::MultiKeySource(keys) => keys.get_key(&header).cloned(),
            Self::SingleKeySource(key) => Ok(key.clone()),
        }
    }
}
