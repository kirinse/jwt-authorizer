#![doc = include_str!("../docs/README.md")]

use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    http::request::Parts,
};
use jsonwebtoken::TokenData;
use serde::de::DeserializeOwned;

pub use self::error::AuthError;
pub use authorizer::{Authorizer, IntoLayer};
pub use builder::{AuthorizerBuilder, JwtAuthorizer};
pub use claims::{NumericDate, OneOrArray, RegisteredClaims};
pub use jwks::key_store_manager::{Refresh, RefreshStrategy};
pub use validation::Validation;

pub mod authorizer;
pub mod builder;
pub mod claims;
pub mod error;
pub mod jwks;
pub mod layer;
mod oidc;
pub mod validation;

/// Claims serialized using T
#[derive(Debug, Clone, Copy, Default)]
pub struct JwtClaims<T>(pub T);

impl<T, S> FromRequestParts<S> for JwtClaims<T>
where
    T: DeserializeOwned + Send + Sync + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<TokenData<T>>().map_or_else(
            || Err(AuthError::NoAuthorizerLayer()),
            |claims| Ok(Self(claims.claims.clone())),
        )
    }
}

impl<T, S> OptionalFromRequestParts<S> for JwtClaims<T>
where
    T: DeserializeOwned + Send + Sync + Clone + 'static,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<TokenData<T>>().map(|t| Self(t.claims.clone())))
    }
}
