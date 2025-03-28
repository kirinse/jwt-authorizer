use std::sync::Arc;

use serde::de::DeserializeOwned;

use crate::{
    authorizer::{ClaimsCheckerFn, KeySourceType},
    error::InitError,
    layer::{AuthorizationLayer, JwtSource},
    Authorizer, Refresh, RefreshStrategy, RegisteredClaims, Validation,
};

use reqwest::Client;

/// Authorizer Layer builder
///
/// - initialisation of the Authorizer from jwks, rsa, ed, ec or secret
/// - can define a checker (jwt claims check)
pub struct AuthorizerBuilder<C = RegisteredClaims>
where
    C: Clone + DeserializeOwned,
{
    key_source_type: KeySourceType,
    refresh: Option<Refresh>,
    claims_checker: Option<ClaimsCheckerFn<C>>,
    validation: Option<Validation>,
    jwt_source: JwtSource,
    http_client: Option<Client>,
}

/// alias for `AuthorizerBuidler` (backwards compatibility)
pub type JwtAuthorizer<C = RegisteredClaims> = AuthorizerBuilder<C>;

/// authorization layer builder
impl<C> AuthorizerBuilder<C>
where
    C: Clone + DeserializeOwned + Send + Sync,
{
    /// Builds Authorizer Layer from a `OpenId` Connect discover metadata
    #[must_use]
    pub fn from_oidc(issuer: &str) -> Self {
        Self {
            key_source_type: KeySourceType::Discovery(issuer.to_string()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a JWKS endpoint
    #[must_use]
    pub fn from_jwks_url(url: &str) -> Self {
        Self {
            key_source_type: KeySourceType::Jwks(url.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }
    #[must_use]
    pub fn from_jwks(path: &str) -> Self {
        Self {
            key_source_type: KeySourceType::JwksPath(path.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }
    #[must_use]
    pub fn from_jwks_text(text: &str) -> Self {
        Self {
            key_source_type: KeySourceType::JwksString(text.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a RSA PEM file
    #[must_use]
    pub fn from_rsa_pem(path: &str) -> Self {
        Self {
            key_source_type: KeySourceType::RSA(path.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from an RSA PEM raw text
    #[must_use]
    pub fn from_rsa_pem_text(text: &str) -> Self {
        Self {
            key_source_type: KeySourceType::RSAString(text.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a EC PEM file
    #[must_use]
    pub fn from_ec_pem(path: &str) -> Self {
        Self {
            key_source_type: KeySourceType::EC(path.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a EC PEM raw text
    #[must_use]
    pub fn from_ec_pem_text(text: &str) -> Self {
        Self {
            key_source_type: KeySourceType::ECString(text.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a EC PEM file
    #[must_use]
    pub fn from_ed_pem(path: &str) -> Self {
        Self {
            key_source_type: KeySourceType::ED(path.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a EC PEM raw text
    #[must_use]
    pub fn from_ed_pem_text(text: &str) -> Self {
        Self {
            key_source_type: KeySourceType::EDString(text.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Builds Authorizer Layer from a secret phrase
    #[must_use]
    pub fn from_secret(secret: &str) -> Self {
        Self {
            key_source_type: KeySourceType::Secret(secret.to_owned()),
            refresh: Option::default(),
            claims_checker: None,
            validation: None,
            jwt_source: JwtSource::AuthorizationHeader,
            http_client: None,
        }
    }

    /// Refreshes configuration for jwk store
    #[must_use]
    pub fn refresh(mut self, refresh: Refresh) -> Self {
        if self.refresh.is_some() {
            tracing::warn!("More than one refresh configuration found!");
        }
        self.refresh = Some(refresh);
        self
    }

    /// no refresh, jwks will be loaded juste once
    #[must_use]
    pub fn no_refresh(mut self) -> Self {
        if self.refresh.is_some() {
            tracing::warn!("More than one refresh configuration found!");
        }
        self.refresh = Some(Refresh {
            strategy: RefreshStrategy::NoRefresh,
            ..Default::default()
        });
        self
    }

    /// configures token content check (custom function), if false a 403 will be sent.
    /// (`AuthError::InvalidClaims()`)
    #[must_use]
    pub fn check<F>(mut self, checker_fn: F) -> Self
    where
        F: Fn(&C) -> bool + Send + Sync + 'static,
    {
        self.claims_checker = Some(Arc::new(Box::new(checker_fn)));

        self
    }

    #[must_use]
    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = Some(validation);

        self
    }

    /// configures the source of the bearer token
    ///
    /// (default: `AuthorizationHeader`)
    #[must_use]
    pub fn jwt_source(mut self, src: JwtSource) -> Self {
        self.jwt_source = src;

        self
    }

    /// provide a custom http client for oicd requests
    /// if not called, uses a default configured client
    ///
    /// (default: None)
    #[must_use]
    pub fn http_client(mut self, http_client: Client) -> Self {
        self.http_client = Some(http_client);

        self
    }

    /// Build layer
    ///
    /// # Errors
    ///
    /// [`InitError`]
    #[deprecated(since = "0.10.0", note = "please use `IntoLayer::into_layer()` instead")]
    pub async fn layer(self) -> Result<AuthorizationLayer<C>, InitError> {
        let val = self.validation.unwrap_or_default();
        let auth = Arc::new(
            Authorizer::build(
                self.key_source_type,
                self.claims_checker,
                self.refresh,
                val,
                self.jwt_source,
                None,
            )
            .await?,
        );
        Ok(AuthorizationLayer::new(vec![auth]))
    }

    /// Build
    ///
    /// # Errors
    ///
    /// [`InitError`]
    pub async fn build(self) -> Result<Authorizer<C>, InitError> {
        let val = self.validation.unwrap_or_default();

        Authorizer::build(
            self.key_source_type,
            self.claims_checker,
            self.refresh,
            val,
            self.jwt_source,
            self.http_client,
        )
        .await
    }
}
