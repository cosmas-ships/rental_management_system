use crate::{
    config::Config,
    error::{AppError, Result},
    models::{AccessTokenClaims, RefreshTokenClaims, User},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use uuid::Uuid;

#[derive(Clone)]
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    config: Config,
}

impl JwtService {
    pub fn new(config: Config) -> Self {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        Self {
            encoding_key,
            decoding_key,
            config,
        }
    }

    /// Generate access token with token_id reference
    pub fn generate_access_token(&self, user: &User, token_id: Uuid) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.access_token_expiry);

        let claims = AccessTokenClaims {
            sub: user.id.to_string(),
            jti: token_id.to_string(), // Add token_id reference
            email: user.email.clone(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.config.jwt_issuer.clone(),
            aud: self.config.jwt_audience.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::JwtError(e.to_string()))
    }

    /// Generate refresh token with token_id
    pub fn generate_refresh_token(&self, user_id: Uuid, token_id: Uuid) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.refresh_token_expiry);

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            jti: token_id.to_string(),     // Add jti
            token_id: token_id.to_string(), // Keep for backwards compatibility
            exp: exp.timestamp(),
            iat: now.timestamp(),
            iss: self.config.jwt_issuer.clone(),
            aud: self.config.jwt_audience.clone(),
        };

        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::JwtError(e.to_string()))
    }

    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_audience(&[&self.config.jwt_audience]);

        decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                _ => AppError::InvalidToken,
            })
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<RefreshTokenClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_audience(&[&self.config.jwt_audience]);

        decode::<RefreshTokenClaims>(token, &self.decoding_key, &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
                _ => AppError::InvalidToken,
            })
    }
}