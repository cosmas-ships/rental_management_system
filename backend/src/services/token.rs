// src/services/token.rs
use crate::{
    config::Config,
    error::{AppError, Result},
    models::RefreshToken,
};
use chrono::{Duration, Utc};
use ipnetwork::IpNetwork;
use redis::{aio::ConnectionManager, AsyncCommands};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenService {
    db: PgPool,
    redis: ConnectionManager,
    config: Config,
}

impl TokenService {
    pub fn new(db: PgPool, redis: ConnectionManager, config: Config) -> Self {
        Self { db, redis, config }
    }

    /// Hash a refresh token for storage
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Store refresh token in database
    pub async fn store_refresh_token(
        &self,
        token_id: Uuid,
        user_id: Uuid,
        token: &str,
        device_info: Option<String>,
        ip_address: Option<String>,
    ) -> Result<()> {
        let token_hash = Self::hash_token(token);
        let expires_at = Utc::now() + Duration::seconds(self.config.refresh_token_expiry);
        
        // Convert IP string to IpNetwork
        let ip_network = ip_address
            .as_ref()
            .and_then(|ip| IpNetwork::from_str(ip).ok());

        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, device_info, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            token_id,
            user_id,
            token_hash,
            expires_at,
            device_info,
            ip_network as Option<IpNetwork>
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Verify and retrieve refresh token from database
    pub async fn verify_refresh_token(&self, token: &str) -> Result<RefreshToken> {
        let token_hash = Self::hash_token(token);

        let refresh_token = sqlx::query_as!(
            RefreshToken,
            r#"
            SELECT id, user_id, token_hash, expires_at, created_at, 
                   revoked_at, replaced_by_token, device_info, 
                   ip_address as "ip_address: _"
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
            token_hash
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or(AppError::InvalidToken)?;

        // Check if token is revoked
        if refresh_token.revoked_at.is_some() {
            return Err(AppError::TokenRevoked);
        }

        // Check if token is expired
        if refresh_token.expires_at < Utc::now() {
            return Err(AppError::TokenExpired);
        }

        Ok(refresh_token)
    }

    /// Rotate refresh token (revoke old, create new)
    pub async fn rotate_refresh_token(
        &self,
        old_token: &str,
        new_token_id: Uuid,
        new_token: &str,
        device_info: Option<String>,
        ip_address: Option<String>,
    ) -> Result<()> {
        let old_token_hash = Self::hash_token(old_token);
        let new_token_hash = Self::hash_token(new_token);
        let expires_at = Utc::now() + Duration::seconds(self.config.refresh_token_expiry);
        
        // Convert IP string to IpNetwork
        let ip_network = ip_address
            .as_ref()
            .and_then(|ip| IpNetwork::from_str(ip).ok());

        // Get old token details
        let old_refresh_token = sqlx::query_as!(
            RefreshToken,
            r#"
            SELECT id, user_id, token_hash, expires_at, created_at, 
                   revoked_at, replaced_by_token, device_info, 
                   ip_address as "ip_address: _"
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
            old_token_hash
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or(AppError::InvalidToken)?;

        // Start transaction
        let mut tx = self.db.begin().await?;

        // Revoke old token
        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = $1, replaced_by_token = $2
            WHERE token_hash = $3
            "#,
            Utc::now(),
            new_token_id,
            old_token_hash
        )
        .execute(&mut *tx)
        .await?;

        // Create new token
        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, device_info, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            new_token_id,
            old_refresh_token.user_id,
            new_token_hash,
            expires_at,
            device_info,
            ip_network as Option<IpNetwork>
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    /// Revoke all refresh tokens for a user
    pub async fn revoke_all_user_tokens(&self, user_id: Uuid) -> Result<()> {
        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = $1
            WHERE user_id = $2 AND revoked_at IS NULL
            "#,
            Utc::now(),
            user_id
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Revoke specific refresh token
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        let token_hash = Self::hash_token(token);

        sqlx::query!(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = $1
            WHERE token_hash = $2
            "#,
            Utc::now(),
            token_hash
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Clean up expired tokens (run periodically)
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let result = sqlx::query!(
            r#"
            DELETE FROM refresh_tokens
            WHERE expires_at < $1 OR (revoked_at IS NOT NULL AND revoked_at < $2)
            "#,
            Utc::now(),
            Utc::now() - Duration::days(30)
        )
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected())
    }

    /// Store blacklisted access token in Redis (for logout before expiry)
    pub async fn blacklist_access_token(&self, token: &str, expiry_secs: i64) -> Result<()> {
        let mut conn = self.redis.clone();
        let key = format!("blacklist:{}", token);

        let _: () = conn.set_ex(&key, "1", expiry_secs as u64)
            .await
            .map_err(AppError::Redis)?;

        Ok(())
    }

    /// Check if access token is blacklisted
    pub async fn is_token_blacklisted(&self, token: &str) -> Result<bool> {
        let mut conn = self.redis.clone();
        let key = format!("blacklist:{}", token);

        let exists: bool = conn.exists(&key).await.map_err(AppError::Redis)?;

        Ok(exists)
    }
}