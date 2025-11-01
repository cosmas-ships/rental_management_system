// services/users.rs
use crate::{
    error::{AppError, Result},
    models::User,
};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Clone)]
pub struct UserService {
    db: PgPool,
}

impl UserService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
    /// Create a new user
    pub async fn create_user(&self, email: &str, password_hash: &str) -> Result<User> {
        let user = sqlx::query_as!( User, r#" INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, password_hash, created_at, updated_at, is_active, email_verified "#, email, password_hash ) .fetch_one(&self.db) .await .map_err(|e| { if let sqlx::Error::Database(db_err) = &e { if db_err.is_unique_violation() { return AppError::UserAlreadyExists; } } AppError::Database(e) })?;
        Ok(user)
    }
    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<User> {
        let user = sqlx::query_as!( User, r#" SELECT id, email, password_hash, created_at, updated_at, is_active, email_verified FROM users WHERE email = $1 "#, email ) .fetch_optional(&self.db) .await? .ok_or(AppError::UserNotFound)?;
        Ok(user)
    }
    /// Get user by ID
    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User> {
        let user = sqlx::query_as!( User, r#" SELECT id, email, password_hash, created_at, updated_at, is_active, email_verified FROM users WHERE id = $1 "#, user_id ) .fetch_optional(&self.db) .await? .ok_or(AppError::UserNotFound)?;
        Ok(user)
    }
    /// Check if user is active
    pub async fn is_user_active(&self, user_id: Uuid) -> Result<bool> {
        let result = sqlx::query!(r#" SELECT is_active FROM users WHERE id = $1 "#, user_id)
            .fetch_optional(&self.db)
            .await?
            .ok_or(AppError::UserNotFound)?;
        Ok(result.is_active)
    }
}
