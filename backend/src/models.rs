use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub email_verified: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by_token: Option<Uuid>,
    pub device_info: Option<String>,
    pub ip_address: Option<IpNetwork>,
}

// Request/Response DTOs
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String, // Add this so client can store it
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub email_verified: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            created_at: user.created_at,
            email_verified: user.email_verified,
        }
    }
}

// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,      // user_id
    pub jti: String,      // token_id (refresh token ID reference)
    pub email: String,
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,      // user_id
    pub jti: String,      // token_id (unique identifier for this refresh token)
    pub token_id: String, // Keep for backwards compatibility
    pub exp: i64,
    pub iat: i64,
    pub iss: String,
    pub aud: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub logout_all: bool, // Default to false (current device only)
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub message: String,
    pub sessions_revoked: u64,
}

// Session Management
#[derive(Debug, Serialize)]
pub struct ActiveSession {
    pub token_id: Uuid,
    pub device_info: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub is_current: bool,
}

#[derive(Debug, Serialize)]
pub struct ActiveSessionsResponse {
    pub sessions: Vec<ActiveSession>,
    pub current_session_id: Uuid,
    pub total_sessions: usize,
}

#[derive(Debug, Deserialize)]
pub struct CheckSessionsRequest {
    pub access_token: String,
}