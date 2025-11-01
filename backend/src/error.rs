// src/error.rs

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("User not found")]
    UserNotFound,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token revoked")]
    TokenRevoked,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Internal server error")]
    InternalServerError,

    #[error("Password hashing error")]
    PasswordHashError,

    #[error("JWT error: {0}")]
    JwtError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::Redis(ref e) => {
                tracing::error!("Redis error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AppError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AppError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AppError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AppError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
            AppError::TokenRevoked => (StatusCode::UNAUTHORIZED, "Token revoked"),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AppError::Validation(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::InternalServerError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::PasswordHashError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
            AppError::JwtError(ref e) => {
                tracing::error!("JWT error: {:?}", e);
                (StatusCode::UNAUTHORIZED, "Invalid token")
            }
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

// Catch-all conversion for unexpected errors
impl From<Box<dyn std::error::Error>> for AppError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        tracing::error!("Unexpected error: {:?}", e);
        AppError::InternalServerError
    }
}

// Additional conversions for common error types
impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        tracing::error!("IO error: {:?}", e);
        AppError::InternalServerError
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        tracing::error!("JSON serialization error: {:?}", e);
        AppError::InternalServerError
    }
}

pub type Result<T> = std::result::Result<T, AppError>;