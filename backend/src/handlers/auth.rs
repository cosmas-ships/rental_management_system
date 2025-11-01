use crate::{
    error::{AppError, Result},
    models::{
        User, LoginRequest, RegisterRequest, AuthResponse, RefreshRequest, LogoutRequest,
    },
    state::AppState,
};
use axum::{
    extract::{State, Extension},
    Json,
};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng, PasswordHash};
use uuid::Uuid;
use validator::Validate; // ✅ Needed for payload.validate()

/// Register a new user
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>> {
    // Validate input
    payload.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    // Generate salt and hash password using Argon2
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|_| AppError::PasswordHashError)?
        .to_string();

    // Create user in DB
    let user = state
        .user_service
        .create_user(&payload.email, &password_hash)
        .await?;

    // Generate tokens
    let access_token = state.jwt_service.generate_access_token(&user)?;
    let refresh_token_id = Uuid::new_v4();
    let refresh_token = state
        .jwt_service
        .generate_refresh_token(user.id, refresh_token_id)?;

    // Store refresh token
    state
        .token_service
        .store_refresh_token(refresh_token_id, user.id, &refresh_token, None, None)
        .await?;

    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_expiry,
    }))
}

/// Login user
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>> {
    payload.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    // Fetch user by email
    let user = state
        .user_service
        .get_user_by_email(&payload.email)
        .await?;

    // Verify password
    let parsed_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| AppError::PasswordHashError)?;
    let argon2 = Argon2::default();
    argon2
        .verify_password(payload.password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::InvalidCredentials)?;

    // Generate tokens
    let access_token = state.jwt_service.generate_access_token(&user)?;
    let refresh_token_id = Uuid::new_v4();
    let refresh_token = state
        .jwt_service
        .generate_refresh_token(user.id, refresh_token_id)?;

    // Store refresh token
    state
        .token_service
        .store_refresh_token(refresh_token_id, user.id, &refresh_token, None, None)
        .await?;

    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_expiry,
    }))
}

/// Refresh access token using a valid refresh token
pub async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>> {
    let refresh_token = payload.refresh_token.clone();

    // Verify refresh token
    let claims = state.jwt_service.verify_refresh_token(&refresh_token)?;
    let _refresh_record = state
        .token_service
        .verify_refresh_token(&refresh_token)
        .await?;

    // Rotate refresh token
    let new_token_id = Uuid::new_v4();
    let new_refresh_token = state
        .jwt_service
        .generate_refresh_token(
            Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?,
            new_token_id,
        )?;

    state
        .token_service
        .rotate_refresh_token(
            &refresh_token,
            new_token_id,
            &new_refresh_token,
            None,
            None,
        )
        .await?;

    // Generate new access token
    let user = state
        .user_service
        .get_user_by_id(Uuid::parse_str(&claims.sub).unwrap())
        .await?;
    let new_access_token = state.jwt_service.generate_access_token(&user)?;

    Ok(Json(AuthResponse {
        access_token: new_access_token,
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_expiry,
    }))
}

/// Logout user (invalidate refresh + blacklist access token)
pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<()>> {
    let token = &payload.access_token;

    // Decode to get user_id
    let claims = state.jwt_service.verify_access_token(token)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    // Blacklist access token
    state
        .token_service
        .blacklist_access_token(token, state.config.access_token_expiry)
        .await?;

    // Revoke all refresh tokens for this user
    state
        .token_service
        .revoke_all_user_tokens(user_id)
        .await?;

    Ok(Json(()))
}

/// Get current authenticated user
pub async fn me(
    State(state): State<AppState>,
    Extension(user_id): Extension<Uuid>,
) -> Result<Json<User>> {
    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(Json(user))
}
