use crate::{
    error::{AppError, Result}, 
    middleware::RequestExt,
    models::{
        ActiveSessionsResponse, AuthResponse, CheckSessionsRequest, LoginRequest, 
        LogoutRequest, LogoutResponse, RefreshRequest, RegisterRequest, User
    }, 
    services::password::PasswordService, 
    state::AppState
};
use axum::{
    extract::{Request, State},
    Json,
};
use uuid::Uuid;
use validator::Validate;

/// Register a new user
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>> {
    // Validate input
    payload.validate().map_err(|e| AppError::Validation(e.to_string()))?;

    // Hash password using PasswordService
    let password_hash = PasswordService::hash_password(&payload.password)?;

    // Create user in DB
    let user = state
        .user_service
        .create_user(&payload.email, &password_hash)
        .await?;

    // Generate tokens
    let refresh_token_id = Uuid::new_v4();
    let access_token = state.jwt_service.generate_access_token(&user, refresh_token_id)?;
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
        refresh_token, // Return refresh token to client
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

    // Verify password using PasswordService
    let is_valid = PasswordService::verify_password(&payload.password, &user.password_hash)?;
    if !is_valid {
        return Err(AppError::InvalidCredentials);
    }

    // Generate tokens
    let refresh_token_id = Uuid::new_v4();
    let access_token = state.jwt_service.generate_access_token(&user, refresh_token_id)?;
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
        refresh_token, // Return refresh token to client
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
    let new_access_token = state.jwt_service.generate_access_token(&user, new_token_id)?;

    Ok(Json(AuthResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token, // Return new refresh token
        token_type: "Bearer".into(),
        expires_in: state.config.access_token_expiry,
    }))
}

/// Get all active sessions for the current user
pub async fn get_active_sessions(
    State(state): State<AppState>,
    Json(payload): Json<CheckSessionsRequest>,
) -> Result<Json<ActiveSessionsResponse>> {
    let token = &payload.access_token;
    
    // Decode to get user_id and current token_id
    let claims = state.jwt_service.verify_access_token(token)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;
    let current_token_id = Uuid::parse_str(&claims.jti)
        .map_err(|_| AppError::InvalidToken)?;
    
    // Get all active sessions
    let sessions = state
        .token_service
        .get_active_sessions(user_id, current_token_id)
        .await?;
    
    let total_sessions = sessions.len();
    
    Ok(Json(ActiveSessionsResponse {
        current_session_id: current_token_id,
        total_sessions,
        sessions,
    }))
}

/// Logout user with option to logout from all devices
pub async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>> {
    let token = &payload.access_token;

    // Decode to get user_id
    let claims = state.jwt_service.verify_access_token(token)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    // Blacklist access token
    state
        .token_service
        .blacklist_access_token(token, state.config.access_token_expiry)
        .await?;

    let sessions_revoked = if payload.logout_all {
        // Revoke all refresh tokens for this user
        state
            .token_service
            .revoke_all_user_tokens(user_id)
            .await?
    } else {
        // Revoke only the specific refresh token
        state
            .token_service
            .revoke_token(&payload.refresh_token)
            .await?;
        1
    };

    Ok(Json(LogoutResponse {
        message: if payload.logout_all {
            "Logged out from all devices".to_string()
        } else {
            "Logged out from current device".to_string()
        },
        sessions_revoked,
    }))
}

/// Get current authenticated user
pub async fn me(
    State(state): State<AppState>,
    req: Request,
) -> Result<Json<User>> {
    // Extract user_id from request extensions using RequestExt trait
    let user_id = req.user_id()?;
    
    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(Json(user))
}