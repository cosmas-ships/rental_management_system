//src/middleware.rs 

use crate::{
    error::{AppError, Result},
    state::AppState,
};
use axum::{
    extract::{Request, State},
    http::{header},
    middleware::Next,
    response::{Response},
};
use uuid::Uuid;

/// Extract user ID from Authorization header
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response> {
    let token = extract_token_from_header(&req)?;

    // Check if token is blacklisted
    if state.token_service.is_token_blacklisted(&token).await? {
        return Err(AppError::TokenRevoked);
    }

    // Verify token
    let claims = state.jwt_service.verify_access_token(&token)?;

    // Parse user ID
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::InvalidToken)?;

    // Check if user is active
    if !state.user_service.is_user_active(user_id).await? {
        return Err(AppError::Unauthorized);
    }

    // Insert user_id into request extensions for handlers to use
    req.extensions_mut().insert(user_id);

    Ok(next.run(req).await)
}

/// Extract bearer token from Authorization header
fn extract_token_from_header(req: &Request) -> Result<String> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized);
    }

    Ok(auth_header[7..].to_string())
}

/// Extension trait to extract authenticated user ID from request
pub trait RequestExt {
    fn user_id(&self) -> Result<Uuid>;
}

impl RequestExt for Request {
    fn user_id(&self) -> Result<Uuid> {
        self.extensions()
            .get::<Uuid>()
            .copied()
            .ok_or(AppError::Unauthorized)
    }
}