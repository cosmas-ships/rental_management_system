use crate::{handlers::auth, middleware::auth_middleware, state::AppState};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};

pub fn create_router(state: AppState) -> Router {
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route("/logout", post(auth::logout))
        .route("/sessions", post(auth::get_active_sessions)); // New route

    let protected_routes = Router::new()
        .route("/me", get(auth::me))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new()
        .nest("/auth", auth_routes)
        .nest("/api", protected_routes)
        .with_state(state)
}