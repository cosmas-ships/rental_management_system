mod config;
mod error;
mod handlers {
    pub mod auth;
}
mod middleware;
mod models;
mod routes;
mod services {
    pub mod jwt;
    pub mod password;
    pub mod token;
    pub mod users;
}
mod state;

use config::Config;
use redis::aio::ConnectionManager;
use routes::create_router;
use services::{jwt::JwtService, token::TokenService, users::UserService};
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use tower_http::cors::CorsLayer;
use axum::http::{Method, header};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_backend=debug,tower_http=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load configuration
    let config = Config::from_env()?;
    tracing::info!("Configuration loaded");

    // Setup database connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    tracing::info!("Database connection established");

    // Run migrations
    sqlx::migrate!("./migrations").run(&db_pool).await?;
    tracing::info!("Database migrations completed");

    // Setup Redis connection
    let redis_client = redis::Client::open(config.redis_url.clone())?;
    let redis_conn = ConnectionManager::new(redis_client).await?;
    tracing::info!("Redis connection established");

    // Initialize services
    let jwt_service = JwtService::new(config.clone());
    let user_service = UserService::new(db_pool.clone());
    let token_service = TokenService::new(db_pool.clone(), redis_conn, config.clone());

    // Create application state
    let app_state = AppState {
        config: config.clone(),
        jwt_service,
        token_service,
        user_service,
    };

    // Compliant CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(config.frontend_url.parse::<axum::http::HeaderValue>()?)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_credentials(true);

    // Create router with layers
    let app = create_router(app_state)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_cookies::CookieManagerLayer::new());

    // Start server
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("✅ Server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}
