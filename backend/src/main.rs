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
    // Load configuration first to determine environment
    let config = Config::from_env()?;

    // Initialize tracing with environment-specific log level
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    format!(
                        "auth_backend={},tower_http={},axum={}",
                        config.log_level(),
                        if config.is_production() { "info" } else { "debug" },
                        if config.is_production() { "info" } else { "trace" }
                    )
                    .into()
                }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("🚀 Starting application in {} mode", config.environment);
    tracing::info!("Configuration loaded successfully");

    // Use debug_enabled for conditional debug logging
    if config.debug_enabled() {
        tracing::debug!("Debug mode is enabled");
        tracing::debug!("Database URL: {}", mask_connection_string(&config.database_url));
        tracing::debug!("Redis URL: {}", mask_connection_string(&config.redis_url));
        tracing::debug!("JWT Issuer: {}", config.jwt_issuer);
        tracing::debug!("JWT Audience: {}", config.jwt_audience);
    }

    // Setup database connection pool with environment-specific settings
    let max_connections = if config.is_production() { 20 } else { 10 };
    let db_pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&config.database_url)
        .await?;
    tracing::info!(
        "Database connection established with {} max connections",
        max_connections
    );

    // Run migrations
    // sqlx::migrate!("./migrations").run(&db_pool).await?;
    // tracing::info!("Database migrations completed");

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

    // Environment-specific CORS configuration
    let cors = if config.is_production() {
        // Strict CORS for production
        tracing::info!("Configuring strict CORS for production");
        CorsLayer::new()
            .allow_origin(config.frontend_url.parse::<axum::http::HeaderValue>()?)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .allow_credentials(true)
    } else {
        // More permissive CORS for development
        tracing::info!("Configuring permissive CORS for development");
        CorsLayer::new()
            .allow_origin(config.frontend_url.parse::<axum::http::HeaderValue>()?)
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
            .allow_credentials(true)
    };

    // Create router with layers
    let mut app = create_router(app_state)
        .layer(cors)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_cookies::CookieManagerLayer::new());

    // Add development-specific middleware
    if config.is_development() {
        tracing::info!("Adding development-specific middleware");
        // In development, you might want to add additional debugging layers
        app = app.layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new()
                    .level(tracing::Level::DEBUG))
                .on_response(tower_http::trace::DefaultOnResponse::new()
                    .level(tracing::Level::DEBUG))
        );
    }

    // Start server
    let addr = config.server_address();
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Server listening on {}", addr);
    
    if config.is_production() {
        tracing::warn!("Running in PRODUCTION mode - ensure all security measures are in place");
    } else {
        tracing::info!("Running in DEVELOPMENT mode - debug features enabled");
    }

    tracing::info!("Frontend URL: {}", config.frontend_url);
    tracing::info!(
        "Token expiry - Access: {}s, Refresh: {}s",
        config.access_token_expiry,
        config.refresh_token_expiry
    );

    // Use is_development for additional startup info
    if config.is_development() {
        tracing::info!("Development tips:");
        tracing::info!("  - Check logs for detailed request/response information");
        tracing::info!("  - CORS is configured permissively for local testing");
        tracing::info!("  - Database pool size: {}", max_connections);
    }

    axum::serve(listener, app).await?;

    Ok(())
}

/// Masks sensitive parts of connection strings for safe logging
fn mask_connection_string(conn_str: &str) -> String {
    if let Some(at_pos) = conn_str.find('@') {
        if let Some(protocol_end) = conn_str.find("://") {
            let protocol = &conn_str[..protocol_end + 3];
            let host_and_rest = &conn_str[at_pos..];
            format!("{}***:***{}", protocol, host_and_rest)
        } else {
            "***".to_string()
        }
    } else {
        conn_str.to_string()
    }
}