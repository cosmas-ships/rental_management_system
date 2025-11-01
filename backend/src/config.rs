// src/config.rs

use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub access_token_expiry: i64,
    pub refresh_token_expiry: i64,
    pub host: String,
    pub port: u16,
    pub environment: Environment,
    pub frontend_url: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    Development,
    Production,
}

impl Config {
    pub fn from_env() -> Result<Self, anyhow::Error> {
        dotenvy::dotenv().ok();

        Ok(Config {
            database_url: env::var("DATABASE_URL")?,
            redis_url: env::var("REDIS_URL")?,
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_issuer: env::var("JWT_ISSUER").unwrap_or_else(|_| "auth-backend".to_string()),
            jwt_audience: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "auth-client".to_string()),
            access_token_expiry: env::var("ACCESS_TOKEN_EXPIRY")
                .unwrap_or_else(|_| "900".to_string())
                .parse()?,
            refresh_token_expiry: env::var("REFRESH_TOKEN_EXPIRY")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()?,
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT").unwrap_or_else(|_| "8000".to_string()).parse()?,
            environment: env::var("ENVIRONMENT")
                .unwrap_or_else(|_| "development".to_string())
                .parse::<Environment>()
                .unwrap_or(Environment::Development),
            frontend_url: env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3000".to_string()),
        })
    }

    pub fn is_production(&self) -> bool {
        self.environment == Environment::Production
    }

    pub fn is_development(&self) -> bool {
        self.environment == Environment::Development
    }

    /// Get the server address as a string
    pub fn server_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Get log level based on environment
    pub fn log_level(&self) -> &str {
        match self.environment {
            Environment::Development => "debug",
            Environment::Production => "info",
        }
    }

    /// Check if debug mode should be enabled
    pub fn debug_enabled(&self) -> bool {
        self.is_development()
    }
}

impl Environment {
    pub fn as_str(&self) -> &str {
        match self {
            Environment::Development => "development",
            Environment::Production => "production",
        }
    }
}

impl std::str::FromStr for Environment {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "development" => Ok(Environment::Development),
            "production" => Ok(Environment::Production),
            _ => Err(anyhow::anyhow!("Invalid environment: {}", s)),
        }
    }
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}