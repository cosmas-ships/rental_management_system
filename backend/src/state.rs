use crate::{
    config::Config,
    services::{jwt::JwtService, token::TokenService, users::UserService},
};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub jwt_service: JwtService,
    pub token_service: TokenService,
    pub user_service: UserService,
}