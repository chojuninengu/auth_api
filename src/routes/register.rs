use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize};
use crate::models::user::{Role, User};
use argon2::{Argon2, PasswordHasher};
use password_hash::{SaltString};
use rand::rngs::OsRng;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
}

pub async fn register(Json(payload): Json<RegisterRequest>) -> impl IntoResponse {
    if payload.password != payload.confirm_password {
        return (StatusCode::BAD_REQUEST, "Passwords do not match").into_response();
    }

    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    let user = User {
        id: Uuid::new_v4().as_u128() as i32,
        username: payload.username,
        password: password_hash,
        role: Role::User,
    };
    println!("User registered: {:?}", user);
    // In a real app, save to DB here.

    (StatusCode::CREATED, "User registered").into_response()
}