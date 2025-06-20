use axum::{
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use jsonwebtoken::{encode, Header};
use serde_json::json;
use utoipa::OpenApi;
use bcrypt::{hash, DEFAULT_COST};

use crate::models::{LoginRequest, LoginResponse, Role, RegisterRequest, RegisterResponse};
use crate::middleware::auth::Claims;
use crate::config::jwt;

#[derive(OpenApi)]
#[openapi(
    paths(login, register),
    components(schemas(LoginRequest, LoginResponse, RegisterRequest, RegisterResponse))
)]
pub struct AuthApi;

#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    )
)]

pub async fn login(Json(payload): Json<LoginRequest>) -> impl IntoResponse {
    // In production, verify against a database
    if payload.username == "admin" && payload.password == "password" {
        let claims = Claims {
            sub: payload.username.clone(),
            role: Role::Admin,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &jwt::get_encoding_key(),
        )
        .unwrap();

        return (
            StatusCode::OK,
            Json(LoginResponse { token }),
        ).into_response();
    } else if payload.username == "user" && payload.password == "password" {
        // Also allow regular user login for testing purposes
        let claims = Claims {
            sub: payload.username.clone(),
            role: Role::User,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &jwt::get_encoding_key(),
        )
        .unwrap();

        return (
            StatusCode::OK,
            Json(LoginResponse { token }),
        ).into_response();
    }

    (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid credentials"}))).into_response()
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful", body = RegisterResponse),
        (status = 400, description = "Invalid registration data")
    )
)]
pub async fn register(Json(payload): Json<RegisterRequest>) -> impl IntoResponse {
    // Validate the registration data
    if payload.username.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Username cannot be empty"}))
        ).into_response();
    }

    if payload.password.is_empty() || payload.password.len() < 6 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Password must be at least 6 characters"}))
        ).into_response();
    }

    if payload.password != payload.confirm_password {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Passwords do not match"}))
        ).into_response();
    }

    // In a real application, check if username already exists in database
    // For this example, we'll simulate a successful registration with a new user ID
    
    // Hash the password - in production this would be stored in a database
    let _hashed_password = match hash(payload.password, DEFAULT_COST) {
        Ok(hashed) => hashed,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to hash password"}))
            ).into_response();
        }
    };

    // Generate a new user ID (in production, this would come from the database)
    let user_id = 2; // For demonstration purposes

    // In a real application, we would store the new user with role "User" in the database
    // For this example, we'll just return a successful response
    // The role will be assigned when they log in
    
    // Return success response
    (
        StatusCode::CREATED,
        Json(RegisterResponse {
            message: format!("User {} registered successfully with role User", payload.username),
            user_id,
        })
    ).into_response()
}
