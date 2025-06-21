use axum::extract::State;
use axum::{http::StatusCode, response::IntoResponse, Json};
use bcrypt::hash_with_salt;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use utoipa::OpenApi;

use crate::middleware::auth::Claims;
use crate::models::{LoginRequest, LoginResponse, Role};
use crate::AppState;

const JWT_SALT: &[u8; 16] = b"your-secret-salt"; // Use a secure key in production

#[derive(OpenApi)]
#[openapi(paths(login), components(schemas(LoginRequest, LoginResponse)))]
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
pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let users = state.users.lock().unwrap();

    //Check if the user exist and the password matches
    let user = users.iter().find(|u| u.username == payload.username);

    if user.is_none()
        || bcrypt::verify(payload.password.as_bytes(), &user.unwrap().password).ok() != Some(true)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid credentilas"})),
        )
            .into_response();
    }

    let claims = Claims {
        sub: payload.username.clone(),
        role: user.unwrap().role.clone(),
        exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your-secret-key".as_ref()),
    )
    .unwrap();

    return (StatusCode::OK, Json(LoginResponse { token })).into_response();
}

#[utoipa::path(
    post,
    path = "/register",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "User regisered successfully", body = LoginResponse),
        (status = 401, description = "Bad request")
    )
)]
pub async fn register(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    // In production, verify against a database
    if payload.username.is_empty() || payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Username and password are required"})),
        )
            .into_response();
    }

    // Here you would typically hash the password and save the user to a database
    let hashed_password =
        hash_with_salt(payload.password.as_bytes(), bcrypt::DEFAULT_COST, *JWT_SALT).unwrap();

    let mut users = state.users.lock().unwrap();

    let new_user = crate::models::User {
        id: users.len() as i32 + 1,
        username: payload.username,
        password: hashed_password.to_string(),
        role: Role::User,
    };

    users.push(new_user);

    // Simulate successful registration
    (
        StatusCode::CREATED,
        Json(json!({"message": "User registered successfully"})),
    )
        .into_response()
}