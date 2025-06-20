use axum::{
    routing::{get, post},
    Router,
    middleware::from_fn,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use tower_http::cors::CorsLayer;
use dotenv::dotenv;

pub mod models;
pub mod routes;
pub mod middleware;
pub mod config;

use crate::{routes::{auth, protected}, middleware::auth::auth_middleware};

#[tokio::main]
async fn main() {
    // Load environment variables from .env file if present
    dotenv().ok();

    #[derive(OpenApi)]
    #[openapi(
        info(title = "Auth API", description = "A simple auth API"),
        paths(
            auth::login,
            auth::register,
            protected::admin_route,
            protected::user_route
        ),
        components(schemas(
           models::User,
           models::Role,
           models::LoginRequest,
           models::LoginResponse,
           models::RegisterRequest,
           models::RegisterResponse
        ))
    )]
    struct ApiDoc;

    // Public routes don't require authentication
    let public_routes = Router::new()
        .route("/login", post(auth::login))
        .route("/register", post(auth::register))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()));

    // Protected routes require authentication
    let protected_routes = Router::new()
        .route("/admin", get(protected::admin_route))
        .route("/user", get(protected::user_route))
        .layer(from_fn(auth_middleware));

    // Combine public and protected routes into a single router
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
