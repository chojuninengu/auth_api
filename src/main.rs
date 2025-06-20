use axum::{
    routing::{get, post},
    Router,
};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use tower_http::cors::CorsLayer;

pub mod models;
pub mod routes;
pub mod middleware;

use crate::{routes::{auth, protected}, middleware::auth::auth_middleware};

#[tokio::main]
async fn main() {
    #[derive(OpenApi)]
    #[openapi(
        info(title = "Auth API", description = "A simple auth API"),
        paths(
            auth::login,
            auth::register,
            protected::admin_route
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

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/login", post(auth::login))
        .route("/register", post(auth::register))
        .route("/admin", get(protected::admin_route))
        // .layer(axum::middleware::from_fn::<_, _>(auth_middleware))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
