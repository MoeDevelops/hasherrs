use axum::{routing::post, Router};
use tokio::net::TcpListener;
mod routes;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/argon2", post(routes::argon2::hash))
        .route("/scrypt", post(routes::scrypt::hash));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
