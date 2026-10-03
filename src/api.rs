//! REST control API: /status /ip /rotate.

use std::sync::Arc;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::backend::BackendRouter;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub router: Arc<BackendRouter>,
    pub config: Config,
}

impl AppState {
    pub fn new(router: Arc<BackendRouter>, config: Config) -> Self {
        Self { router, config }
    }
}

#[derive(Deserialize, Default)]
pub struct RotateQuery {
    pub force: Option<bool>,
}

pub async fn run(
    addr: std::net::SocketAddr,
    state: AppState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/status", get(get_status))
        .route("/ip", get(get_ip))
        .route("/rotate", get(trigger_rotate).post(trigger_rotate))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("REST API on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let backends: Vec<String> = (0..state.router.len())
        .map(|_| "backend".to_string())
        .collect();
    Json(json!({
        "status": "online",
        "identities": state.config.identities,
        "backends": state.config.backends,
        "backend_count": backends.len(),
        "rotate_every_reqs": state.config.rotate_every_reqs,
        "rotate_mins": state.config.rotate_mins,
    }))
}

async fn get_ip(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({
        "identities": state.config.identities.len(),
        "note": "per-identity exit IP: curl -x socks5h://<identity> http://lumtest.com/myip.json",
    }))
}

async fn trigger_rotate(
    State(state): State<AppState>,
    Query(_q): Query<RotateQuery>,
) -> impl IntoResponse {
    state.router.rotate_all().await;
    (StatusCode::OK, Json(json!({"status": "rotated"})))
}
