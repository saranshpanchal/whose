use std::net::{Ipv4Addr, SocketAddr};

use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::engine::{list_listening, outbound_report, topology};
use crate::error::{Error, Result};
use crate::model::{ListenReport, OutboundFilter, OutboundReport, QueryOpts, Topology};

const INDEX: &str = include_str!("index.html");

pub async fn serve(port: u16) -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("whose=info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| Error::new(format!("bind {addr}: {err}")))?;
    let bound = listener
        .local_addr()
        .map_err(|err| Error::new(err.to_string()))?;
    eprintln!("whose dashboard http://{bound}");
    axum::serve(listener, router())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|err| Error::new(err.to_string()))?;
    Ok(())
}

pub fn router() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/topology", get(api_topology))
        .route("/api/ports", get(api_ports))
        .route("/api/outbound", get(api_outbound))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new())
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

async fn api_topology() -> std::result::Result<Json<Topology>, (StatusCode, String)> {
    blocking(topology).await.map(Json)
}

async fn api_ports() -> std::result::Result<Json<ListenReport>, (StatusCode, String)> {
    blocking(list_listening).await.map(Json)
}

async fn api_outbound() -> std::result::Result<Json<OutboundReport>, (StatusCode, String)> {
    let report = tokio::task::spawn_blocking(|| {
        outbound_report(&OutboundFilter::default(), &QueryOpts::default())
    })
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(report))
}

async fn blocking<T: Send + 'static>(
    func: fn(&QueryOpts) -> Result<T>,
) -> std::result::Result<T, (StatusCode, String)> {
    tokio::task::spawn_blocking(move || func(&QueryOpts::default()))
        .await
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}
