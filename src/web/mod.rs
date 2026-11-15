use std::net::{Ipv4Addr, SocketAddr};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
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
    axum::serve(listener, router(bound.port()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|err| Error::new(err.to_string()))?;
    Ok(())
}

pub fn router(port: u16) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/topology", get(api_topology))
        .route("/api/ports", get(api_ports))
        .route("/api/outbound", get(api_outbound))
        .layer(middleware::from_fn(move |req, next| async move {
            guard(port, req, next).await
        }))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::new())
}

pub fn host_allowed(host: &str, port: u16) -> bool {
    let host = host.trim();
    [
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
    .iter()
    .any(|expected| host.eq_ignore_ascii_case(expected))
}

pub fn origin_allowed(origin: &str, port: u16) -> bool {
    let origin = origin.trim().trim_end_matches('/');
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://localhost:{port}"),
        format!("http://[::1]:{port}"),
        format!("https://127.0.0.1:{port}"),
        format!("https://localhost:{port}"),
        format!("https://[::1]:{port}"),
    ]
    .iter()
    .any(|expected| origin.eq_ignore_ascii_case(expected))
}

async fn guard(port: u16, req: Request<Body>, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !host_allowed(host, port) {
        return (
            StatusCode::FORBIDDEN,
            "whose: Host is not this loopback listener",
        )
            .into_response();
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !origin_allowed(origin, port) {
            return (
                StatusCode::FORBIDDEN,
                "whose: Origin is not this loopback listener",
            )
                .into_response();
        }
    }
    next.run(req).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_origin_must_be_loopback_with_the_bound_port() {
        assert!(host_allowed("127.0.0.1:7070", 7070));
        assert!(host_allowed("localhost:7070", 7070));
        assert!(host_allowed("[::1]:7070", 7070));
        assert!(!host_allowed("evil.example:7070", 7070));
        assert!(!host_allowed("127.0.0.1:80", 7070));
        assert!(!host_allowed("127.0.0.1", 7070));
        assert!(origin_allowed("http://127.0.0.1:7070", 7070));
        assert!(origin_allowed("http://[::1]:7070", 7070));
        assert!(!origin_allowed("http://evil.example:7070", 7070));
        assert!(!origin_allowed("", 7070));
    }
}
