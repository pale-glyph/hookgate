use std::{collections::HashMap, fs, sync::Arc};

use anyhow::Context;
use axum::{
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hmac::{Hmac, Mac};
use redis::AsyncCommands;
use serde::Deserialize;
use sha2::Sha256;
use tracing::{error, info, warn};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
struct Config {
    #[serde(default = "default_bind")]
    bind: String,
    redis_url: String,
    hooks: Vec<HookConfig>,
}

fn default_bind() -> String {
    "0.0.0.0:3000".to_string()
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
enum SignatureScheme {
    /// GitHub-style HMAC-SHA256: `X-Hub-Signature-256: sha256=<hex>` (default)
    #[default]
    Hub,
    /// Svix HMAC-SHA256: `svix-id`, `svix-timestamp`, `svix-signature` headers
    Svix,
}

#[derive(Debug, Deserialize)]
struct HookConfig {
    source: String,
    stream: String,
    /// Optional HMAC-SHA256 secret. Interpretation depends on `scheme`.
    secret: Option<String>,
    #[serde(default)]
    scheme: SignatureScheme,
}

#[derive(Clone)]
struct AppState {
    redis: redis::aio::ConnectionManager,
    routes: Arc<HashMap<String, RouteEntry>>,
}

#[derive(Clone)]
struct RouteEntry {
    stream: String,
    secret: Option<String>,
    scheme: SignatureScheme,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hookgate=info".parse()?),
        )
        .init();

    info!("hookgate starting");

    let config_path =
        std::env::var("HOOKGATE_CONFIG").unwrap_or_else(|_| "hookgate.yaml".to_string());
    let config_str = fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read config file: {config_path}"))?;
    let config: Config =
        serde_yaml::from_str(&config_str).context("Failed to parse config file")?;
    info!("Configuration loaded");

    let redis_client =
        redis::Client::open(config.redis_url.as_str()).context("Invalid Redis URL")?;
    let redis_mgr = redis::aio::ConnectionManager::new(redis_client)
        .await
        .context("Failed to connect to Redis")?;
    info!("Connected to Redis");

    let routes: HashMap<String, RouteEntry> = config
        .hooks
        .into_iter()
        .map(|h| {
            (
                h.source,
                RouteEntry {
                    stream: h.stream,
                    secret: h.secret,
                    scheme: h.scheme,
                },
            )
        })
        .collect();

    info!("Registered {} webhook route(s)", routes.len());

    let state = AppState {
        redis: redis_mgr,
        routes: Arc::new(routes),
    };

    let app = Router::new()
        .route("/{*path}", post(webhook_handler))
        // Reject bodies larger than 1 MiB to prevent resource exhaustion.
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind)
        .await
        .with_context(|| format!("Failed to bind to {}", config.bind))?;
    info!("Listening on {}", config.bind);
    info!("Ready to accept webhook requests");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn webhook_handler(
    OriginalUri(uri): OriginalUri,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path = uri.path().to_string();

    let route = match state.routes.get(&path) {
        Some(r) => r.clone(),
        None => {
            warn!("Webhook received for unknown route");
            return StatusCode::NOT_FOUND;
        }
    };

    if let Some(secret) = &route.secret {
        let verified = match route.scheme {
            SignatureScheme::Hub => {
                match headers
                    .get("x-hub-signature-256")
                    .and_then(|v| v.to_str().ok())
                {
                    Some(sig) => verify_hub_signature(secret, &body, sig),
                    None => {
                        warn!("Webhook received with missing signature header");
                        return StatusCode::UNAUTHORIZED;
                    }
                }
            }
            SignatureScheme::Svix => {
                let msg_id = headers.get("svix-id").and_then(|v| v.to_str().ok());
                let timestamp = headers.get("svix-timestamp").and_then(|v| v.to_str().ok());
                let signatures = headers.get("svix-signature").and_then(|v| v.to_str().ok());
                match (msg_id, timestamp, signatures) {
                    (Some(id), Some(ts), Some(sigs)) => {
                        verify_svix_signature(secret, id, ts, &body, sigs)
                    }
                    _ => {
                        warn!("Webhook received with missing signature headers");
                        return StatusCode::UNAUTHORIZED;
                    }
                }
            }
        };
        if !verified {
            warn!("Webhook received with invalid signature");
            return StatusCode::UNAUTHORIZED;
        }
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let payload = match std::str::from_utf8(&body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            warn!("Webhook received with non-UTF8 body");
            return StatusCode::UNPROCESSABLE_ENTITY;
        }
    };

    let mut conn = state.redis.clone();
    let result: redis::RedisResult<String> = conn
        .xadd(
            &route.stream,
            "*",
            &[
                ("source", path.as_str()),
                ("content_type", content_type.as_str()),
                ("payload", payload.as_str()),
            ],
        )
        .await;

    match result {
        Ok(_) => {
            info!("Webhook received and forwarded");
            StatusCode::OK
        }
        Err(_) => {
            error!("Failed to forward webhook message");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

/// Constant-time HMAC-SHA256 verification against a `sha256=<hex>` signature
/// (GitHub / Clerk style: `X-Hub-Signature-256: sha256=<hex>`).
fn verify_hub_signature(secret: &str, body: &[u8], signature: &str) -> bool {
    let hex_str = match signature.strip_prefix("sha256=") {
        Some(s) => s,
        None => return false,
    };
    let sig_bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Svix webhook signature verification.
///
/// The secret may optionally be prefixed with `whsec_`; the remainder is
/// standard base64. The signed content is `"{svix-id}.{svix-timestamp}.{body}"`.
/// The `svix-signature` header contains one or more `v1,<base64>` tokens
/// separated by spaces; the payload is accepted if any token matches.
/// Timestamps more than 5 minutes from the current time are rejected to
/// prevent replay attacks.
fn verify_svix_signature(
    secret: &str,
    msg_id: &str,
    timestamp: &str,
    body: &[u8],
    signatures: &str,
) -> bool {
    let b64 = secret.strip_prefix("whsec_").unwrap_or(secret);
    let key = match STANDARD.decode(b64) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let ts: i64 = match timestamp.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Use checked arithmetic: a crafted large-negative timestamp would cause
    // `now - ts` to overflow i64 and wrap to a small value, bypassing the
    // replay-protection window. Treat overflow as rejection.
    let diff = match now.checked_sub(ts) {
        Some(d) => d.saturating_abs(),
        None => return false,
    };
    if diff > 300 {
        return false;
    }

    // Use constant-time verify_slice for each candidate signature to prevent
    // timing side-channel attacks. A fresh MAC instance is created per token
    // so that verify_slice (which consumes the instance) can be reused.
    signatures
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix("v1,"))
        .filter_map(|sig| STANDARD.decode(sig).ok())
        .any(|sig_bytes| {
            let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key size");
            mac.update(format!("{msg_id}.{timestamp}.").as_bytes());
            mac.update(body);
            mac.verify_slice(&sig_bytes).is_ok()
        })
}
