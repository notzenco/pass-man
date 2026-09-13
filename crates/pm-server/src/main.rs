//! `pm-server` binary: run the self-hostable sync server.

use std::path::PathBuf;

use pm_server::{router, AppState, Db};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pm_server=info,tower_http=info".into()),
        )
        .init();

    let db_path = std::env::var("PM_DB").unwrap_or_else(|_| "pm-server.db".to_string());
    let bind = std::env::var("PM_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let db = Db::open(&PathBuf::from(&db_path))?;
    let app = router(AppState::new(db));
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, %db_path, "pass-man sync server listening");
    axum::serve(listener, app).await?;
    Ok(())
}
