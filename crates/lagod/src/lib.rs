pub mod config;
pub mod shutdown;

use config::DaemonConfig;
use std::sync::Arc;
use tracing::info;

/// Run the Lago daemon with the given configuration.
pub async fn run(config: DaemonConfig) -> Result<(), Box<dyn std::error::Error>> {
    info!(?config, "starting lagod");

    // --- Ensure data directory exists
    std::fs::create_dir_all(&config.data_dir)?;

    // --- Load policy engine
    let (policy_engine, rbac_manager, hook_runner) = if config.policy_path.exists() {
        let policy_config = lago_policy::PolicyConfig::load(&config.policy_path)?;
        let (engine, rbac_mgr, runner) = policy_config.into_engine();
        info!(
            rules = engine.rules().len(),
            roles = rbac_mgr.roles().len(),
            hooks = runner.hooks().len(),
            path = %config.policy_path.display(),
            "policy engine loaded"
        );
        (
            Some(Arc::new(engine)),
            Some(Arc::new(tokio::sync::RwLock::new(rbac_mgr))),
            Some(Arc::new(runner)),
        )
    } else {
        info!(
            path = %config.policy_path.display(),
            "no policy file found, running without policy enforcement"
        );
        (None, None, None)
    };

    // --- Open the redb journal
    let db_path = config.data_dir.join("journal.redb");
    let journal = lago_journal::RedbJournal::open(&db_path)?;
    let journal = Arc::new(journal);
    info!(path = %db_path.display(), "journal opened");

    // --- Open the blob store
    let blobs_path = config.data_dir.join("blobs");
    let blob_store = lago_store::BlobStore::open(&blobs_path)?;
    let blob_store = Arc::new(blob_store);
    info!(path = %blobs_path.display(), "blob store opened");

    // --- Start gRPC server
    let grpc_addr: std::net::SocketAddr = format!("0.0.0.0:{}", config.grpc_port).parse()?;
    let ingest_server = lago_ingest::IngestServer::new(journal.clone());
    let grpc_service =
        lago_ingest::proto::ingest_service_server::IngestServiceServer::new(ingest_server);

    info!(%grpc_addr, "starting gRPC server");
    let grpc_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(grpc_service)
            .serve(grpc_addr)
            .await
            .map_err(|e| format!("gRPC server error: {e}"))
    });

    // --- Configure auth layer (optional)
    let jwt_secret = config
        .auth
        .jwt_secret
        .clone()
        .or_else(|| std::env::var("LAGO_JWT_SECRET").ok());

    let auth = if let Some(secret) = jwt_secret {
        let session_map = Arc::new(lago_auth::SessionMap::new(journal.clone()));
        session_map.rebuild().await?;
        info!("auth middleware enabled (JWT shared secret)");
        Some(Arc::new(lago_auth::AuthLayer {
            jwt_secret: secret,
            session_map,
        }))
    } else {
        info!("auth middleware disabled (no JWT secret configured)");
        None
    };

    // --- Create rate limiter for public endpoints
    let rate_limiter = Arc::new(lago_api::rate_limit::RateLimiter::new(
        lago_api::rate_limit::RateLimitConfig::default(),
    ));
    info!("rate limiter enabled (1000 req/min per IP)");

    // --- Install Prometheus metrics recorder
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let prometheus_handle = recorder.handle();
    // Install as the global metrics recorder. If another recorder is already
    // installed (e.g. in tests), this silently fails — that's fine.
    let _ = metrics::set_global_recorder(recorder);
    info!("prometheus metrics recorder installed");

    // --- Start HTTP server
    let http_addr: std::net::SocketAddr = format!("0.0.0.0:{}", config.http_port).parse()?;
    let state = lago_api::AppState {
        journal: journal.clone() as Arc<dyn lago_core::Journal>,
        blob_store: blob_store.clone(),
        data_dir: config.data_dir.clone(),
        started_at: std::time::Instant::now(),
        auth,
        policy_engine,
        rbac_manager,
        hook_runner,
        rate_limiter: Some(rate_limiter),
        prometheus_handle,
    };
    let app = lago_api::build_router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind(http_addr).await?;

    info!(%http_addr, "starting HTTP server");
    let http_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|e| format!("HTTP server error: {e}"))
    });

    info!("lagod is ready");

    // --- Wait for shutdown signal
    shutdown::shutdown_signal().await;
    info!("shutdown signal received");

    // Abort both servers
    grpc_handle.abort();
    http_handle.abort();

    // Wait for tasks to finish (they may have already been aborted)
    let _ = grpc_handle.await;
    let _ = http_handle.await;

    info!("lagod stopped");
    Ok(())
}
