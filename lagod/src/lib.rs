pub mod config;
pub mod shutdown;
pub mod substrate;

use config::DaemonConfig;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

/// Bind lagod's substrate-plane gRPC server (`lago.v1.LagoSubstrate`) on
/// a Unix-domain socket and serve it until `shutdown` resolves.
///
/// Stage 6 (June 2026): this is the entry point lifed's `lago-proxy`
/// reaches in Topology B. lago-proxy dials a UDS (`LagoProxy::connect`
/// → `UnixStream::connect`), so the TCP `LagoSubstrate` mounted on the
/// gRPC port (BRO-1017) is unreachable from lifed — lifed needs a
/// *socket*. This binds the SAME service over a UDS, sharing the one
/// `Arc<dyn Journal>` the TCP gRPC + HTTP planes already drive. Mirrors
/// arcand's `serve_substrate_uds` (`crates/arcan/arcan/src/main.rs`):
/// ensure the parent dir exists, unlink any stale socket, bind, then
/// serve via `serve_with_incoming_shutdown`.
///
/// The shutdown trigger is injected rather than hard-wired to
/// `shutdown::shutdown_signal()` so the bind→serve→cleanup path can be
/// exercised by an integration test with a `oneshot` (the daemon passes
/// the real signal future at its single call site below).
///
/// `#[doc(hidden)] pub` purely so `tests/topology_b_e2e_lago.rs` can
/// drive lagod's OWN serve path (rather than a hand-rolled copy of it);
/// not part of the supported API surface.
#[doc(hidden)]
pub async fn serve_substrate_uds<S>(
    socket_path: PathBuf,
    journal: Arc<dyn lago_core::Journal>,
    shutdown: S,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: Future<Output = ()> + Send + 'static,
{
    let listener = bind_substrate_uds(&socket_path)?;
    serve_substrate_uds_on(socket_path, listener, journal, shutdown).await
}

/// Bind the substrate-plane Unix socket: ensure the parent dir exists,
/// unlink any stale socket file (a crashed predecessor leaves one
/// behind and a fresh `bind()` would fail with AddrInUse), then bind.
///
/// Split from the serve future so `run()` can bind EAGERLY: a failed
/// `--uds-socket` is an explicitly requested plane and must fail the
/// daemon fast — not log-and-continue inside a spawned task while the
/// TCP/HTTP planes keep serving with the substrate plane silently dead.
#[doc(hidden)]
pub fn bind_substrate_uds(
    socket_path: &std::path::Path,
) -> Result<tokio::net::UnixListener, Box<dyn std::error::Error>> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create parent dir {}: {e}", parent.display()))?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .map_err(|e| format!("unlink stale socket {}: {e}", socket_path.display()))?;
    }

    let listener = tokio::net::UnixListener::bind(socket_path)
        .map_err(|e| format!("bind {}: {e}", socket_path.display()))?;

    info!(
        socket = %socket_path.display(),
        "lago substrate-plane gRPC listening (lago.v1.LagoSubstrate over UDS)"
    );
    Ok(listener)
}

/// Serve `lago.v1.LagoSubstrate` on an already-bound listener until
/// `shutdown` resolves, then best-effort remove the socket file.
#[doc(hidden)]
pub async fn serve_substrate_uds_on<S>(
    socket_path: PathBuf,
    listener: tokio::net::UnixListener,
    journal: Arc<dyn lago_core::Journal>,
    shutdown: S,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: Future<Output = ()> + Send + 'static,
{
    use lago_substrate_proto::lago::v1::lago_substrate_server::LagoSubstrateServer;

    let service = substrate::SubstrateService::new(journal);
    let incoming = tokio_stream::wrappers::UnixListenerStream::new(listener);

    tonic::transport::Server::builder()
        .add_service(LagoSubstrateServer::new(service))
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(|e| format!("substrate UDS serve: {e}"))?;

    // Best-effort cleanup of the socket file on graceful shutdown.
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

/// Run the Lago daemon with the given configuration.
///
/// When `uds_socket` is `Some(path)`, an additional substrate-plane
/// gRPC server (`lago.v1.LagoSubstrate`) is bound on that Unix-domain
/// socket alongside the TCP gRPC + HTTP servers — this is the surface
/// lifed's `lago-proxy` dials under Topology B (Stage 6). When `None`,
/// only the TCP gRPC + HTTP planes run (the standalone / `lago serve`
/// behavior).
pub async fn run(
    config: DaemonConfig,
    uds_socket: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!(?config, ?uds_socket, "starting lagod");

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

    // BRO-1017: Substrate-plane service. Topology B's lifed (via
    // lago-proxy) dials this for `Append` + `ListNamespaces`.
    // Mounted alongside IngestService on the same gRPC port so a
    // single client connection can multiplex both services.
    let substrate_service =
        substrate::SubstrateService::new(journal.clone() as Arc<dyn lago_core::Journal>);
    let substrate_grpc =
        lago_substrate_proto::lago::v1::lago_substrate_server::LagoSubstrateServer::new(
            substrate_service,
        );

    info!(%grpc_addr, "starting gRPC server");
    let grpc_handle = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(grpc_service)
            .add_service(substrate_grpc)
            .serve(grpc_addr)
            .await
            .map_err(|e| format!("gRPC server error: {e}"))
    });

    // --- Optional substrate-plane UDS server (Topology B, Stage 6)
    //
    // lifed's `lago-proxy` dials `lago.v1.LagoSubstrate` over a Unix
    // socket (not TCP). When `--uds-socket <PATH>` / `LAGO_UDS_SOCKET`
    // is set, bind that service on the socket using the SAME journal as
    // the TCP gRPC + HTTP planes. Additive — the standalone TCP/HTTP
    // daemon is unchanged when the socket is absent.
    let uds_handle = match uds_socket {
        Some(socket_path) => {
            // Bind eagerly (cross-review finding): the UDS is the only
            // plane Topology B consumes — a bind failure must fail the
            // daemon NOW with the real error, not surface 30 seconds
            // later as the stack entrypoint's generic probe timeout
            // while TCP/HTTP keep serving a substrate-dead lagod.
            let listener = bind_substrate_uds(&socket_path)?;
            let uds_journal = journal.clone() as Arc<dyn lago_core::Journal>;
            Some(tokio::spawn(async move {
                if let Err(e) = serve_substrate_uds_on(
                    socket_path,
                    listener,
                    uds_journal,
                    shutdown::shutdown_signal(),
                )
                .await
                {
                    tracing::error!(error = %e, "substrate-plane UDS server exited with error");
                }
            }))
        }
        None => None,
    };

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
        manifest_cache: tokio::sync::RwLock::new(std::collections::HashMap::new()),
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

    // Abort the servers. The UDS server (if running) drains itself via
    // its own `serve_with_incoming_shutdown(shutdown_signal())`, so it
    // observes the same SIGTERM/SIGINT and exits gracefully; we still
    // await its handle so the socket-file cleanup runs before we return.
    grpc_handle.abort();
    http_handle.abort();

    // Wait for tasks to finish (they may have already been aborted)
    let _ = grpc_handle.await;
    let _ = http_handle.await;
    if let Some(handle) = uds_handle {
        let _ = handle.await;
    }

    info!("lagod stopped");
    Ok(())
}
