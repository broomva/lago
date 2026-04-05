/// Returns a future that resolves when the process receives a shutdown signal
/// (SIGINT on all platforms, plus SIGTERM on Unix).
///
/// This is used to coordinate graceful shutdown of the gRPC and HTTP servers.
pub async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("received SIGINT (Ctrl+C)");
            },
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            },
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for Ctrl+C");
        tracing::info!("received Ctrl+C");
    }
}
