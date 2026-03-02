//! SimpleProxy - A local proxy tool that intercepts specific URLs
//! and replaces content or redirects based on configurable rules.

mod cert;
mod config;
mod proxy;
mod rule_engine;
mod system_proxy;
mod upstream;
mod web;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "simple-proxy",
    version,
    about = "A configurable local HTTP/HTTPS proxy server"
)]
struct Args {
    /// Path to the config JSON file
    #[arg(short, long, default_value = "config.json", env = "CONFIG_FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config_path = if args.config.is_absolute() {
        args.config.clone()
    } else {
        std::env::current_dir()
            .expect("Failed to get current directory")
            .join(&args.config)
    };

    // Load configuration (creates default if missing, uses defaults on invalid JSON)
    let config_mgr = match config::ConfigManager::load(&config_path) {
        Ok(mgr) => mgr,
        Err(e) => {
            error!("Failed to load config: {}. Using defaults.", e);
            config::ConfigManager::from_default(&config_path)
        }
    };

    let cfg = config_mgr.get();
    let rules_path = config_mgr.rules_path();

    info!("Config file: {}", config_path.display());
    info!("Rules file: {}", rules_path.display());

    // Load rules (creates default empty rules file if missing)
    let rule_engine = match rule_engine::RuleEngine::new(&rules_path) {
        Ok(engine) => Arc::new(engine),
        Err(e) => {
            error!("Failed to load rules: {}. Starting with empty rules.", e);
            Arc::new(rule_engine::RuleEngine::empty(&rules_path))
        }
    };

    // Start file watcher for hot reload
    let watcher_engine = Arc::clone(&rule_engine);
    let watcher_path = rules_path.clone();
    if let Err(e) = rule_engine::start_watcher(watcher_engine, watcher_path) {
        error!("Failed to start rules file watcher: {}", e);
    }

    // Create system proxy manager (supports runtime toggle)
    let sys_proxy_mgr = system_proxy::SystemProxyManager::new(
        "127.0.0.1",
        cfg.port,
        cfg.system_proxy,
    );

    // Initialize certificate manager for HTTPS MITM
    let config_dir = config_path.parent().unwrap_or(std::path::Path::new("."));
    let cert_mgr = match cert::CertManager::new(config_dir) {
        Ok(mgr) => Arc::new(mgr),
        Err(e) => {
            error!("Failed to initialize certificate manager: {}", e);
            error!("HTTPS interception will not be available.");
            panic!("Certificate manager initialization failed: {}", e);
        }
    };

    // Check if CA certificate is installed in system trust store
    cert_mgr.check_ca_trusted();

    // Start web dashboard
    let web_cfg = Arc::clone(&config_mgr);
    let web_engine = Arc::clone(&rule_engine);
    let web_certs = Arc::clone(&cert_mgr);
    let web_sys_proxy = Arc::clone(&sys_proxy_mgr);
    let web_port = cfg.web_port;
    tokio::spawn(async move {
        if let Err(e) = web::start_web_server(web_cfg, web_engine, web_certs, web_sys_proxy, web_port).await {
            error!("Web dashboard error: {}", e);
        }
    });

    // Auto-open browser
    if cfg.auto_open_browser {
        let url = format!("http://127.0.0.1:{}", cfg.web_port);
        info!("[Web] Opening dashboard: {}", url);
        if let Err(e) = open::that(&url) {
            error!("Failed to open browser: {}", e);
        }
    }

    // Start proxy server
    let server = proxy::ProxyServer::new(
        Arc::clone(&rule_engine),
        Arc::clone(&config_mgr),
        Arc::clone(&cert_mgr),
        cfg.port,
    );

    // Handle shutdown signals
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("\nShutting down...");
    };

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                error!("Proxy server error: {}", e);
            }
        }
        _ = shutdown => {}
    }

    // Ensure system proxy is restored before exit
    if sys_proxy_mgr.is_enabled() {
        info!("Restoring system proxy settings before exit...");
    }
    drop(sys_proxy_mgr);
    info!("Goodbye!");
}
