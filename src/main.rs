use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use rust_admin_api::admin::AppConfig;
use rust_admin_api::auth::verifier::AuthVerifier;
use rust_admin_api::proxy::gateway::{Gateway, GatewayState};
use rust_admin_api::proxy::router::RouteTable;
use rust_admin_api::proxy::status::RouteInfo;
use rust_admin_api::{admin, config, db};

#[derive(Parser)]
#[command(name = "rust-admin-api", about = "Admin panel with Pingora reverse proxy and auth gateway")]
struct Cli {
    /// Path to config.toml
    #[arg(long, default_value = "/etc/rust-admin-api/config.toml")]
    config: PathBuf,

    /// Web server port (overrides config file)
    #[arg(long)]
    web_port: Option<u16>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Load config from file, falling back to defaults
    let cfg = if cli.config.exists() {
        match config::Config::load(&cli.config) {
            Ok(c) => {
                tracing::info!(path = %cli.config.display(), "Loaded config");
                c
            }
            Err(e) => {
                tracing::warn!("Failed to load config: {e}, using defaults");
                config::Config::default()
            }
        }
    } else {
        tracing::info!("No config found at {}, using defaults", cli.config.display());
        config::Config::default()
    };

    // CLI --web-port overrides config file
    let listen_addr = if let Some(port) = cli.web_port {
        format!("0.0.0.0:{port}")
    } else {
        cfg.server.listen_addr.clone()
    };

    let jwt_secret = config::resolve_jwt_secret(&cfg.auth);

    let app_config = AppConfig {
        cookie_domain: cfg.auth.cookie_domain.clone(),
        cookie_secure: cfg.auth.cookie_secure,
        jwt_secret: jwt_secret.clone(),
    };

    let database = db::init_db(&cfg.database.path);

    // Build proxy route info for dashboard display
    let proxy_routes: Vec<RouteInfo> = cfg
        .proxy
        .routes
        .iter()
        .map(|r| RouteInfo {
            host: r.host.clone(),
            path_prefix: if r.path_prefix.is_empty() {
                "/".to_string()
            } else {
                r.path_prefix.clone()
            },
            upstream: r.upstream.clone(),
            auth_required: r.auth_required,
        })
        .collect();

    // Start Pingora proxy if enabled
    if cfg.proxy.enabled {
        let route_table = match RouteTable::compile(&cfg.proxy.routes) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Failed to compile proxy routes: {e}");
                std::process::exit(1);
            }
        };

        let verifier = AuthVerifier::new(database.clone(), jwt_secret.clone());
        let login_url = format!("{}/login", cfg.auth.auth_url);

        let gateway_state = Arc::new(GatewayState {
            router: route_table,
            verifier,
            login_url,
        });

        let http_addr = cfg.proxy.http_addr.clone();
        let https_addr = cfg.proxy.https_addr.clone();
        let cert_path = cfg.proxy.cert_path.clone();
        let key_path = cfg.proxy.key_path.clone();

        // Pingora blocks the calling thread — spawn on a dedicated OS thread
        std::thread::spawn(move || {
            let mut server =
                pingora_core::server::Server::new(None).expect("Failed to create Pingora server");
            server.bootstrap();

            let gateway = Gateway {
                state: gateway_state,
            };

            let mut proxy_service =
                pingora_proxy::http_proxy_service(&server.configuration, gateway);

            // Always listen on HTTP
            proxy_service.add_tcp(&http_addr);
            tracing::info!("Pingora proxy HTTP on {http_addr}");

            // Add TLS if cert paths are configured
            if !cert_path.is_empty() && !key_path.is_empty() {
                match proxy_service.add_tls(&https_addr, &cert_path, &key_path) {
                    Ok(_) => tracing::info!("Pingora proxy HTTPS on {https_addr}"),
                    Err(e) => {
                        tracing::error!("Failed to add TLS listener: {e}");
                        std::process::exit(1);
                    }
                }
            }

            server.add_service(proxy_service);
            tracing::info!("Pingora proxy started");
            server.run_forever();
        });
    }

    // Build and start Axum admin panel
    let app = admin::build_router(database, app_config, proxy_routes);

    tracing::info!("Admin panel at http://{listen_addr}");

    let listener = match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {listen_addr}: {e}");
            if e.kind() == std::io::ErrorKind::AddrInUse {
                tracing::error!(
                    "Port already in use. Kill the existing process: ss -tlnp | grep {}",
                    listen_addr.split(':').last().unwrap_or("3000")
                );
            }
            std::process::exit(1);
        }
    };
    axum::serve(listener, app).await.unwrap();
}
