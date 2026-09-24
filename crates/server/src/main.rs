//! The Authenc server binary.
//!
//! Deliberately thin: parse the command, load configuration, wire the
//! application together, and either run it or perform a one-off task.
//! Everything it composes lives in the library half of this crate, which is
//! what the integration tests exercise.

use std::sync::Arc;

use authenc_server::{
    AppState, Config,
    cli::{Cli, Command},
    http, telemetry,
};
use clap::Parser;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let config = Config::load()?;
    telemetry::init(&config.telemetry)?;

    let db = authenc_identity::connect(&config.db_config()).await?;
    let hasher = authenc_identity::PasswordHasher::new();
    let mailer = build_mailer(&config)?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Migrate => {
            authenc_identity::migrate(&db).await?;
        }

        Command::Seed {
            realm,
            username,
            email,
            password,
        } => {
            authenc_identity::migrate(&db).await?;
            authenc_server::cli::seed(&db, &hasher, &realm, &username, &email, &password).await?;
        }

        Command::Purge { audit_older_than } => {
            authenc_server::cli::purge(&db, audit_older_than).await?;
        }

        Command::GenerateMasterKey => {
            let key = authenc_identity::MasterKey::generate()?;
            print_secret(&key.to_base64());
        }

        Command::RotateKeys {
            realm,
            retire_after_hours,
        } => {
            let realm = authenc_identity::realm::by_name(&db, &realm).await?;
            let rotated = authenc_oauth::keyring::rotate(
                &db,
                &config.master_key()?,
                realm.id,
                time::Duration::hours(retire_after_hours),
            )
            .await?;
            tracing::info!(kid = %rotated.kid, "rotated signing key");
        }

        Command::RegisterClient {
            realm,
            client_id,
            name,
            public,
            redirect_uris,
            scopes,
            skip_consent,
        } => {
            authenc_identity::migrate(&db).await?;
            let secret = authenc_server::cli::register_client(
                &db,
                &hasher,
                &realm,
                authenc_server::cli::ClientRegistration {
                    client_id: &client_id,
                    name: &name,
                    is_public: public,
                    redirect_uris: &redirect_uris,
                    scopes: &scopes,
                    require_consent: !skip_consent,
                },
            )
            .await?;

            match secret {
                Some(secret) => print_secret(&secret),
                None => tracing::info!("public client registered; no secret was issued"),
            }
        }

        Command::Serve => {
            serve(config, db, hasher, mailer).await?;
        }
    }

    Ok(())
}

/// Write a generated secret to stdout, and nowhere else.
///
/// The two commands that mint a credential have to hand it over somehow.
/// Stdout is the right channel: it can be piped straight into a secret store,
/// and unlike the log it is not collected, shipped, or retained by anything.
/// `print_stdout` is denied across the workspace precisely so that every
/// exception is a decision — this is the only one.
///
/// The secret is written to the stdout handle rather than passed to
/// `println!`: the formatting macros are logging sinks to static analysis, and
/// a value that provably must not be logged should not travel through one.
#[allow(
    clippy::print_stdout,
    reason = "a generated secret must reach the operator without passing through the log"
)]
fn print_secret(value: &str) {
    use std::io::Write as _;

    let _ = writeln!(std::io::stdout(), "{value}");
}

/// Run the HTTP server until it is asked to stop.
async fn serve(
    config: Config,
    db: authenc_identity::Db,
    hasher: authenc_identity::PasswordHasher,
    mailer: Arc<dyn authenc_identity::mail::Mailer>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        profile = ?config.profile,
        "starting authenc",
    );

    if config.database.migrate_on_start {
        authenc_identity::migrate(&db).await?;
    }

    let state = AppState {
        // Parsed here rather than per request: a malformed key must stop the
        // process at startup, not surface as a 500 at the first token call.
        master_key: Arc::new(config.master_key()?),
        // Also parsed here: a public URL WebAuthn cannot use must stop the
        // process at startup, not surface as a 500 the first time somebody
        // reaches for a passkey.
        relying_party: Arc::new(config.relying_party()?),
        config: Arc::new(config),
        db,
        hasher,
        mailer,
        leptos_options: http::leptos_options()?,
    };

    let address = http::bind_address(&state.config);
    let router = http::router(state);

    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "listening");

    // `into_make_service_with_connect_info` is what puts the peer address in
    // the request extensions. Without it, every login would be recorded with
    // no address and the per-address lockout could never fire.
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("shutdown complete");
    Ok(())
}

/// Build the configured mail transport.
///
/// Done at startup so a malformed relay URL fails here rather than on the
/// first password reset.
fn build_mailer(
    config: &Config,
) -> Result<Arc<dyn authenc_identity::mail::Mailer>, Box<dyn std::error::Error + Send + Sync>> {
    use authenc_server::config::MailTransport;

    Ok(match config.mail.transport {
        MailTransport::Logging => Arc::new(authenc_identity::mail::LoggingMailer),
        MailTransport::Smtp => Arc::new(authenc_identity::mail::SmtpMailer::new(
            config.mail.smtp_url.expose(),
            &config.mail.from,
        )?),
    })
}

/// Resolve when the process is asked to stop.
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for ctrl-c");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received ctrl-c, shutting down"),
        () = terminate => tracing::info!("received SIGTERM, shutting down"),
    }
}
