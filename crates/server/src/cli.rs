//! Command-line interface.
//!
//! Operational tasks live here rather than behind an HTTP endpoint. That is a
//! deliberate boundary: the previous server shipped `/api/v1/auth/test-login`
//! and `/oauth2/consent/test` in its production router — unauthenticated, and
//! hardcoding a user id — because there was nowhere else to put "set up some
//! data to try this with". There is now.

use authenc_contract::{AppError, Permission, Result, model::ROLE_ADMIN};
use authenc_identity::{
    Db, PasswordHasher, realm, role,
    user::{self, NewUser},
};
use clap::{Parser, Subcommand};

/// The Authenc server.
#[derive(Debug, Parser)]
#[command(name = "authenc", version, about)]
pub struct Cli {
    /// What to do. Defaults to running the server.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the HTTP server. The default when no subcommand is given.
    Serve,

    /// Apply pending migrations and exit.
    Migrate,

    /// Create a realm and an administrator in it.
    ///
    /// Idempotent enough to be safe to re-run: an existing realm is reused, and
    /// an existing username is reported rather than overwritten.
    Seed {
        /// Realm slug to create or reuse.
        #[arg(long, default_value = "master")]
        realm: String,

        /// Administrator username.
        #[arg(long, default_value = "admin")]
        username: String,

        /// Administrator email address.
        #[arg(long)]
        email: String,

        /// Administrator password.
        ///
        /// Prefer the environment variable: a password passed as an argument
        /// is visible in the process list and in shell history.
        #[arg(long, env = "AUTHENC_SEED_PASSWORD", hide_env_values = true)]
        password: String,
    },

    /// Delete expired sessions, authorization codes, and refresh tokens.
    ///
    /// Safe to run on a timer. Spent codes and tokens are kept until they
    /// could no longer be replayed, so this never removes evidence of an
    /// attack that is still in progress.
    Purge {
        /// Also delete audit events older than this many days.
        ///
        /// Off unless given, and deliberately not defaulted: an audit log that
        /// trims itself on a schedule nobody chose is one that will be empty
        /// when it is needed. Retention is an operator's decision, made once,
        /// in the open.
        #[arg(long, value_name = "DAYS")]
        audit_older_than: Option<u32>,
    },

    /// Print a fresh key-encryption key for `AUTHENC_OAUTH__MASTER_KEY`.
    ///
    /// Nothing is written: the value is yours to put wherever secrets live.
    /// Rotating it requires re-encrypting stored signing keys, so treat it as
    /// permanent for a deployment.
    GenerateMasterKey,

    /// Rotate a realm's OAuth signing key.
    ///
    /// The old key keeps verifying, and keeps appearing in JWKS, until it
    /// expires — so tokens signed a moment ago stay valid.
    RotateKeys {
        /// Realm whose key to rotate.
        #[arg(long, default_value = "master")]
        realm: String,

        /// How long the outgoing key keeps verifying, in hours.
        #[arg(long, default_value_t = 48)]
        retire_after_hours: i64,
    },

    /// Register an OAuth client.
    ///
    /// The generated secret is printed once and never again; only its hash is
    /// stored.
    RegisterClient {
        /// Realm to register in.
        #[arg(long, default_value = "master")]
        realm: String,

        /// The `client_id` the client will present.
        #[arg(long)]
        client_id: String,

        /// Display name, shown on the consent screen.
        #[arg(long)]
        name: String,

        /// Register a public client: no secret, PKCE required.
        #[arg(long)]
        public: bool,

        /// Redirect URI. Repeat for more than one. Matched exactly.
        #[arg(long = "redirect-uri", required = true)]
        redirect_uris: Vec<String>,

        /// Scope the client may request. Repeat for more than one.
        #[arg(long = "scope")]
        scopes: Vec<String>,

        /// Skip the consent screen. Only sensible for a first-party client.
        #[arg(long)]
        skip_consent: bool,
    },
}

/// Create a realm and an administrator inside it.
///
/// # Errors
///
/// Returns an error if validation fails or the database rejects a write.
pub async fn seed(
    db: &Db,
    hasher: &PasswordHasher,
    realm_name: &str,
    username: &str,
    email: &str,
    password: &str,
) -> Result<()> {
    let realm = match realm::by_name(db, realm_name).await {
        Ok(existing) => {
            tracing::info!(realm = realm_name, "reusing existing realm");
            existing
        }
        Err(error) if error.status() == 404 => realm::create(db, realm_name, realm_name).await?,
        Err(error) => return Err(error),
    };

    let user = user::create(
        db,
        hasher,
        NewUser {
            realm_id: realm.id,
            username,
            email,
            password,
            first_name: None,
            last_name: None,
        },
    )
    .await
    .map_err(|error| match error.status() {
        409 => AppError::conflict(format!(
            "user {username} already exists in realm {realm_name}; \
             nothing was changed"
        )),
        _ => error,
    })?;

    let admin = role::ensure(
        db,
        realm.id,
        ROLE_ADMIN,
        Some("Full administrative access within the realm"),
    )
    .await?;
    // Explicit rows, not a magic role name: the previous code branched on
    // `roles.contains("admin")`, so the string *was* the authorisation.
    role::set_permissions(db, realm.id, admin.id, Permission::ALL).await?;
    role::grant(db, user.id, admin.id).await?;

    tracing::info!(
        realm = realm_name,
        username,
        "created administrator; sign in at /login",
    );
    Ok(())
}

/// Register an OAuth client and return the secret, if it has one.
///
/// # Errors
///
/// Returns an error if the realm does not exist or the metadata is refused.
pub async fn register_client(
    db: &Db,
    hasher: &PasswordHasher,
    realm_name: &str,
    new: ClientRegistration<'_>,
) -> Result<Option<String>> {
    use authenc_oauth::client;

    let realm = realm::by_name(db, realm_name).await?;

    let registered = client::register(
        db,
        hasher,
        client::NewClient {
            realm_id: realm.id,
            client_id: Some(new.client_id),
            name: new.name,
            is_public: new.is_public,
            redirect_uris: new.redirect_uris,
            grant_types: &[],
            scopes: new.scopes,
            require_consent: new.require_consent,
        },
    )
    .await
    .map_err(|error| AppError::validation(error.description))?;

    tracing::info!(
        realm = realm_name,
        client_id = %registered.client.client_id,
        public = registered.client.is_public,
        "registered oauth client",
    );

    Ok(registered
        .client_secret
        .map(|secret| secret.expose().to_owned()))
}

/// What [`register_client`] needs, so the argument list stays readable.
#[derive(Debug, Clone)]
pub struct ClientRegistration<'a> {
    /// The `client_id` the client will present.
    pub client_id: &'a str,
    /// Display name.
    pub name: &'a str,
    /// Whether it is a public client.
    pub is_public: bool,
    /// Exact redirect URIs.
    pub redirect_uris: &'a [String],
    /// Scopes it may request.
    pub scopes: &'a [String],
    /// Whether the consent screen is shown.
    pub require_consent: bool,
}

/// Delete everything that has expired, across every store.
///
/// # Errors
///
/// Returns an error if any delete fails.
pub async fn purge(db: &Db, audit_older_than_days: Option<u32>) -> Result<()> {
    let sessions = authenc_identity::session::purge_expired(db).await?;
    let recovery = authenc_identity::recovery::purge_expired(db).await?;
    let codes = authenc_oauth::code::purge_expired(db).await?;
    let refresh = authenc_oauth::refresh::purge_expired(db).await?;
    let keys = authenc_oauth::keyring::purge_retired(db).await?;
    let challenges = authenc_identity::mfa::challenge::purge_expired(db).await?;
    let ceremonies = authenc_identity::mfa::passkey::purge_expired(db).await?;
    // Accepted invitations are kept: they are the record of who joined.
    let invitations = authenc_identity::organization::purge_expired(db).await?;
    let login_states = authenc_oauth::social::purge_expired(db).await?;
    // Revoked tokens are kept for the same reason: they are the record that a
    // credential existed and was withdrawn.
    let api_tokens = authenc_identity::api_token::purge_expired(db).await?;

    let audit = match audit_older_than_days {
        Some(days) => {
            let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(days.into());
            authenc_identity::audit::purge_before(db, cutoff).await?
        }
        None => 0,
    };

    tracing::info!(
        sessions,
        recovery,
        authorization_codes = codes,
        refresh_tokens = refresh,
        signing_keys = keys,
        mfa_challenges = challenges,
        webauthn_ceremonies = ceremonies,
        invitations,
        federation_login_states = login_states,
        api_tokens,
        audit_events = audit,
        "purged expired records",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A password generated at runtime; see the integration tests for why.
    fn password() -> &'static str {
        static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        P.get_or_init(|| uuid::Uuid::new_v4().to_string()).as_str()
    }

    /// A password distinct from [`password`], for a re-seed that must conflict.
    fn different_password() -> String {
        let mut p = password().to_owned();
        p.push_str("-other");
        p
    }

    /// A password below the policy's minimum length.
    fn weak_password() -> String {
        let mut p = password().to_owned();
        p.truncate(p.len() - 30);
        p
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn seeding_creates_a_realm_an_admin_and_the_admin_role(db: Db) {
        let hasher = PasswordHasher::new();
        seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            password(),
        )
        .await
        .unwrap();

        // Prove it through the same path a login takes, rather than by
        // reading rows: the roles must be visible where authorisation reads
        // them.
        let authenticated = authenc_identity::login::authenticate(
            &db,
            &hasher,
            authenc_identity::login::Attempt {
                realm: "master",
                identifier: "admin",
                password: password(),
                origin: authenc_identity::session::Origin::default(),
            },
        )
        .await
        .unwrap();

        // A freshly seeded administrator has no second factor, so this must be
        // a completed login; anything else means seeding produced an account
        // nobody can sign in to.
        let authenticated = match authenticated {
            authenc_identity::login::Outcome::Complete(authenticated) => *authenticated,
            authenc_identity::login::Outcome::SecondFactorRequired(_) => {
                panic!("a seeded administrator must not require a second factor")
            }
        };

        let roles = user::role_names(&db, authenticated.user.id).await.unwrap();
        assert_eq!(roles, vec![ROLE_ADMIN.to_owned()]);

        // And the role must carry real permissions, not just a name.
        let permissions = user::permissions(&db, authenticated.user.id).await.unwrap();
        assert_eq!(permissions.len(), Permission::ALL.len(), "{permissions:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_seeded_admin_can_actually_log_in(db: Db) {
        // The property that matters: seeding produces working credentials, not
        // merely rows.
        let hasher = PasswordHasher::new();
        seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            password(),
        )
        .await
        .unwrap();

        let result = authenc_identity::login::authenticate(
            &db,
            &hasher,
            authenc_identity::login::Attempt {
                realm: "master",
                identifier: "admin",
                password: password(),
                origin: authenc_identity::session::Origin::default(),
            },
        )
        .await;

        assert!(result.is_ok(), "seeded admin should be able to sign in");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn seeding_twice_reports_a_conflict_rather_than_overwriting(db: Db) {
        let hasher = PasswordHasher::new();
        seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            password(),
        )
        .await
        .unwrap();

        let error = seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            &different_password(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.status(), 409);

        // And the original password must still work — a re-run must not have
        // silently reset the administrator's credentials.
        assert!(
            authenc_identity::login::authenticate(
                &db,
                &hasher,
                authenc_identity::login::Attempt {
                    realm: "master",
                    identifier: "admin",
                    password: password(),
                    origin: authenc_identity::session::Origin::default(),
                },
            )
            .await
            .is_ok(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_weak_seed_password_is_refused(db: Db) {
        let hasher = PasswordHasher::new();
        let error = seed(
            &db,
            &hasher,
            "master",
            "admin",
            "admin@example.com",
            &weak_password(),
        )
        .await
        .unwrap_err();

        assert_eq!(error.status(), 400, "policy applies to the first user too");
    }
}
