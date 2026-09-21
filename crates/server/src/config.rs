//! Layered configuration.
//!
//! Sources, in increasing precedence:
//!
//! 1. the defaults in [`Config::default`]
//! 2. `config/default.toml`, then `config/{profile}.toml`, if present
//! 3. environment variables prefixed `AUTHENC_`, nested with `__`
//!    (`AUTHENC_SERVER__PORT=8080`)
//!
//! Everything is read and validated **once**, at startup, into an immutable
//! value. The previous implementation scattered forty-eight `env::var` calls
//! across five crates, read only fifteen of them into its config struct, and
//! left whole config sections unreachable from the environment entirely.

use std::{net::IpAddr, time::Duration};

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A configuration value that must never appear in a log line.
///
/// `secrecy::SecretString` deliberately refuses to implement `Serialize`,
/// which figment's defaults provider requires, so this is the local
/// equivalent: it serialises (in memory, to figment) but its `Debug` output is
/// redacted and its buffer is zeroed on drop. The redaction is what stops a
/// database password travelling inside a `tracing` field or a panic message.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Read the underlying value. Every call site is a place to check.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Which environment the process believes it is running in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Local development: relaxed cookie flags, human-readable logs.
    #[default]
    Development,
    /// Continuous integration.
    Test,
    /// Production: every security control on, no defaults tolerated.
    Production,
}

impl Profile {
    /// Whether this profile must refuse to start on a weak configuration.
    #[must_use]
    pub const fn is_production(self) -> bool {
        matches!(self, Self::Production)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }
}

/// The whole configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which environment this is.
    pub profile: Profile,
    /// HTTP listener.
    pub server: ServerConfig,
    /// Database connection.
    pub database: DatabaseConfig,
    /// Logging and tracing.
    pub telemetry: TelemetryConfig,
    /// Security controls.
    pub security: SecurityConfig,
    /// Outbound mail.
    pub mail: MailConfig,
    /// The OAuth 2.0 / OpenID Connect provider.
    pub oauth: OauthConfig,
}

/// HTTP listener settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address to bind. Honoured — the previous server hardcoded `0.0.0.0`
    /// and ignored the configured host entirely.
    pub host: IpAddr,
    /// Port to bind.
    pub port: u16,
    /// Public origin, used for absolute URLs and cookie scoping.
    pub public_url: String,
    /// How long a single request may take before it is cut off.
    #[serde(with = "humantime_secs")]
    pub request_timeout: Duration,
    /// Largest accepted request body, in bytes.
    pub max_body_bytes: usize,
}

/// Database settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// libpq-style connection URL.
    pub url: Secret,
    /// Upper bound on pooled connections.
    pub max_connections: u32,
    /// Lower bound, kept warm.
    pub min_connections: u32,
    /// How long to wait for a free connection.
    #[serde(with = "humantime_secs")]
    pub acquire_timeout: Duration,
    /// Whether to apply pending migrations at startup.
    pub migrate_on_start: bool,
}

/// Logging and tracing settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `tracing-subscriber` filter directive, e.g. `info,authenc=debug`.
    pub filter: String,
    /// Emit machine-readable JSON logs instead of human-readable ones.
    pub json: bool,
}

/// How outbound mail is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MailTransport {
    /// Write the message to the log instead of sending it.
    ///
    /// Makes a fresh checkout produce a working reset link with no SMTP setup.
    /// Rejected under the production profile: a recovery flow that silently
    /// sends nothing locks users out with no error anywhere.
    #[default]
    Logging,
    /// Send over SMTP.
    Smtp,
}

/// Outbound mail settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailConfig {
    /// How to deliver.
    pub transport: MailTransport,
    /// SMTP URL, e.g. `smtp://localhost:1025` or `smtps://user:pass@host:465`.
    pub smtp_url: Secret,
    /// `From` address on outbound mail.
    pub from: String,
}

/// A development-only key-encryption key.
///
/// Present so a fresh checkout can issue tokens that survive a restart without
/// any setup at all. `validate` refuses to start the production profile with
/// it, exactly as it refuses the development database credentials — the
/// alternative, generating one per boot, is what the previous build did, and
/// it invalidated every token it had ever issued on every restart.
pub const DEVELOPMENT_MASTER_KEY: &str = "ZGV2ZWxvcG1lbnQtb25seS1tYXN0ZXIta2V5LTMyYnk";

/// The OAuth 2.0 / OpenID Connect provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OauthConfig {
    /// Base64url-encoded 32-byte key that encrypts stored signing keys.
    ///
    /// It never reaches the database, so a database disclosure alone does not
    /// yield a signing key. Generate one with `authenc generate-master-key`.
    pub master_key: Secret,
    /// The realm served at the root discovery document, for clients that
    /// cannot be pointed at a realm-specific URL.
    pub default_realm: String,
    /// Whether any client may register itself (RFC 7591).
    ///
    /// Off by default. Open registration on an IAM server lets anyone create a
    /// client with a redirect URI they control, which is a phishing surface
    /// wearing the operator's domain.
    pub allow_dynamic_registration: bool,
}

/// Security controls.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Origins permitted to make cross-origin requests. Empty means
    /// same-origin only.
    ///
    /// The previous server parsed this setting and then applied
    /// `CorsLayer::permissive()` — `Access-Control-Allow-Origin: *` on an IAM
    /// server — so the value never had any effect.
    #[serde(default, deserialize_with = "comma_separated::deserialize")]
    pub cors_allowed_origins: Vec<String>,
    /// Whether to emit HSTS. Off in development, where there is no TLS.
    pub hsts: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: Profile::Development,
            server: ServerConfig {
                host: IpAddr::from([127, 0, 0, 1]),
                port: 3000,
                public_url: "http://localhost:3000".to_owned(),
                request_timeout: Duration::from_secs(30),
                max_body_bytes: 1024 * 1024,
            },
            database: DatabaseConfig {
                // A development-only default. `validate` rejects it under the
                // production profile rather than letting it through silently,
                // which is how the old build shipped
                // `default_jwt_secret_change_in_production`.
                url: Secret::from("postgres://postgres:postgres@localhost:5432/authenc"),
                max_connections: 16,
                min_connections: 1,
                acquire_timeout: Duration::from_secs(5),
                migrate_on_start: true,
            },
            telemetry: TelemetryConfig {
                filter: "info,authenc=debug,tower_http=debug".to_owned(),
                json: false,
            },
            security: SecurityConfig {
                cors_allowed_origins: Vec::new(),
                hsts: false,
            },
            mail: MailConfig {
                transport: MailTransport::Logging,
                // MailHog, from compose.yaml.
                smtp_url: Secret::from("smtp://localhost:1025"),
                from: "Authenc <no-reply@localhost>".to_owned(),
            },
            oauth: OauthConfig {
                master_key: Secret::from(DEVELOPMENT_MASTER_KEY),
                default_realm: "master".to_owned(),
                allow_dynamic_registration: false,
            },
        }
    }
}

/// Why a configuration was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The sources could not be read or merged.
    ///
    /// Boxed because `figment::Error` is over 200 bytes, and this type is the
    /// `Err` half of every configuration call.
    #[error("reading configuration: {0}")]
    Source(#[from] Box<figment::Error>),

    /// The merged configuration is internally inconsistent or unsafe.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Load, merge, and validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a source cannot be read or the result fails
    /// [`Config::validate`].
    pub fn load() -> Result<Self, ConfigError> {
        // Read the profile first, because it selects which file to overlay and
        // how strict validation is.
        let profile: Profile = Figment::new()
            .merge(Serialized::default("profile", Profile::default()))
            .merge(Env::prefixed("AUTHENC_").only(&["profile"]))
            .extract_inner("profile")
            .unwrap_or_default();

        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Toml::file("config/default.toml"))
            .merge(Toml::file(format!("config/{}.toml", profile.as_str())))
            // `AUTHENC_SEED_PASSWORD` shares the prefix but is a CLI argument, not
            // configuration. Excluded explicitly so `deny_unknown_fields` keeps
            // catching genuine typos instead of being switched off.
            .merge(
                Env::prefixed("AUTHENC_")
                    .split("__")
                    .ignore(&["SEED_PASSWORD"]),
            )
            .extract()
            .map_err(Box::new)?;

        config.validate()?;
        Ok(config)
    }

    /// Reject configurations that are unsafe for the selected profile.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Invalid`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |message: String| Err(ConfigError::Invalid(message));

        if self.server.port == 0 {
            return invalid("server.port must not be 0".to_owned());
        }
        if self.database.min_connections > self.database.max_connections {
            return invalid(
                "database.min_connections must not exceed database.max_connections".to_owned(),
            );
        }
        if self.database.max_connections == 0 {
            return invalid("database.max_connections must be at least 1".to_owned());
        }
        if self.oauth.default_realm.trim().is_empty() {
            return invalid("oauth.default_realm must not be empty".to_owned());
        }
        // Checked in every profile: a key that cannot be decoded makes every
        // token endpoint fail at the first request instead of at startup.
        self.master_key()
            .map_err(|error| ConfigError::Invalid(format!("oauth.master_key: {error}")))?;

        if !self.profile.is_production() {
            return Ok(());
        }

        // Production is where silence becomes dangerous, so fail loudly.
        if self.database.url.expose().contains("postgres:postgres@") {
            return invalid(
                "database.url still uses the development postgres:postgres credentials".to_owned(),
            );
        }
        if !self.server.public_url.starts_with("https://") {
            return invalid("server.public_url must be https:// in production".to_owned());
        }
        if !self.security.hsts {
            return invalid("security.hsts must be enabled in production".to_owned());
        }
        if self
            .security
            .cors_allowed_origins
            .iter()
            .any(|origin| origin == "*")
        {
            return invalid(
                "security.cors_allowed_origins must not contain '*' in production".to_owned(),
            );
        }
        if self.mail.transport == MailTransport::Logging {
            return invalid(
                "mail.transport must be 'smtp' in production; \
                 'logging' would silently discard every password-reset mail"
                    .to_owned(),
            );
        }
        if self.oauth.master_key.expose() == DEVELOPMENT_MASTER_KEY {
            return invalid(
                "oauth.master_key is still the development key; \
                 generate one with `authenc generate-master-key`"
                    .to_owned(),
            );
        }

        Ok(())
    }

    /// The key-encryption key that protects stored signing keys.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Validation`] if the configured value is not a
    /// base64url-encoded 32-byte key.
    ///
    /// [`AppError::Validation`]: authenc_contract::AppError::Validation
    pub fn master_key(&self) -> authenc_contract::Result<authenc_identity::MasterKey> {
        authenc_identity::MasterKey::from_base64(self.oauth.master_key.expose())
    }

    /// The WebAuthn relying party this server presents itself as.
    ///
    /// Derived from `server.public_url` and nothing else. A relying-party id
    /// taken from a request header is one an attacker can choose, and a
    /// ceremony run against an origin they control is a ceremony they can
    /// replay against this one.
    ///
    /// # Errors
    ///
    /// Returns a validation error if the configured public URL has no host.
    pub fn relying_party(
        &self,
    ) -> authenc_contract::Result<authenc_identity::mfa::passkey::RelyingParty> {
        // The name an authenticator shows when it asks the user to confirm.
        // Not per realm: a `Webauthn` is built once at startup, and a name that
        // changed per request would show the user a different party than the
        // one their credential is scoped to.
        authenc_identity::mfa::passkey::RelyingParty::new(self.origin(), "Authenc")
    }

    /// The public origin, without a trailing slash.
    #[must_use]
    pub fn origin(&self) -> &str {
        self.server.public_url.trim_end_matches('/')
    }

    /// The database settings, in the shape the identity crate wants.
    #[must_use]
    pub fn db_config(&self) -> authenc_identity::DbConfig {
        authenc_identity::DbConfig {
            url: self.database.url.expose().to_owned(),
            max_connections: self.database.max_connections,
            min_connections: self.database.min_connections,
            acquire_timeout: self.database.acquire_timeout,
        }
    }
}

/// Read a list from either a TOML array or a comma-separated string.
///
/// `.env.example` documents `AUTHENC_SECURITY__CORS_ALLOWED_ORIGINS` as
/// comma-separated, and it is the value `just setup` copies into place — but
/// figment hands env vars over as plain strings, which do not deserialise into
/// a `Vec<String>`. Without this, the quickstart in `README.md` fails at
/// startup for anyone who followed it, empty value included, because even `""`
/// is a string and not a sequence.
mod comma_separated {
    use serde::{Deserialize, Deserializer};

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            Many(Vec<String>),
            One(String),
        }

        Ok(match OneOrMany::deserialize(deserializer)? {
            OneOrMany::Many(values) => values,
            OneOrMany::One(value) => value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::to_owned)
                .collect(),
        })
    }
}

/// Serialise `Duration` as whole seconds, so TOML and env vars can say `30`.
mod humantime_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(value.as_secs())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn production() -> Config {
        Config {
            profile: Profile::Production,
            server: ServerConfig {
                public_url: "https://id.example.com".to_owned(),
                ..Config::default().server
            },
            database: DatabaseConfig {
                url: Secret::from("postgres://app:s3cret@db.internal:5432/authenc"),
                ..Config::default().database
            },
            security: SecurityConfig {
                cors_allowed_origins: vec!["https://app.example.com".to_owned()],
                hsts: true,
            },
            mail: MailConfig {
                transport: MailTransport::Smtp,
                ..Config::default().mail
            },
            oauth: OauthConfig {
                master_key: Secret::from(
                    authenc_oauth::MasterKey::generate()
                        .expect("entropy")
                        .to_base64()
                        .as_str(),
                ),
                ..Config::default().oauth
            },
            ..Config::default()
        }
    }

    #[test]
    fn the_default_configuration_is_valid_in_development() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn a_well_formed_production_configuration_is_valid() {
        assert!(production().validate().is_ok());
    }

    #[test]
    fn production_rejects_the_development_database_credentials() {
        let mut config = production();
        config.database.url = Secret::from("postgres://postgres:postgres@db:5432/authenc");
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("postgres:postgres"), "got: {error}");
    }

    #[test]
    fn production_requires_https_and_hsts() {
        let mut config = production();
        config.server.public_url = "http://id.example.com".to_owned();
        assert!(config.validate().is_err());

        let mut config = production();
        config.security.hsts = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn production_refuses_to_discard_mail() {
        let mut config = production();
        config.mail.transport = MailTransport::Logging;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("mail.transport"), "got: {error}");
    }

    #[test]
    fn production_rejects_wildcard_cors() {
        let mut config = production();
        config.security.cors_allowed_origins = vec!["*".to_owned()];
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("cors_allowed_origins"), "got: {error}");
    }

    #[test]
    fn development_tolerates_what_production_rejects() {
        // The same values that fail above must not block a local run.
        let config = Config::default();
        assert!(!config.profile.is_production());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn nonsensical_pool_sizes_are_rejected() {
        let mut config = Config::default();
        config.database.min_connections = 20;
        config.database.max_connections = 5;
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.database.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn production_refuses_the_development_master_key() {
        // Shipping with it would mean every deployment shared one
        // key-encryption key, published in this repository.
        let mut config = production();
        config.oauth.master_key = Secret::from(DEVELOPMENT_MASTER_KEY);
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("master_key"), "got: {error}");
    }

    #[test]
    fn a_master_key_that_cannot_be_decoded_is_rejected_at_startup() {
        // Not at the first token request, which is how it would surface if
        // this were only parsed lazily.
        for bad in ["", "not base64!!", "c2hvcnQ"] {
            let mut config = Config::default();
            config.oauth.master_key = Secret::from(bad);
            assert!(config.validate().is_err(), "accepted: {bad:?}");
        }
    }

    #[test]
    fn the_development_master_key_is_a_usable_32_byte_key() {
        // Otherwise a fresh checkout fails validation before it can start.
        let config = Config::default();
        assert!(config.validate().is_ok());
        assert!(config.master_key().is_ok());
    }

    #[test]
    fn the_master_key_is_redacted_in_debug_output() {
        let mut config = Config::default();
        config.oauth.master_key = Secret::from("bWFzdGVyLWtleS10aGF0LW11c3Qtbm90LWxlYWs");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("bWFzdGVy"), "got: {rendered}");
    }

    #[test]
    fn the_origin_never_carries_a_trailing_slash() {
        let mut config = Config::default();
        config.server.public_url = "https://id.example.com/".to_owned();
        assert_eq!(config.origin(), "https://id.example.com");
    }

    #[test]
    fn the_database_url_is_redacted_in_debug_output() {
        // A config struct ends up in logs and panic messages; the password
        // must not travel with it.
        let rendered = format!("{:?}", Config::default());
        assert!(!rendered.contains("postgres:postgres"), "got: {rendered}");
    }

    #[test]
    fn a_comma_separated_cors_list_is_read_as_a_list() {
        // `.env.example` documents this setting as comma-separated and
        // `just setup` copies that file into place. The env provider hands
        // figment a plain string, which is what this Serialized value is;
        // without the comma-splitting deserialiser it fails to parse and the
        // server refuses to start for anyone who followed the README.
        let config: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Serialized::default(
                "security.cors_allowed_origins",
                "https://a.example.com, https://b.example.com",
            ))
            .extract()
            .expect("a comma-separated list deserialises");
        assert_eq!(
            config.security.cors_allowed_origins,
            vec![
                "https://a.example.com".to_owned(),
                "https://b.example.com".to_owned()
            ]
        );
    }

    #[test]
    fn an_empty_cors_value_is_an_empty_list() {
        // The shipped default is the empty string, which still has to parse.
        // This is the exact value `.env.example` sets, and the one that
        // blocked the quickstart before the list was read through a
        // comma-splitting deserialiser.
        let config: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Serialized::default("security.cors_allowed_origins", ""))
            .extract()
            .expect("an empty value is an empty list, not a parse error");
        assert!(config.security.cors_allowed_origins.is_empty());
    }
}
