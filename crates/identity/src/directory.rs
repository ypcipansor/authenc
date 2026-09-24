//! LDAP and Active Directory as a source of users.
//!
//! # The three rules that make this safe
//!
//! Each is a way LDAP authentication is routinely got wrong, and each is a
//! pure function here so it can be tested without a directory.
//!
//! **An empty password is refused before anything is sent.** LDAP treats a
//! simple bind with an empty password as an *anonymous* bind, and an anonymous
//! bind succeeds. A server that forwards a blank password to the directory and
//! reads "success" has authenticated nobody as somebody. This is the single
//! most common LDAP authentication bypass, and [`Credentials::new`] is where it
//! stops.
//!
//! **The login is escaped before it reaches the filter.** RFC 4515 gives five
//! characters special meaning inside a filter. Substituted raw, a login of
//! `*)(uid=*` turns "find this user" into "find any user", and whoever the
//! directory returns first is who gets in. [`escape_filter_value`] handles it.
//!
//! **Exactly one result, or nothing.** Two matches is not "pick the first" —
//! it means the filter does not identify a person, and the right answer is to
//! refuse and say so in the log.
//!
//! # The DN is the identity
//!
//! Not the login name. A `uid` can be reassigned when somebody leaves, and a
//! directory handing `jsmith` to a new starter would otherwise hand them the
//! previous holder's local account and its roles. The same reasoning as the
//! upstream `sub` in [`crate::federation`].
//!
//! # Why a trait
//!
//! No directory's credentials can run in CI, and standing up an OpenLDAP
//! container for the unit tests would test `ldap3` rather than the rules above.
//! [`Directory`] is substituted in tests, exactly as `Transport` is for social
//! login.

use authenc_contract::{AppError, RealmId, Result, UserId, model::User};
use time::OffsetDateTime;

use crate::{db::Db, sealed::MasterKey, user};

/// The placeholder a user filter must contain.
pub const LOGIN_PLACEHOLDER: &str = "{login}";

/// Escape a value for use inside an LDAP filter, per RFC 4515.
///
/// Without this, a login containing `*`, `(`, `)`, `\` or a NUL rewrites the
/// filter it is substituted into. `*)(uid=*` is the canonical example: it
/// closes the intended clause and opens a match-anything one.
#[must_use]
pub fn escape_filter_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\\' => escaped.push_str("\\5c"),
            '\0' => escaped.push_str("\\00"),
            // Everything else passes through unchanged.
            //
            // By `char`, not by byte. An earlier version iterated bytes and
            // rebuilt each one with `char::from`, which reads a UTF-8
            // continuation byte as Latin-1 — so `zoë` went to the directory as
            // `zoÃ«` and matched nobody. All five special characters are
            // ASCII, so working per character loses nothing.
            other => escaped.push(other),
        }
    }
    escaped
}

/// Credentials that are worth sending to a directory.
///
/// Constructing this is the *only* way to reach [`Directory::authenticate`],
/// which is how the empty-password rule is made unskippable rather than
/// remembered.
#[derive(Debug, Clone)]
pub struct Credentials {
    login: String,
    password: String,
}

impl Credentials {
    /// Check a login and password before they are used.
    ///
    /// # Errors
    ///
    /// [`AppError::Unauthenticated`] for a blank login or a blank password.
    ///
    /// The password case is the important one: LDAP reads a simple bind with
    /// an empty password as an anonymous bind, and answers success. A server
    /// that passes one through has authenticated nobody as somebody.
    pub fn new(login: &str, password: &str) -> Result<Self> {
        if login.trim().is_empty() {
            return Err(AppError::Unauthenticated);
        }
        // Not `.trim()`: a password of spaces is a password, and trimming it
        // would silently authenticate a different string than was typed. What
        // is refused is *nothing at all*.
        if password.is_empty() {
            return Err(AppError::Unauthenticated);
        }

        Ok(Self {
            login: login.trim().to_owned(),
            password: password.to_owned(),
        })
    }

    /// The login, as typed.
    #[must_use]
    pub fn login(&self) -> &str {
        &self.login
    }

    /// The password. Deliberately not `Display` or `Debug`-visible in full.
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// What a directory told us about somebody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The distinguished name. The identity.
    pub dn: String,
    /// The login name, from the configured attribute.
    pub username: Option<String>,
    /// The address, from the configured attribute.
    pub email: Option<String>,
    /// Given name.
    pub first_name: Option<String>,
    /// Family name.
    pub last_name: Option<String>,
}

/// Talking to a directory.
///
/// Two operations, because that is all an authentication needs: find the
/// person, then prove the password against their DN.
#[async_trait::async_trait]
pub trait Directory: Send + Sync {
    /// Find exactly one entry matching this filter.
    ///
    /// The filter is already escaped by the caller. Implementations must
    /// return `Ok(None)` for no match and an error for more than one — see the
    /// module note on why "pick the first" is wrong.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or the search fails.
    async fn find(&self, config: &LdapDirectory, filter: &str) -> Result<Option<Entry>>;

    /// Bind as this DN with this password.
    ///
    /// `Ok(false)` is a wrong password. An error is a directory that could not
    /// be reached, which is a different thing and must not be reported as a
    /// failed login.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    async fn bind(&self, config: &LdapDirectory, dn: &str, password: &str) -> Result<bool>;
}

/// A configured directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LdapDirectory {
    /// Stable identifier.
    pub id: uuid::Uuid,
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// URL-safe handle.
    pub alias: String,
    /// What an operator calls it.
    pub display_name: String,
    /// `ldaps://host:636` or `ldap://host:389`.
    pub url: String,
    /// Whether to upgrade a plaintext connection before binding.
    pub start_tls: bool,
    /// The service account used to search. Empty means anonymous.
    pub bind_dn: String,
    /// Where to search.
    pub user_base_dn: String,
    /// The filter, containing [`LOGIN_PLACEHOLDER`].
    pub user_filter: String,
    /// Attribute carrying the login name.
    pub attr_username: String,
    /// Attribute carrying the address.
    pub attr_email: String,
    /// Attribute carrying the given name.
    pub attr_first_name: String,
    /// Attribute carrying the family name.
    pub attr_last_name: String,
    /// Whether a directory account nobody here has seen may create a local one.
    pub allow_provisioning: bool,
    /// Whether it is consulted at sign-in.
    pub enabled: bool,
    /// When it was configured.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl LdapDirectory {
    /// The filter to search with, for this login.
    ///
    /// The login is escaped first. This is the only place the two are combined,
    /// so there is one call site to get right rather than one per caller.
    #[must_use]
    pub fn filter_for(&self, login: &str) -> String {
        self.user_filter
            .replace(LOGIN_PLACEHOLDER, &escape_filter_value(login))
    }

    /// Whether this connection protects the password in transit.
    ///
    /// A simple bind sends the password in the clear, so a directory reached
    /// over plain `ldap://` without StartTLS is one where every sign-in is
    /// readable by anything on the path.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.url.starts_with("ldaps://") || self.start_tls
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// What a new directory needs.
#[derive(Debug, Clone)]
pub struct NewDirectory<'a> {
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// URL-safe handle.
    pub alias: &'a str,
    /// What an operator calls it.
    pub display_name: &'a str,
    /// `ldaps://host:636` or `ldap://host:389`.
    pub url: &'a str,
    /// Whether to upgrade a plaintext connection before binding.
    pub start_tls: bool,
    /// The service account used to search. Empty means anonymous.
    pub bind_dn: &'a str,
    /// Its password, sealed before it reaches the database.
    pub bind_password: Option<&'a str>,
    /// Where to search.
    pub user_base_dn: &'a str,
    /// The filter, which must contain [`LOGIN_PLACEHOLDER`].
    pub user_filter: &'a str,
    /// Attribute carrying the login name.
    pub attr_username: &'a str,
    /// Attribute carrying the address.
    pub attr_email: &'a str,
    /// Attribute carrying the given name.
    pub attr_first_name: &'a str,
    /// Attribute carrying the family name.
    pub attr_last_name: &'a str,
    /// Whether a directory account nobody here has seen may create a local one.
    pub allow_provisioning: bool,
}

fn translate(error: sqlx::Error, context: &'static str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        match db_error.code().as_deref() {
            Some("23505") => return AppError::conflict("that alias is taken in this realm"),
            Some("23514") => {
                return AppError::validation(
                    "an alias must be lowercase letters, digits, and hyphens",
                );
            }
            _ => {}
        }
    }
    AppError::internal_from(context, error)
}

/// Configure a directory.
///
/// # Errors
///
/// [`AppError::Validation`] for a filter without [`LOGIN_PLACEHOLDER`], a
/// malformed URL, or a blank required field; [`AppError::Conflict`] if the
/// alias is taken.
pub async fn create(db: &Db, master: &MasterKey, new: NewDirectory<'_>) -> Result<LdapDirectory> {
    // A filter with no placeholder matches the same thing for every login,
    // which means the first entry it returns can sign in as anybody. Refused
    // here rather than discovered in production.
    if !new.user_filter.contains(LOGIN_PLACEHOLDER) {
        return Err(AppError::field(
            "user_filter",
            "must contain {login}, where the submitted name is substituted",
        ));
    }

    if !new.url.starts_with("ldap://") && !new.url.starts_with("ldaps://") {
        return Err(AppError::field("url", "must be ldap:// or ldaps://"));
    }

    if new.user_base_dn.trim().is_empty() {
        return Err(AppError::field("user_base_dn", "must not be empty"));
    }

    // A bind DN with no password would bind anonymously while looking like it
    // had credentials, which is the sort of gap nobody notices until the
    // search starts returning nothing.
    if !new.bind_dn.trim().is_empty() && new.bind_password.is_none_or(str::is_empty) {
        return Err(AppError::field(
            "bind_password",
            "a bind DN needs a password; leave both empty to search anonymously",
        ));
    }

    let id = uuid::Uuid::new_v4();
    let sealed = new
        .bind_password
        .filter(|password| !password.is_empty())
        .map(|password| crate::sealed::seal(master, id.as_bytes(), password.as_bytes()))
        .transpose()?;

    let row = sqlx::query!(
        r#"
        INSERT INTO ldap_directories
            (id, realm_id, alias, display_name, url, start_tls, bind_dn,
             bind_password_ciphertext, bind_password_nonce, user_base_dn,
             user_filter, attr_username, attr_email, attr_first_name,
             attr_last_name, allow_provisioning)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        RETURNING created_at, enabled
        "#,
        id,
        new.realm_id.0,
        new.alias.trim(),
        new.display_name.trim(),
        new.url,
        new.start_tls,
        new.bind_dn.trim(),
        sealed.as_ref().map(|s| s.ciphertext.clone()),
        sealed.as_ref().map(|s| s.nonce.to_vec()),
        new.user_base_dn.trim(),
        new.user_filter,
        new.attr_username,
        new.attr_email,
        new.attr_first_name,
        new.attr_last_name,
        new.allow_provisioning,
    )
    .fetch_one(db)
    .await
    .map_err(|e| translate(e, "configuring a directory"))?;

    Ok(LdapDirectory {
        id,
        realm_id: new.realm_id,
        alias: new.alias.trim().to_owned(),
        display_name: new.display_name.trim().to_owned(),
        url: new.url.to_owned(),
        start_tls: new.start_tls,
        bind_dn: new.bind_dn.trim().to_owned(),
        user_base_dn: new.user_base_dn.trim().to_owned(),
        user_filter: new.user_filter.to_owned(),
        attr_username: new.attr_username.to_owned(),
        attr_email: new.attr_email.to_owned(),
        attr_first_name: new.attr_first_name.to_owned(),
        attr_last_name: new.attr_last_name.to_owned(),
        allow_provisioning: new.allow_provisioning,
        enabled: row.enabled,
        created_at: row.created_at,
    })
}

/// The row shape shared by every directory read.
macro_rules! directory_from_row {
    ($row:expr) => {
        LdapDirectory {
            id: $row.id,
            realm_id: RealmId($row.realm_id),
            alias: $row.alias,
            display_name: $row.display_name,
            url: $row.url,
            start_tls: $row.start_tls,
            bind_dn: $row.bind_dn,
            user_base_dn: $row.user_base_dn,
            user_filter: $row.user_filter,
            attr_username: $row.attr_username,
            attr_email: $row.attr_email,
            attr_first_name: $row.attr_first_name,
            attr_last_name: $row.attr_last_name,
            allow_provisioning: $row.allow_provisioning,
            enabled: $row.enabled,
            created_at: $row.created_at,
        }
    };
}

/// Every directory in a realm, in the order they are consulted.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, realm_id: RealmId) -> Result<Vec<LdapDirectory>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, realm_id, alias, display_name, url, start_tls, bind_dn,
               user_base_dn, user_filter, attr_username, attr_email,
               attr_first_name, attr_last_name, allow_provisioning, enabled,
               created_at
          FROM ldap_directories WHERE realm_id = $1 ORDER BY created_at
        "#,
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing directories", e))?;

    Ok(rows
        .into_iter()
        .map(|row| directory_from_row!(row))
        .collect())
}

/// Look one up.
///
/// # Errors
///
/// [`AppError::NotFound`] if no directory has that id.
pub async fn by_id(db: &Db, id: uuid::Uuid) -> Result<LdapDirectory> {
    let row = sqlx::query!(
        r#"
        SELECT id, realm_id, alias, display_name, url, start_tls, bind_dn,
               user_base_dn, user_filter, attr_username, attr_email,
               attr_first_name, attr_last_name, allow_provisioning, enabled,
               created_at
          FROM ldap_directories WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading a directory", e))?
    .ok_or(AppError::NotFound("directory"))?;

    Ok(directory_from_row!(row))
}

/// The service account's password, decrypted.
///
/// Separate from [`LdapDirectory`] so that every caller wanting it has to say
/// so, and a directory record cannot carry one into a log line.
///
/// # Errors
///
/// [`AppError::NotFound`] if the directory is gone, or an internal error if
/// the ciphertext does not open.
pub async fn bind_password(db: &Db, master: &MasterKey, id: uuid::Uuid) -> Result<Option<String>> {
    let row = sqlx::query!(
        "SELECT bind_password_ciphertext, bind_password_nonce FROM ldap_directories WHERE id = $1",
        id,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading a bind password", e))?
    .ok_or(AppError::NotFound("directory"))?;

    let (Some(ciphertext), Some(nonce)) = (row.bind_password_ciphertext, row.bind_password_nonce)
    else {
        return Ok(None);
    };

    let plaintext = crate::sealed::open(
        master,
        id.as_bytes(),
        &ciphertext,
        &nonce,
        "directory bind password",
    )?;

    String::from_utf8(plaintext)
        .map(Some)
        .map_err(|e| AppError::internal_from("decoding a bind password", e))
}

/// Enable or disable a directory.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn set_enabled(db: &Db, id: uuid::Uuid, enabled: bool) -> Result<LdapDirectory> {
    let result = sqlx::query!(
        "UPDATE ldap_directories SET enabled = $2 WHERE id = $1",
        id,
        enabled,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("changing a directory", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("directory"));
    }
    by_id(db, id).await
}

/// Delete a directory and every link through it.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn delete(db: &Db, id: uuid::Uuid) -> Result<()> {
    let result = sqlx::query!("DELETE FROM ldap_directories WHERE id = $1", id)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("deleting a directory", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("directory"));
    }
    Ok(())
}

/// How many accounts are linked through a directory.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn link_count(db: &Db, directory_id: uuid::Uuid) -> Result<i64> {
    sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM ldap_identities WHERE directory_id = $1"#,
        directory_id,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting directory links", e))
}

// ---------------------------------------------------------------------------
// Signing in
// ---------------------------------------------------------------------------

/// A directory sign-in that reached a local account.
#[derive(Debug)]
pub struct SignedIn {
    /// The local account.
    pub user: User,
    /// Whether it had to be created.
    pub provisioned: bool,
}

/// Authenticate against a directory and resolve to a local account.
///
/// The order matters and is the whole of it:
///
/// 1. Refuse a blank password — done by [`Credentials::new`], before this is
///    reachable, because LDAP answers success to an empty bind.
/// 2. Search for the person, with the login escaped into the filter.
/// 3. Bind **as their DN** with the submitted password. That is the check; the
///    search proves only that a directory entry exists.
/// 4. Map the entry to a local account by DN, or create one.
///
/// Resolving to a local account is separate from authenticating, so a wrong
/// password never reaches the provisioning path.
///
/// # Errors
///
/// [`AppError::Unauthenticated`] for an unknown user, a wrong password, an
/// ambiguous search, or a directory that is switched off. Errors reaching the
/// directory are returned as-is, so "the directory is down" is distinguishable
/// in the log from "that password is wrong" — while the caller sees the same
/// refusal either way.
pub async fn authenticate(
    db: &Db,
    directory: &dyn Directory,
    config: &LdapDirectory,
    credentials: &Credentials,
) -> Result<SignedIn> {
    if !config.enabled {
        return Err(AppError::Unauthenticated);
    }

    let filter = config.filter_for(credentials.login());

    let Some(entry) = directory.find(config, &filter).await? else {
        // No such entry. Reported as the same refusal a wrong password gets.
        return Err(AppError::Unauthenticated);
    };

    if entry.dn.trim().is_empty() {
        // A directory that returned an entry with no DN has told us nothing
        // about who this is, and there is nothing to bind as.
        tracing::warn!(alias = %config.alias, "a directory returned an entry with no DN");
        return Err(AppError::Unauthenticated);
    }

    // The actual authentication. Everything before this only located somebody.
    if !directory
        .bind(config, &entry.dn, credentials.password())
        .await?
    {
        return Err(AppError::Unauthenticated);
    }

    resolve(db, config, &entry).await
}

/// Map an authenticated directory entry to a local account.
async fn resolve(db: &Db, config: &LdapDirectory, entry: &Entry) -> Result<SignedIn> {
    let dn = normalise_dn(&entry.dn);

    if let Some(user_id) = linked(db, config.id, &dn).await? {
        touch(db, config.id, user_id).await;
        return Ok(SignedIn {
            user: user::by_id(db, user_id).await?,
            provisioned: false,
        });
    }

    if !config.allow_provisioning {
        tracing::info!(
            alias = %config.alias,
            "a directory account authenticated but provisioning is off",
        );
        return Err(AppError::Unauthenticated);
    }

    // An address is required: it is the account's identity here, and a user
    // without one cannot reset a password or be contacted.
    let email = entry
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or_else(|| {
            AppError::validation("the directory returned no email address for this account")
        })?;

    let username = entry
        .username
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or(email));

    let display_name = match (&entry.first_name, &entry.last_name) {
        (Some(first), Some(last)) => Some(format!("{first} {last}")),
        (Some(one), None) | (None, Some(one)) => Some(one.clone()),
        (None, None) => None,
    };

    let created = user::create_without_password(
        db,
        user::NewFederatedUser {
            realm_id: config.realm_id,
            username,
            email,
            // The directory is the authority on this address, and reaching it
            // required the person's own password — which is a stronger claim
            // than a self-service registration makes.
            email_verified: true,
            display_name: display_name.as_deref(),
        },
    )
    .await?;

    link(db, config.id, created.id, &dn).await?;

    Ok(SignedIn {
        user: created,
        provisioned: true,
    })
}

/// Normalise a distinguished name for comparison.
///
/// Lowercased, because a DN's attribute types are case-insensitive and most
/// directories are case-insensitive about the values too. Two spellings of one
/// identity becoming two local accounts is the failure this prevents; the cost
/// is a directory that deliberately distinguishes `CN=Bob` from `cn=bob`,
/// which is not a thing any of them do.
#[must_use]
pub fn normalise_dn(dn: &str) -> String {
    dn.trim().to_lowercase()
}

/// Which local account this DN is attached to, if any.
async fn linked(db: &Db, directory_id: uuid::Uuid, dn: &str) -> Result<Option<UserId>> {
    let found = sqlx::query_scalar!(
        "SELECT user_id FROM ldap_identities WHERE directory_id = $1 AND external_dn = $2",
        directory_id,
        dn,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("resolving a directory identity", e))?;

    Ok(found.map(UserId))
}

/// Attach a directory entry to a local account.
///
/// # Errors
///
/// [`AppError::Conflict`] if that DN is already attached to somebody, or if
/// this account already has an identity in this directory.
pub async fn link(db: &Db, directory_id: uuid::Uuid, user_id: UserId, dn: &str) -> Result<()> {
    sqlx::query!(
        "INSERT INTO ldap_identities (directory_id, user_id, external_dn) VALUES ($1, $2, $3)",
        directory_id,
        user_id.0,
        normalise_dn(dn),
    )
    .execute(db)
    .await
    .map_err(|e| translate(e, "linking a directory identity"))?;
    Ok(())
}

/// Record that a link was just used.
async fn touch(db: &Db, directory_id: uuid::Uuid, user_id: UserId) {
    let result = sqlx::query!(
        "UPDATE ldap_identities SET last_login_at = now() \
         WHERE directory_id = $1 AND user_id = $2",
        directory_id,
        user_id.0,
    )
    .execute(db)
    .await;

    if let Err(error) = result {
        tracing::error!(%error, "could not record a directory sign-in");
    }
}

// ---------------------------------------------------------------------------
// The real directory
// ---------------------------------------------------------------------------

/// [`Directory`] over the network, via `ldap3`.
///
/// Holds the service account's password for the life of the call rather than
/// reading it per operation, because a search and a bind are two connections
/// and both need it.
#[derive(Debug, Clone)]
pub struct LdapClient {
    bind_password: Option<String>,
}

impl LdapClient {
    /// Build one for a directory whose bind password has been decrypted.
    #[must_use]
    pub const fn new(bind_password: Option<String>) -> Self {
        Self { bind_password }
    }

    /// Open a connection, applying StartTLS where configured.
    async fn connect(config: &LdapDirectory) -> Result<ldap3::Ldap> {
        let settings = ldap3::LdapConnSettings::new().set_starttls(config.start_tls);

        let (connection, ldap) = ldap3::LdapConnAsync::with_settings(settings, &config.url)
            .await
            .map_err(|e| AppError::internal_from("connecting to a directory", e))?;

        // `ldap3` drives the protocol on a separate task; without this the
        // connection never makes progress.
        ldap3::drive!(connection);

        Ok(ldap)
    }
}

#[async_trait::async_trait]
impl Directory for LdapClient {
    async fn find(&self, config: &LdapDirectory, filter: &str) -> Result<Option<Entry>> {
        let mut ldap = Self::connect(config).await?;

        // The service account, or anonymous. An anonymous search is a
        // deliberate configuration, not a fallback: `create` refuses a bind DN
        // with no password precisely so this cannot happen by accident.
        if !config.bind_dn.is_empty() {
            let password = self.bind_password.as_deref().unwrap_or_default();
            ldap.simple_bind(&config.bind_dn, password)
                .await
                .map_err(|e| AppError::internal_from("binding as the service account", e))?
                .success()
                .map_err(|e| AppError::internal_from("the service account was refused", e))?;
        }

        let attributes = [
            config.attr_username.as_str(),
            config.attr_email.as_str(),
            config.attr_first_name.as_str(),
            config.attr_last_name.as_str(),
        ];

        let (results, _) = ldap
            .search(
                &config.user_base_dn,
                ldap3::Scope::Subtree,
                filter,
                attributes,
            )
            .await
            .map_err(|e| AppError::internal_from("searching a directory", e))?
            .success()
            .map_err(|e| AppError::internal_from("a directory search was refused", e))?;

        let _ = ldap.unbind().await;

        // More than one is not "pick the first": the filter does not identify
        // a person, and signing somebody in on that basis picks whoever the
        // directory happened to return.
        if results.len() > 1 {
            tracing::warn!(
                alias = %config.alias,
                matched = results.len(),
                "a directory filter matched more than one entry; refusing",
            );
            return Err(AppError::Unauthenticated);
        }

        let Some(result) = results.into_iter().next() else {
            return Ok(None);
        };

        let entry = ldap3::SearchEntry::construct(result);
        let first = |name: &str| {
            entry
                .attrs
                .get(name)
                .and_then(|values| values.first())
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };

        Ok(Some(Entry {
            dn: entry.dn.clone(),
            username: first(&config.attr_username),
            email: first(&config.attr_email),
            first_name: first(&config.attr_first_name),
            last_name: first(&config.attr_last_name),
        }))
    }

    async fn bind(&self, config: &LdapDirectory, dn: &str, password: &str) -> Result<bool> {
        // Belt and braces. `Credentials::new` refuses a blank password before
        // this is reachable, and this is the other end of the same rule: an
        // empty simple bind is an *anonymous* bind, and a directory answers it
        // with success.
        if password.is_empty() {
            return Ok(false);
        }

        let mut ldap = Self::connect(config).await?;

        let result = ldap
            .simple_bind(dn, password)
            .await
            .map_err(|e| AppError::internal_from("binding to a directory", e))?;

        let _ = ldap.unbind().await;

        // A non-zero result code is a refusal, not an error: "wrong password"
        // is an answer. Only a failure to *reach* the directory is an error,
        // and that is handled above.
        Ok(result.rc == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm;
    use crate::test_support;
    use std::sync::Mutex;

    /// A [`Directory`] that answers from a script and records what it was
    /// asked. Enough to exercise every rule that is ours; `ldap3`'s own
    /// behaviour is not what these tests are about.
    struct Scripted {
        entry: Option<Entry>,
        password: String,
        filters: Mutex<Vec<String>>,
        binds: Mutex<Vec<(String, String)>>,
    }

    impl Scripted {
        fn new(entry: Option<Entry>, password: &str) -> Self {
            Self {
                entry,
                password: password.to_owned(),
                filters: Mutex::new(Vec::new()),
                binds: Mutex::new(Vec::new()),
            }
        }

        fn last_filter(&self) -> Option<String> {
            self.filters.lock().unwrap().last().cloned()
        }
    }

    #[async_trait::async_trait]
    impl Directory for Scripted {
        async fn find(&self, _config: &LdapDirectory, filter: &str) -> Result<Option<Entry>> {
            self.filters.lock().unwrap().push(filter.to_owned());
            Ok(self.entry.clone())
        }

        async fn bind(&self, _config: &LdapDirectory, dn: &str, password: &str) -> Result<bool> {
            self.binds
                .lock()
                .unwrap()
                .push((dn.to_owned(), password.to_owned()));
            Ok(password == self.password.as_str())
        }
    }

    fn an_entry(dn: &str) -> Entry {
        Entry {
            dn: dn.to_owned(),
            username: Some("alice".to_owned()),
            email: Some("alice@example.com".to_owned()),
            first_name: Some("Alice".to_owned()),
            last_name: Some("Example".to_owned()),
        }
    }

    async fn a_directory(db: &Db, provision: bool) -> LdapDirectory {
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        create(
            db,
            &MasterKey::generate().unwrap(),
            NewDirectory {
                realm_id: realm.id,
                alias: "corp",
                display_name: "Corporate",
                url: "ldaps://ldap.example:636",
                start_tls: false,
                bind_dn: "cn=service,dc=example",
                bind_password: Some("service-password"),
                user_base_dn: "ou=people,dc=example",
                user_filter: "(&(objectClass=person)(uid={login}))",
                attr_username: "uid",
                attr_email: "mail",
                attr_first_name: "givenName",
                attr_last_name: "sn",
                allow_provisioning: provision,
            },
        )
        .await
        .unwrap()
    }

    // -- The three rules, without a database ---------------------------------

    #[test]
    fn an_empty_password_never_reaches_the_directory() {
        // The classic LDAP bypass: a simple bind with an empty password is an
        // *anonymous* bind, and a directory answers it with success. A server
        // that forwards one has authenticated nobody as somebody.
        let blank = String::new();
        assert!(Credentials::new("alice", &blank).is_err());
        assert!(Credentials::new("alice", test_support::password()).is_ok());
    }

    #[test]
    fn a_password_of_spaces_is_a_password() {
        // Trimming it would authenticate a different string than was typed.
        // What is refused is nothing at all, not whitespace.
        let typed = test_support::spaces();
        let credentials = Credentials::new("alice", &typed).unwrap();
        assert_eq!(credentials.password(), typed.as_str());
    }

    #[test]
    fn a_blank_login_is_refused() {
        assert!(Credentials::new("", test_support::password()).is_err());
        assert!(Credentials::new("   ", test_support::password()).is_err());
    }

    #[test]
    fn filter_metacharacters_are_escaped() {
        // `*)(uid=*` substituted raw closes the intended clause and opens a
        // match-anything one, so the first entry the directory returns signs
        // in as whoever it is.
        assert_eq!(escape_filter_value("*)(uid=*"), "\\2a\\29\\28uid=\\2a");
        assert_eq!(escape_filter_value("a\\b"), "a\\5cb");
        assert_eq!(escape_filter_value("alice"), "alice");
    }

    #[test]
    fn escaping_leaves_ordinary_unicode_alone() {
        // Escaping by byte is safe because every special character is ASCII
        // and a multi-byte character can never contain one — but the result
        // still has to be the original string.
        assert_eq!(escape_filter_value("zoë"), "zoë");
        assert_eq!(escape_filter_value("日本"), "日本");
    }

    #[test]
    fn a_plaintext_url_is_recognisable_as_unencrypted() {
        let encrypted = |url: &str, start_tls: bool| {
            LdapDirectory {
                id: uuid::Uuid::nil(),
                realm_id: RealmId(uuid::Uuid::nil()),
                alias: String::new(),
                display_name: String::new(),
                url: url.to_owned(),
                start_tls,
                bind_dn: String::new(),
                user_base_dn: String::new(),
                user_filter: String::new(),
                attr_username: String::new(),
                attr_email: String::new(),
                attr_first_name: String::new(),
                attr_last_name: String::new(),
                allow_provisioning: false,
                enabled: true,
                created_at: OffsetDateTime::now_utc(),
            }
            .is_encrypted()
        };

        assert!(encrypted("ldaps://host:636", false));
        assert!(encrypted("ldap://host:389", true));
        assert!(
            !encrypted("ldap://host:389", false),
            "a simple bind sends the password in the clear"
        );
    }

    // -- Against a database --------------------------------------------------

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_filter_without_the_placeholder_is_refused(db: Db) {
        // It would match the same thing for every login, so the first entry it
        // returns could sign in as anybody.
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let refused = create(
            &db,
            &MasterKey::generate().unwrap(),
            NewDirectory {
                realm_id: realm.id,
                alias: "corp",
                display_name: "Corporate",
                url: "ldaps://ldap.example:636",
                start_tls: false,
                bind_dn: "",
                bind_password: None,
                user_base_dn: "ou=people,dc=example",
                user_filter: "(objectClass=person)",
                attr_username: "uid",
                attr_email: "mail",
                attr_first_name: "givenName",
                attr_last_name: "sn",
                allow_provisioning: true,
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 400);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_bind_dn_without_a_password_is_refused(db: Db) {
        // It would bind anonymously while looking like it had credentials.
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let refused = create(
            &db,
            &MasterKey::generate().unwrap(),
            NewDirectory {
                realm_id: realm.id,
                alias: "corp",
                display_name: "Corporate",
                url: "ldaps://ldap.example:636",
                start_tls: false,
                bind_dn: "cn=service,dc=example",
                bind_password: None,
                user_base_dn: "ou=people,dc=example",
                user_filter: "(uid={login})",
                attr_username: "uid",
                attr_email: "mail",
                attr_first_name: "givenName",
                attr_last_name: "sn",
                allow_provisioning: true,
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 400);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_bind_password_is_sealed_and_not_in_the_record(db: Db) {
        let config = a_directory(&db, true).await;
        let master = MasterKey::generate().unwrap();

        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("service-password"), "{json}");

        // It does not open under a different key.
        assert!(bind_password(&db, &master, config.id).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_first_sign_in_provisions_an_account(db: Db) {
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        let signed_in = authenticate(&db, &directory, &config, &credentials)
            .await
            .unwrap();

        assert!(signed_in.provisioned);
        assert_eq!(signed_in.user.username, "alice");
        assert_eq!(signed_in.user.email, "alice@example.com");
        // The directory vouched for the address, and reaching it required the
        // person's own password.
        assert!(signed_in.user.email_verified);
        assert_eq!(signed_in.user.first_name.as_deref(), Some("Alice"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_login_is_escaped_into_the_filter(db: Db) {
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(None, test_support::password());
        let credentials = Credentials::new("*)(uid=*", test_support::password()).unwrap();

        let _ = authenticate(&db, &directory, &config, &credentials).await;

        assert_eq!(
            directory.last_filter().unwrap(),
            "(&(objectClass=person)(uid=\\2a\\29\\28uid=\\2a))",
            "an unescaped login rewrites the filter",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_wrong_password_does_not_provision_anything(db: Db) {
        // The order the module documents: authenticate first, resolve second.
        // A wrong password must never reach the provisioning path.
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let credentials = Credentials::new("alice", &test_support::another_password()).unwrap();

        assert!(
            authenticate(&db, &directory, &config, &credentials)
                .await
                .is_err()
        );

        let count = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM users"#)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(count, 0, "a wrong password created an account");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_bind_is_against_the_entrys_dn_not_the_typed_login(db: Db) {
        // Binding as the typed name would authenticate against whatever that
        // string happens to resolve to, which is not the entry the search
        // found.
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        authenticate(&db, &directory, &config, &credentials)
            .await
            .unwrap();

        let binds = directory.binds.lock().unwrap();
        assert_eq!(binds[0].0, "uid=alice,ou=people,dc=example");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_second_sign_in_finds_the_same_account(db: Db) {
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        let first = authenticate(&db, &directory, &config, &credentials)
            .await
            .unwrap();
        let second = authenticate(&db, &directory, &config, &credentials)
            .await
            .unwrap();

        assert!(first.provisioned);
        assert!(!second.provisioned);
        assert_eq!(first.user.id, second.user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_dn_in_a_different_case_is_the_same_identity(db: Db) {
        // Two spellings of one DN becoming two local accounts is the failure
        // `normalise_dn` prevents.
        let config = a_directory(&db, true).await;
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        let lower = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let upper = Scripted::new(
            Some(an_entry("UID=Alice,OU=People,DC=Example")),
            test_support::password(),
        );

        let first = authenticate(&db, &lower, &config, &credentials)
            .await
            .unwrap();
        let second = authenticate(&db, &upper, &config, &credentials)
            .await
            .unwrap();

        assert_eq!(first.user.id, second.user.id);
        assert!(!second.provisioned);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_account_is_refused(db: Db) {
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(None, test_support::password());
        let credentials = Credentials::new("nobody", test_support::password()).unwrap();

        assert!(
            authenticate(&db, &directory, &config, &credentials)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn provisioning_can_be_refused(db: Db) {
        let config = a_directory(&db, false).await;
        let directory = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        assert!(
            authenticate(&db, &directory, &config, &credentials)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_directory_admits_nobody(db: Db) {
        let config = a_directory(&db, true).await;
        let config = set_enabled(&db, config.id, false).await.unwrap();
        let directory = Scripted::new(
            Some(an_entry("uid=alice,ou=people,dc=example")),
            test_support::password(),
        );
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        assert!(
            authenticate(&db, &directory, &config, &credentials)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_entry_with_no_dn_is_refused(db: Db) {
        let config = a_directory(&db, true).await;
        let directory = Scripted::new(Some(an_entry("   ")), test_support::password());
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        assert!(
            authenticate(&db, &directory, &config, &credentials)
                .await
                .is_err(),
            "there is nothing to bind as",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_account_with_no_address_cannot_be_provisioned(db: Db) {
        let config = a_directory(&db, true).await;
        let mut entry = an_entry("uid=alice,ou=people,dc=example");
        entry.email = None;
        let directory = Scripted::new(Some(entry), test_support::password());
        let credentials = Credentials::new("alice", test_support::password()).unwrap();

        assert!(
            authenticate(&db, &directory, &config, &credentials)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_alias_is_unique_within_a_realm(db: Db) {
        let config = a_directory(&db, true).await;
        let refused = create(
            &db,
            &MasterKey::generate().unwrap(),
            NewDirectory {
                realm_id: config.realm_id,
                alias: "corp",
                display_name: "Another",
                url: "ldaps://other.example:636",
                start_tls: false,
                bind_dn: "",
                bind_password: None,
                user_base_dn: "ou=people,dc=example",
                user_filter: "(uid={login})",
                attr_username: "uid",
                attr_email: "mail",
                attr_first_name: "givenName",
                attr_last_name: "sn",
                allow_provisioning: true,
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 409);
    }
}
