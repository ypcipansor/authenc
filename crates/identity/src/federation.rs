//! Social login: signing in with an account held somewhere else.
//!
//! This module owns the *account* half — which upstream identity maps to which
//! local user, and what may create or adopt one. The protocol half, talking to
//! the provider over HTTP, lives in `authenc_oauth::social`, because it is an
//! OAuth client and this crate stays free of anything that makes a request.
//!
//! # The rule that matters
//!
//! An upstream `sub` is the identity. An email address is not: it can be
//! reassigned, and at several providers it can be changed by the account
//! holder. Resolving a sign-in therefore looks only at `(provider, subject)`.
//!
//! Adopting an *existing* local account is the dangerous operation, and it is
//! off unless an operator turns it on per provider. Even then the upstream has
//! to assert the address is verified, because a provider that will say
//! `admin@yourcompany.example` without checking is a provider that hands over
//! the local administrator.
//!
//! # Why this returns [`login::Outcome`]
//!
//! A federated sign-in goes through the same second-factor machinery as a
//! password one. The alternative — completing the session directly — would
//! make "configure a social provider" a way around every second factor already
//! enrolled, which is the sort of bypass that is only ever noticed afterwards.

use authenc_contract::{
    AppError, IdentityProviderId, RealmId, Result, UserId,
    event::Action,
    model::{Realm, User},
};
use time::OffsetDateTime;

use crate::{
    audit::{self, Entry},
    db::Db,
    login::{self, Authenticated},
    mfa, organization,
    sealed::{self, MasterKey},
    session::{self, Origin},
    user,
};

/// Which claim mapping a provider needs.
///
/// Endpoints are configuration, not code — a provider that moves one must not
/// need a release. What genuinely differs between providers is the *shape of
/// the claims* they return, and that is what this selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Google, via OpenID Connect.
    Google,
    /// GitHub, whose API is OAuth 2.0 and not OIDC.
    GitHub,
    /// Microsoft Entra ID.
    Microsoft,
    /// Facebook Login.
    Facebook,
    /// Sign in with Apple.
    Apple,
    /// Any standards-compliant OpenID Connect provider.
    Oidc,
}

impl Kind {
    /// Every kind this build understands.
    pub const ALL: &'static [Self] = &[
        Self::Google,
        Self::GitHub,
        Self::Microsoft,
        Self::Facebook,
        Self::Apple,
        Self::Oidc,
    ];

    /// The stored name, which is also the name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::GitHub => "github",
            Self::Microsoft => "microsoft",
            Self::Facebook => "facebook",
            Self::Apple => "apple",
            Self::Oidc => "oidc",
        }
    }

    /// Parse a stored name.
    ///
    /// # Errors
    ///
    /// [`AppError::Validation`] if it matches nothing known.
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == value)
            .ok_or_else(|| AppError::field("kind", "must be a supported provider kind"))
    }
}

impl serde::Serialize for Kind {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for Kind {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let name = <std::borrow::Cow<'_, str>>::deserialize(deserializer)?;
        Self::parse(&name).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A configured upstream provider, as callers see it.
///
/// Carries the client id, which is public, and never the client secret. The
/// secret is reachable only through [`client_secret`], which every read path
/// other than the sign-in flow deliberately does not call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provider {
    /// Stable identifier.
    pub id: IdentityProviderId,
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// URL-safe handle, appearing in the callback path.
    pub alias: String,
    /// Which claim mapping to use.
    pub kind: Kind,
    /// What the login page calls it.
    pub display_name: String,
    /// The OAuth client id registered with the provider.
    pub client_id: String,
    /// Where to send the browser.
    pub authorization_endpoint: String,
    /// Where to redeem the code.
    pub token_endpoint: String,
    /// Where to read the claims, for a provider that does not put them all in
    /// the ID token.
    pub userinfo_endpoint: Option<String>,
    /// The expected `iss`, for a provider that issues an ID token.
    pub issuer: Option<String>,
    /// What to ask for.
    pub scopes: Vec<String>,
    /// Whether it is offered on the login page.
    pub enabled: bool,
    /// Whether an unrecognised upstream account may create a local one.
    pub allow_provisioning: bool,
    /// Whether a *verified* upstream address may adopt an existing local
    /// account. Off by default; see the module documentation.
    pub link_by_verified_email: bool,
    /// When it was configured.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// What a new provider needs.
#[derive(Debug, Clone)]
pub struct NewProvider<'a> {
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// URL-safe handle.
    pub alias: &'a str,
    /// Which claim mapping to use.
    pub kind: Kind,
    /// What the login page calls it.
    pub display_name: &'a str,
    /// The OAuth client id.
    pub client_id: &'a str,
    /// The OAuth client secret. Sealed before it reaches the database.
    pub client_secret: &'a str,
    /// Where to send the browser.
    pub authorization_endpoint: &'a str,
    /// Where to redeem the code.
    pub token_endpoint: &'a str,
    /// Where to read the claims.
    pub userinfo_endpoint: Option<&'a str>,
    /// The expected `iss`.
    pub issuer: Option<&'a str>,
    /// What to ask for.
    pub scopes: &'a [String],
    /// Whether an unrecognised upstream account may create a local one.
    pub allow_provisioning: bool,
    /// Whether a verified upstream address may adopt an existing local account.
    pub link_by_verified_email: bool,
}

/// What an upstream told us about the person signing in.
///
/// Normalised by `authenc_oauth::social` from whatever shape the provider
/// returns, so this module sees one type whichever provider was used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// The upstream `sub`. The identity.
    pub subject: String,
    /// The address the upstream reports, if any.
    pub email: Option<String>,
    /// Whether the upstream says it verified that address.
    ///
    /// Not a convenience flag: it is the whole difference between adopting an
    /// account safely and handing it to whoever can type the address into a
    /// provider that does not check.
    pub email_verified: bool,
    /// A display name, if the upstream offers one.
    pub name: Option<String>,
    /// A username suggestion, if the upstream offers one.
    pub preferred_username: Option<String>,
}

/// A link between a local user and an upstream account.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Link {
    /// The provider.
    pub provider_id: IdentityProviderId,
    /// Its alias, so a console does not need a second query.
    pub provider_alias: String,
    /// What the login page calls it.
    pub provider_display_name: String,
    /// The local user.
    pub user_id: UserId,
    /// The address the upstream reported when the link was made.
    pub upstream_email: Option<String>,
    /// When it was linked.
    #[serde(with = "time::serde::rfc3339")]
    pub linked_at: OffsetDateTime,
    /// When it was last used to sign in.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

fn translate(error: sqlx::Error, context: &'static str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        match db_error.code().as_deref() {
            Some("23505") => return AppError::conflict("that already exists in this realm"),
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

// ---------------------------------------------------------------------------
// Providers
// ---------------------------------------------------------------------------

/// Configure a provider.
///
/// # Errors
///
/// [`AppError::Validation`] for a malformed alias or a blank name,
/// [`AppError::Conflict`] if the alias is taken in that realm.
pub async fn create(db: &Db, master: &MasterKey, new: NewProvider<'_>) -> Result<Provider> {
    let alias = new.alias.trim();
    if alias.is_empty() {
        return Err(AppError::field("alias", "must not be empty"));
    }
    let display_name = new.display_name.trim();
    if display_name.is_empty() {
        return Err(AppError::field("display_name", "must not be empty"));
    }
    if new.client_secret.is_empty() {
        return Err(AppError::field("client_secret", "must not be empty"));
    }

    // The id has to exist before the secret can be sealed against it, and the
    // secret has to be sealed before it is stored. One statement cannot do
    // both, so the id is generated here rather than by the default.
    let id = IdentityProviderId::new();
    let sealed = sealed::seal(master, id.0.as_bytes(), new.client_secret.as_bytes())?;

    let row = sqlx::query!(
        r#"
        INSERT INTO identity_providers
            (id, realm_id, alias, kind, display_name, client_id,
             client_secret_ciphertext, client_secret_nonce,
             authorization_endpoint, token_endpoint, userinfo_endpoint, issuer,
             scopes, allow_provisioning, link_by_verified_email)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
        RETURNING created_at, enabled
        "#,
        id.0,
        new.realm_id.0,
        alias,
        new.kind.as_str(),
        display_name,
        new.client_id,
        sealed.ciphertext,
        &sealed.nonce[..],
        new.authorization_endpoint,
        new.token_endpoint,
        new.userinfo_endpoint,
        new.issuer,
        new.scopes,
        new.allow_provisioning,
        new.link_by_verified_email,
    )
    .fetch_one(db)
    .await
    .map_err(|e| translate(e, "configuring an identity provider"))?;

    Ok(Provider {
        id,
        realm_id: new.realm_id,
        alias: alias.to_owned(),
        kind: new.kind,
        display_name: display_name.to_owned(),
        client_id: new.client_id.to_owned(),
        authorization_endpoint: new.authorization_endpoint.to_owned(),
        token_endpoint: new.token_endpoint.to_owned(),
        userinfo_endpoint: new.userinfo_endpoint.map(ToOwned::to_owned),
        issuer: new.issuer.map(ToOwned::to_owned),
        scopes: new.scopes.to_vec(),
        enabled: row.enabled,
        allow_provisioning: new.allow_provisioning,
        link_by_verified_email: new.link_by_verified_email,
        created_at: row.created_at,
    })
}

/// The row shape shared by every provider read.
macro_rules! provider_from_row {
    ($row:expr) => {
        Provider {
            id: IdentityProviderId($row.id),
            realm_id: RealmId($row.realm_id),
            alias: $row.alias,
            kind: Kind::parse(&$row.kind)?,
            display_name: $row.display_name,
            client_id: $row.client_id,
            authorization_endpoint: $row.authorization_endpoint,
            token_endpoint: $row.token_endpoint,
            userinfo_endpoint: $row.userinfo_endpoint,
            issuer: $row.issuer,
            scopes: $row.scopes,
            enabled: $row.enabled,
            allow_provisioning: $row.allow_provisioning,
            link_by_verified_email: $row.link_by_verified_email,
            created_at: $row.created_at,
        }
    };
}

/// Look one up by id.
///
/// # Errors
///
/// [`AppError::NotFound`] if no provider has that id.
pub async fn by_id(db: &Db, id: IdentityProviderId) -> Result<Provider> {
    let row = sqlx::query!(
        r#"
        SELECT id, realm_id, alias, kind, display_name, client_id,
               authorization_endpoint, token_endpoint, userinfo_endpoint,
               issuer, scopes, enabled, allow_provisioning,
               link_by_verified_email, created_at
          FROM identity_providers WHERE id = $1
        "#,
        id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading an identity provider", e))?
    .ok_or(AppError::NotFound("identity provider"))?;

    Ok(provider_from_row!(row))
}

/// Look one up by realm and alias, which is what a callback URL carries.
///
/// # Errors
///
/// [`AppError::NotFound`] if there is no such provider.
pub async fn by_alias(db: &Db, realm_id: RealmId, alias: &str) -> Result<Provider> {
    let row = sqlx::query!(
        r#"
        SELECT id, realm_id, alias, kind, display_name, client_id,
               authorization_endpoint, token_endpoint, userinfo_endpoint,
               issuer, scopes, enabled, allow_provisioning,
               link_by_verified_email, created_at
          FROM identity_providers WHERE realm_id = $1 AND alias = $2
        "#,
        realm_id.0,
        alias,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading an identity provider", e))?
    .ok_or(AppError::NotFound("identity provider"))?;

    Ok(provider_from_row!(row))
}

/// Every provider in a realm, by name.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, realm_id: RealmId) -> Result<Vec<Provider>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, realm_id, alias, kind, display_name, client_id,
               authorization_endpoint, token_endpoint, userinfo_endpoint,
               issuer, scopes, enabled, allow_provisioning,
               link_by_verified_email, created_at
          FROM identity_providers WHERE realm_id = $1 ORDER BY display_name
        "#,
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing identity providers", e))?;

    rows.into_iter()
        .map(|row| Ok(provider_from_row!(row)))
        .collect()
}

/// The client secret, decrypted.
///
/// Called by the token exchange and by nothing else. It is a separate function
/// rather than a field on [`Provider`] precisely so that every caller that
/// wants the secret has to say so, and a `Provider` cannot carry one into a
/// log line or a DTO.
///
/// # Errors
///
/// [`AppError::NotFound`] if the provider is gone, or an internal error if the
/// ciphertext does not open — which means the master key changed.
pub async fn client_secret(db: &Db, master: &MasterKey, id: IdentityProviderId) -> Result<String> {
    let row = sqlx::query!(
        "SELECT client_secret_ciphertext, client_secret_nonce FROM identity_providers WHERE id = $1",
        id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading a client secret", e))?
    .ok_or(AppError::NotFound("identity provider"))?;

    let plaintext = sealed::open(
        master,
        id.0.as_bytes(),
        &row.client_secret_ciphertext,
        &row.client_secret_nonce,
        "identity provider client secret",
    )?;

    String::from_utf8(plaintext).map_err(|e| AppError::internal_from("decoding a client secret", e))
}

/// Enable or disable a provider.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn set_enabled(db: &Db, id: IdentityProviderId, enabled: bool) -> Result<Provider> {
    let result = sqlx::query!(
        "UPDATE identity_providers SET enabled = $2 WHERE id = $1",
        id.0,
        enabled,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("changing an identity provider", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("identity provider"));
    }
    by_id(db, id).await
}

/// Delete a provider and every link through it.
///
/// The users themselves remain. Someone whose only credential was this
/// provider is left unable to sign in, which is why the console warns and the
/// audit record names how many links went with it.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn delete(db: &Db, id: IdentityProviderId) -> Result<()> {
    let result = sqlx::query!("DELETE FROM identity_providers WHERE id = $1", id.0)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("deleting an identity provider", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("identity provider"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

/// Every upstream account attached to a user.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn links_of(db: &Db, user_id: UserId) -> Result<Vec<Link>> {
    let rows = sqlx::query!(
        r#"
        SELECT f.provider_id, f.user_id, f.upstream_email, f.linked_at,
               f.last_login_at, p.alias, p.display_name
          FROM federated_identities f
          JOIN identity_providers p ON p.id = f.provider_id
         WHERE f.user_id = $1
         ORDER BY p.display_name
        "#,
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing a user's linked accounts", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Link {
            provider_id: IdentityProviderId(row.provider_id),
            provider_alias: row.alias,
            provider_display_name: row.display_name,
            user_id: UserId(row.user_id),
            upstream_email: row.upstream_email,
            linked_at: row.linked_at,
            last_login_at: row.last_login_at,
        })
        .collect())
}

/// How many accounts are attached through a provider.
///
/// Read before deleting one, because afterwards there is nothing to count and
/// "how many people lost their way in?" is the question the audit record
/// exists to answer.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn link_count(db: &Db, provider_id: IdentityProviderId) -> Result<i64> {
    sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM federated_identities WHERE provider_id = $1"#,
        provider_id.0,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting linked accounts", e))
}

/// Attach an upstream account to a local one.
///
/// # Errors
///
/// [`AppError::Conflict`] if that upstream account is already attached to
/// somebody, or if this user already has an identity with this provider.
pub async fn link(
    db: &Db,
    provider_id: IdentityProviderId,
    user_id: UserId,
    claims: &Claims,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO federated_identities
            (provider_id, user_id, subject, upstream_email, upstream_name)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        provider_id.0,
        user_id.0,
        claims.subject,
        claims.email,
        claims.name,
    )
    .execute(db)
    .await
    .map_err(|e| translate(e, "linking an upstream account"))?;

    Ok(())
}

/// Detach an upstream account.
///
/// Refuses to remove the last way in. An account with no password and no other
/// link is one whose owner would need an administrator to recover, and the
/// moment to say so is before it happens rather than after.
///
/// # Errors
///
/// [`AppError::NotFound`] if there is no such link, or
/// [`AppError::Validation`] if it is the account's only credential.
pub async fn unlink(db: &Db, provider_id: IdentityProviderId, user_id: UserId) -> Result<()> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("unlinking an upstream account", e))?;

    // Lock the user row: two concurrent unlinks could otherwise each see the
    // other link and both proceed, leaving none.
    sqlx::query_scalar!("SELECT id FROM users WHERE id = $1 FOR UPDATE", user_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AppError::internal_from("locking a user", e))?
        .ok_or(AppError::NotFound("user"))?;

    let has_password = sqlx::query_scalar!(
        r#"SELECT EXISTS (SELECT 1 FROM user_passwords WHERE user_id = $1) AS "exists!""#,
        user_id.0,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("checking for a password", e))?;

    let links = sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM federated_identities WHERE user_id = $1"#,
        user_id.0,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("counting linked accounts", e))?;

    if !has_password && links <= 1 {
        return Err(AppError::validation(
            "that is the only way into this account; set a password first",
        ));
    }

    let result = sqlx::query!(
        "DELETE FROM federated_identities WHERE provider_id = $1 AND user_id = $2",
        provider_id.0,
        user_id.0,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("unlinking an upstream account", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("linked account"));
    }

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("unlinking an upstream account", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Signing in
// ---------------------------------------------------------------------------

/// How an upstream identity resolved to a local account.
///
/// Returned alongside the outcome so the caller can tell the user what
/// happened — "we made you an account" and "we found your existing one" are
/// different sentences, and the second is the one worth being sure about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// The upstream account was already linked.
    Existing,
    /// A verified upstream address matched a local account, which adopted it.
    AdoptedByEmail,
    /// Nobody matched, so an account was created.
    Provisioned,
}

/// A federated sign-in that got as far as a local account.
#[derive(Debug)]
pub struct SignedIn {
    /// Complete, or waiting on a second factor. Same type as a password login,
    /// deliberately: a social provider is not a way around MFA.
    pub outcome: login::Outcome,
    /// How the local account was found.
    pub resolution: Resolution,
}

/// Sign in with claims an upstream has already asserted.
///
/// The caller is responsible for having verified those claims — that is
/// `authenc_oauth::social`'s job, and it is the reason this takes [`Claims`]
/// rather than a code to redeem.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — the provider or realm is disabled, the
///   account is disabled, or nothing matched and provisioning is off.
/// * [`AppError::Conflict`] — provisioning collided with an existing username
///   or address that is not this identity's.
pub async fn sign_in(
    db: &Db,
    provider: &Provider,
    claims: &Claims,
    origin: Origin<'_>,
) -> Result<SignedIn> {
    if !provider.enabled {
        return Err(AppError::Unauthenticated);
    }

    let realm = crate::realm::by_id(db, provider.realm_id).await?;
    if !realm.enabled {
        return Err(AppError::Unauthenticated);
    }

    if claims.subject.trim().is_empty() {
        // A provider that returns no subject has told us nothing about who
        // this is. Signing somebody in on that basis would key every user of
        // that provider to the same empty string.
        refused(db, provider, "the provider returned no subject", origin).await;
        return Err(AppError::Unauthenticated);
    }

    let (user, resolution) = match existing_link(db, provider.id, &claims.subject).await? {
        Some(user_id) => (user::by_id(db, user_id).await?, Resolution::Existing),
        None => adopt_or_provision(db, provider, claims, &realm, origin).await?,
    };

    if !user.enabled {
        refused(db, provider, "the account is disabled", origin).await;
        return Err(AppError::Unauthenticated);
    }

    // The same gate the password path applies, for the same reason: a
    // suspended organisation stops its members signing in however they arrive.
    if organization::blocks_sign_in(db, user.id).await? {
        refused(db, provider, "the organisation is suspended", origin).await;
        return Err(AppError::Unauthenticated);
    }

    touch(db, provider.id, user.id).await?;

    // A second factor still applies. Whatever the upstream verified, it did
    // not verify the factor enrolled here.
    let factors = mfa::enrolment(db, user.id).await?.available();
    if !factors.is_empty() {
        let issued =
            mfa::challenge::issue(db, user.id, realm.id, mfa::FirstFactor::Federated, origin)
                .await?;

        audit::observe(
            db,
            Entry::success(Action::SecondFactorRequired)
                .in_realm(realm.id)
                .by(user.id, &user.username)
                .from(origin)
                .detail(serde_json::json!({ "provider": provider.alias })),
        )
        .await;

        return Ok(SignedIn {
            outcome: login::Outcome::SecondFactorRequired(Box::new(login::Challenged {
                user,
                issued,
                factors,
            })),
            resolution,
        });
    }

    let session = session::create(
        db,
        user.id,
        realm.id,
        mfa::amr_for(mfa::FirstFactor::Federated, None),
        origin,
    )
    .await?;

    audit::observe(
        db,
        Entry::success(Action::FederatedLoginSucceeded)
            .in_realm(realm.id)
            .by(user.id, &user.username)
            .from(origin)
            .detail(serde_json::json!({
                "provider": provider.alias,
                "resolution": resolution,
            })),
    )
    .await;

    Ok(SignedIn {
        outcome: login::Outcome::Complete(Box::new(Authenticated { user, session })),
        resolution,
    })
}

/// Which local user, if any, this upstream account is already attached to.
async fn existing_link(
    db: &Db,
    provider_id: IdentityProviderId,
    subject: &str,
) -> Result<Option<UserId>> {
    let found = sqlx::query_scalar!(
        "SELECT user_id FROM federated_identities WHERE provider_id = $1 AND subject = $2",
        provider_id.0,
        subject,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("resolving a federated identity", e))?;

    Ok(found.map(UserId))
}

/// Nothing was linked. Decide whether an existing account may be adopted, or a
/// new one created, or neither.
async fn adopt_or_provision(
    db: &Db,
    provider: &Provider,
    claims: &Claims,
    realm: &Realm,
    origin: Origin<'_>,
) -> Result<(User, Resolution)> {
    // Adoption first, and only under both conditions. `link_by_verified_email`
    // is the operator's decision that this provider's word is good enough;
    // `email_verified` is that provider's word in this particular case. Either
    // one missing means the address proves nothing.
    if provider.link_by_verified_email
        && claims.email_verified
        && let Some(email) = claims.email.as_deref()
        && let Some(user_id) = user::id_by_email(db, realm.id, email).await?
    {
        let user = user::by_id(db, user_id).await?;
        link(db, provider.id, user_id, claims).await?;

        audit::observe(
            db,
            Entry::success(Action::FederatedIdentityLinked)
                .in_realm(realm.id)
                .by(user.id, &user.username)
                .from(origin)
                .detail(serde_json::json!({
                    "provider": provider.alias,
                    "matched_on": "verified_email",
                })),
        )
        .await;

        return Ok((user, Resolution::AdoptedByEmail));
    }

    if !provider.allow_provisioning {
        refused(
            db,
            provider,
            "no local account, and provisioning is off",
            origin,
        )
        .await;
        return Err(AppError::Unauthenticated);
    }

    // Provisioning needs an address: it is the account's identity here, and a
    // user with none cannot reset a password or be contacted.
    let email = claims
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or_else(|| {
            AppError::validation("the provider returned no email address to create an account with")
        })?;

    let username = provisioned_username(claims, email);

    let user = user::create_without_password(
        db,
        user::NewFederatedUser {
            realm_id: realm.id,
            username: &username,
            email,
            // Trusted only as far as the upstream's own assertion goes. An
            // unverified address produces an unverified local account, which
            // is exactly what a locally registered one would get.
            email_verified: claims.email_verified,
            display_name: claims.name.as_deref(),
        },
    )
    .await?;

    link(db, provider.id, user.id, claims).await?;

    audit::observe(
        db,
        Entry::success(Action::FederatedUserProvisioned)
            .in_realm(realm.id)
            .by(user.id, &user.username)
            .from(origin)
            .detail(serde_json::json!({ "provider": provider.alias })),
    )
    .await;

    Ok((user, Resolution::Provisioned))
}

/// A username for a newly provisioned account.
///
/// Prefers what the upstream suggests, falls back to the local part of the
/// address, and refuses neither — a collision is a `Conflict` from
/// `user::create_without_password` rather than a silently mangled name,
/// because two people quietly sharing a username is worse than one sign-in
/// that fails and says why.
fn provisioned_username(claims: &Claims, email: &str) -> String {
    claims
        .preferred_username
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| email.split('@').next().unwrap_or(email))
        .to_owned()
}

/// Record that this sign-in was refused, and why.
///
/// The reason goes in the audit detail and never to the caller: every refusal
/// here is one `Unauthenticated`, so a prober cannot tell "no such account"
/// from "provisioning is off" from "your organisation is suspended".
async fn refused(db: &Db, provider: &Provider, reason: &str, origin: Origin<'_>) {
    audit::observe(
        db,
        Entry::failure(Action::FederatedLoginFailed)
            .in_realm(provider.realm_id)
            .from(origin)
            .detail(serde_json::json!({
                "provider": provider.alias,
                "reason": reason,
            })),
    )
    .await;
}

/// Record that this link was just used.
async fn touch(db: &Db, provider_id: IdentityProviderId, user_id: UserId) -> Result<()> {
    sqlx::query!(
        "UPDATE federated_identities SET last_login_at = now() \
         WHERE provider_id = $1 AND user_id = $2",
        provider_id.0,
        user_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording a federated sign-in", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::{
        password::PasswordHasher,
        realm,
        user::{self, NewUser},
    };

    fn claims(subject: &str, email: Option<&str>, verified: bool) -> Claims {
        Claims {
            subject: subject.to_owned(),
            email: email.map(ToOwned::to_owned),
            email_verified: verified,
            name: Some("Alice Example".to_owned()),
            preferred_username: None,
        }
    }

    async fn a_user(db: &Db, realm_id: RealmId, username: &str) -> User {
        user::create(
            db,
            &PasswordHasher::new(),
            NewUser {
                realm_id,
                username,
                email: &format!("{username}@example.com"),
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap()
    }

    /// A realm with one provider. `adopt` and `provision` are the two settings
    /// every test here is really about.
    async fn fixture(db: &Db, adopt: bool, provision: bool) -> (RealmId, MasterKey, Provider) {
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let master = MasterKey::generate().unwrap();
        let provider = create(
            db,
            &master,
            NewProvider {
                realm_id: realm.id,
                alias: "google",
                kind: Kind::Google,
                display_name: "Google",
                client_id: "client-id",
                client_secret: "client-secret",
                authorization_endpoint: "https://accounts.example/authorize",
                token_endpoint: "https://accounts.example/token",
                userinfo_endpoint: Some("https://accounts.example/userinfo"),
                issuer: Some("https://accounts.example"),
                scopes: &["openid".to_owned(), "email".to_owned()],
                allow_provisioning: provision,
                link_by_verified_email: adopt,
            },
        )
        .await
        .unwrap();
        (realm.id, master, provider)
    }

    #[test]
    fn every_kind_round_trips_through_its_stored_name() {
        // One name on the wire and in the database, as for `Permission` and
        // `Action`. A derived spelling would be a second name for the same
        // thing, and only one of the two would parse back.
        for kind in Kind::ALL {
            assert_eq!(Kind::parse(kind.as_str()).unwrap(), *kind);
            let json = serde_json::to_string(kind).unwrap();
            assert_eq!(serde_json::from_str::<Kind>(&json).unwrap(), *kind);
        }
    }

    #[test]
    fn an_unknown_kind_is_refused_rather_than_guessed() {
        assert!(Kind::parse("okta").is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_client_secret_is_not_readable_from_the_provider_record(db: Db) {
        let (_realm, master, provider) = fixture(&db, false, true).await;

        // The struct simply has no field for it, so this is really a test that
        // the serialised form does not carry one either — that is the shape a
        // secret leaks in.
        let json = serde_json::to_string(&provider).unwrap();
        assert!(!json.contains("client-secret"), "{json}");

        // And it is reachable when deliberately asked for.
        assert_eq!(
            client_secret(&db, &master, provider.id).await.unwrap(),
            "client-secret"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_client_secret_does_not_open_under_a_different_master_key(db: Db) {
        let (_realm, _master, provider) = fixture(&db, false, true).await;
        let other = MasterKey::generate().unwrap();

        assert!(client_secret(&db, &other, provider.id).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_first_sign_in_provisions_an_account(db: Db) {
        let (realm_id, _master, provider) = fixture(&db, false, true).await;

        let signed_in = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await
        .unwrap();

        assert_eq!(signed_in.resolution, Resolution::Provisioned);
        let login::Outcome::Complete(authenticated) = signed_in.outcome else {
            panic!("no second factor is enrolled");
        };
        assert_eq!(authenticated.user.realm_id, realm_id);
        assert_eq!(authenticated.user.email, "alice@example.com");
        assert_eq!(authenticated.user.username, "alice");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_provisioned_account_has_no_password_to_guess(db: Db) {
        // The point of provisioning without a credential: the account exists,
        // and the password path can never admit it.
        let (realm_id, _master, provider) = fixture(&db, false, true).await;

        sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await
        .unwrap();

        let refused = login::authenticate(
            &db,
            &PasswordHasher::new(),
            login::Attempt {
                realm: "acme",
                identifier: "alice",
                password: test_support::password(),
                origin: Origin::default(),
            },
        )
        .await;

        assert!(refused.is_err(), "a passwordless account has no password");
        let _ = realm_id;
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_second_sign_in_finds_the_same_account(db: Db) {
        let (_realm, _master, provider) = fixture(&db, false, true).await;
        let asserted = claims("upstream-1", Some("alice@example.com"), true);

        let first = sign_in(&db, &provider, &asserted, Origin::default())
            .await
            .unwrap();
        let second = sign_in(&db, &provider, &asserted, Origin::default())
            .await
            .unwrap();

        assert_eq!(second.resolution, Resolution::Existing);

        let (login::Outcome::Complete(a), login::Outcome::Complete(b)) =
            (first.outcome, second.outcome)
        else {
            panic!("no second factor is enrolled");
        };
        assert_eq!(a.user.id, b.user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_subject_is_the_identity_not_the_address(db: Db) {
        // The upstream changed the address on the same account. It is still
        // the same person, and keying on the address would have made it a
        // different one — or worse, someone else's.
        let (_realm, _master, provider) = fixture(&db, false, true).await;

        let first = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await
        .unwrap();

        let second = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice.new@example.com"), true),
            Origin::default(),
        )
        .await
        .unwrap();

        assert_eq!(second.resolution, Resolution::Existing);
        let (login::Outcome::Complete(a), login::Outcome::Complete(b)) =
            (first.outcome, second.outcome)
        else {
            panic!("no second factor is enrolled");
        };
        assert_eq!(a.user.id, b.user.id);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_different_subject_at_the_same_address_does_not_take_the_account(db: Db) {
        // The attack this whole design is arranged against: a second upstream
        // account claiming an address that already belongs to somebody here.
        // With adoption off, it gets its own account or nothing — never the
        // existing one.
        let (realm_id, _master, provider) = fixture(&db, false, true).await;
        let existing = a_user(&db, realm_id, "alice").await;

        let refused = sign_in(
            &db,
            &provider,
            &claims("attacker", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await;

        // Provisioning collides with the taken address rather than adopting.
        assert!(refused.is_err(), "must not take over an existing account");

        let still_there = user::by_id(&db, existing.id).await.unwrap();
        assert_eq!(still_there.email, "alice@example.com");
        assert!(links_of(&db, existing.id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn adoption_requires_the_operator_to_have_allowed_it(db: Db) {
        let (realm_id, _master, provider) = fixture(&db, false, true).await;
        let existing = a_user(&db, realm_id, "alice").await;

        let refused = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await;

        assert!(refused.is_err());
        assert!(links_of(&db, existing.id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn adoption_requires_the_upstream_to_have_verified_the_address(db: Db) {
        // Adoption is on, and the provider still says it has not checked. That
        // is the case where an address proves nothing at all.
        let (realm_id, _master, provider) = fixture(&db, true, true).await;
        let existing = a_user(&db, realm_id, "alice").await;

        let refused = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), false),
            Origin::default(),
        )
        .await;

        assert!(refused.is_err(), "an unverified address must not adopt");
        assert!(links_of(&db, existing.id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn adoption_works_when_both_conditions_hold(db: Db) {
        let (realm_id, _master, provider) = fixture(&db, true, false).await;
        let existing = a_user(&db, realm_id, "alice").await;

        let signed_in = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await
        .unwrap();

        assert_eq!(signed_in.resolution, Resolution::AdoptedByEmail);
        let login::Outcome::Complete(authenticated) = signed_in.outcome else {
            panic!("no second factor is enrolled");
        };
        assert_eq!(authenticated.user.id, existing.id);
        assert_eq!(links_of(&db, existing.id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn provisioning_can_be_refused(db: Db) {
        let (_realm, _master, provider) = fixture(&db, false, false).await;

        let refused = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("nobody@example.com"), true),
            Origin::default(),
        )
        .await;

        assert!(refused.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_provider_admits_nobody(db: Db) {
        let (_realm, _master, provider) = fixture(&db, false, true).await;
        let provider = set_enabled(&db, provider.id, false).await.unwrap();

        assert!(
            sign_in(
                &db,
                &provider,
                &claims("upstream-1", Some("alice@example.com"), true),
                Origin::default(),
            )
            .await
            .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_empty_subject_is_refused(db: Db) {
        // Otherwise every user of that provider keys to the same empty string,
        // and the first of them owns the rest.
        let (_realm, _master, provider) = fixture(&db, false, true).await;

        assert!(
            sign_in(
                &db,
                &provider,
                &claims("", Some("alice@example.com"), true),
                Origin::default(),
            )
            .await
            .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_disabled_account_cannot_sign_in_through_a_provider(db: Db) {
        let (realm_id, _master, provider) = fixture(&db, true, true).await;
        let existing = a_user(&db, realm_id, "alice").await;
        link(
            &db,
            provider.id,
            existing.id,
            &claims("upstream-1", None, false),
        )
        .await
        .unwrap();

        // Disabled directly rather than through `admin::set_user_enabled`,
        // which wants an `Actor`. A production helper that exists only for
        // tests is the shape this repository does not add.
        sqlx::query!(
            "UPDATE users SET enabled = false WHERE id = $1",
            existing.id.0
        )
        .execute(&db)
        .await
        .unwrap();

        assert!(
            sign_in(
                &db,
                &provider,
                &claims("upstream-1", Some("alice@example.com"), true),
                Origin::default(),
            )
            .await
            .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_upstream_account_cannot_be_linked_to_two_local_ones(db: Db) {
        let (realm_id, _master, provider) = fixture(&db, false, true).await;
        let alice = a_user(&db, realm_id, "alice").await;
        let bob = a_user(&db, realm_id, "bob").await;
        let asserted = claims("upstream-1", None, false);

        link(&db, provider.id, alice.id, &asserted).await.unwrap();
        let refused = link(&db, provider.id, bob.id, &asserted).await;

        assert!(refused.is_err(), "one upstream account, one local account");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn unlinking_the_only_way_in_is_refused(db: Db) {
        let (_realm, _master, provider) = fixture(&db, false, true).await;

        let signed_in = sign_in(
            &db,
            &provider,
            &claims("upstream-1", Some("alice@example.com"), true),
            Origin::default(),
        )
        .await
        .unwrap();
        let login::Outcome::Complete(authenticated) = signed_in.outcome else {
            panic!("no second factor is enrolled");
        };

        let refused = unlink(&db, provider.id, authenticated.user.id).await;
        assert!(
            refused.is_err(),
            "the account would be left with no credential at all"
        );
        assert_eq!(links_of(&db, authenticated.user.id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn unlinking_is_allowed_when_a_password_remains(db: Db) {
        let (realm_id, _master, provider) = fixture(&db, false, true).await;
        let alice = a_user(&db, realm_id, "alice").await;
        link(
            &db,
            provider.id,
            alice.id,
            &claims("upstream-1", None, false),
        )
        .await
        .unwrap();

        unlink(&db, provider.id, alice.id).await.unwrap();
        assert!(links_of(&db, alice.id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_alias_is_unique_within_a_realm(db: Db) {
        let (realm_id, master, _provider) = fixture(&db, false, true).await;

        let refused = create(
            &db,
            &master,
            NewProvider {
                realm_id,
                alias: "google",
                kind: Kind::Google,
                display_name: "Google Again",
                client_id: "other",
                client_secret: "other",
                authorization_endpoint: "https://accounts.example/authorize",
                token_endpoint: "https://accounts.example/token",
                userinfo_endpoint: None,
                issuer: None,
                scopes: &["openid".to_owned()],
                allow_provisioning: true,
                link_by_verified_email: false,
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 409);
    }
}
