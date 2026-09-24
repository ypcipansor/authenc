//! Machine-to-machine API tokens.
//!
//! `/api/v1` is otherwise authenticated by the session cookie the console
//! uses, which means an automated client has to sign in as a person and echo a
//! CSRF token. That works and is wrong: a Terraform provider ends up holding
//! somebody's password, and every change it makes is recorded under their name.
//!
//! # A token is never more than the person who made it
//!
//! Two rules, and the second is the one that matters.
//!
//! At creation, the requested permissions are checked against the creator's
//! own. That stops a token being minted with authority its maker never had.
//!
//! At *use*, the authority is the **intersection** of the token's grant and
//! what the bound account holds now. So losing a role narrows every token that
//! account owns, immediately, without anybody remembering to revoke them. The
//! alternative — a token that keeps what it was granted — reproduces exactly
//! the failure an offboarding process exists to prevent: the account is
//! disabled and its automation carries on with the authority it used to have.
//!
//! # Why a token is bound to a user
//!
//! Because something has to be answerable for it. A token with no owner is one
//! nobody notices is still live, and "a token did this" names nothing an
//! incident can act on. A service account is a user, so every rule already in
//! place — realm isolation, disabled accounts, suspended organisations —
//! applies to it without being restated.

use authenc_contract::{AppError, Permission, RealmId, Result, UserId, model::Actor};
use time::OffsetDateTime;

use crate::{db::Db, token::SecretToken, user};

/// The prefix every token carries, so one found in a log or a CI variable is
/// recognisable as ours rather than as somebody else's key.
pub const PREFIX: &str = "authenc_pat_";

/// How many characters of the token are kept in the clear.
///
/// Enough to tell two tokens apart in a list; far too few to be worth
/// guessing from. The secret is 32 bytes.
const VISIBLE: usize = 8;

/// A token as an operator sees it. Never the secret.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApiToken {
    /// Stable identifier.
    pub id: uuid::Uuid,
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// The account it acts as.
    pub user_id: UserId,
    /// What an operator calls it.
    pub name: String,
    /// The visible, non-secret prefix.
    pub prefix: String,
    /// What it was granted. The authority at use is this narrowed by what the
    /// bound account currently holds.
    pub permissions: Vec<Permission>,
    /// When it was made.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When it stops working, if ever.
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    /// When it was last presented.
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    /// When it was revoked.
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

/// A freshly minted token, with the secret to hand over.
#[derive(Debug)]
pub struct Minted {
    /// The stored record.
    pub token: ApiToken,
    /// The secret. Available exactly once, and never recoverable: only its
    /// hash is stored.
    pub secret: String,
}

/// What a new token needs.
#[derive(Debug, Clone)]
pub struct NewToken<'a> {
    /// The account it acts as.
    pub user_id: UserId,
    /// What an operator calls it.
    pub name: &'a str,
    /// What it may do. Must be a subset of the creator's own permissions.
    pub permissions: &'a [Permission],
    /// When it stops working. `None` means never, which is a decision rather
    /// than an oversight and is shown as such.
    pub expires_at: Option<OffsetDateTime>,
}

fn translate(error: sqlx::Error, context: &'static str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        match db_error.code().as_deref() {
            Some("23505") => {
                return AppError::conflict("that account already has a token by that name");
            }
            Some("23514") => return AppError::validation("a token needs a name"),
            _ => {}
        }
    }
    AppError::internal_from(context, error)
}

/// Mint a token.
///
/// `creator` is checked against `new.permissions`: a token cannot carry
/// authority its maker does not have.
///
/// # Errors
///
/// * [`AppError::Forbidden`] — the creator lacks one of the requested
///   permissions.
/// * [`AppError::Validation`] — a blank name, an expiry in the past, or no
///   permissions at all.
/// * [`AppError::NotFound`] — the bound account is outside the creator's realm.
/// * [`AppError::Conflict`] — that account already has a token by that name.
pub async fn mint(db: &Db, creator: &Actor, new: NewToken<'_>) -> Result<Minted> {
    let name = new.name.trim();
    if name.is_empty() {
        return Err(AppError::field("name", "must not be empty"));
    }

    // A token that may do nothing is not a useful object, and creating one is
    // almost always a caller that meant to send a permission list and did not.
    if new.permissions.is_empty() {
        return Err(AppError::field(
            "permissions",
            "a token must be granted at least one permission",
        ));
    }

    if let Some(expires_at) = new.expires_at
        && expires_at <= OffsetDateTime::now_utc()
    {
        return Err(AppError::field("expires_at", "must be in the future"));
    }

    // The escalation check. `Actor::can` honours `implies`, so `user:write`
    // covers a request for `user:read`.
    for permission in new.permissions {
        if !creator.can(*permission) {
            return Err(AppError::Forbidden);
        }
    }

    let target = user::by_id(db, new.user_id).await?;
    if target.realm_id != creator.realm_id {
        // Not `Forbidden`: an account in another realm is one this caller
        // cannot learn the existence of.
        return Err(AppError::NotFound("user"));
    }

    let secret = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating an API token", e))?;
    let presented = format!("{PREFIX}{}", secret.expose());
    let prefix: String = presented.chars().take(PREFIX.len() + VISIBLE).collect();

    let names: Vec<String> = new
        .permissions
        .iter()
        .map(|permission| permission.as_str().to_owned())
        .collect();

    let row = sqlx::query!(
        r#"
        INSERT INTO api_tokens
            (realm_id, user_id, name, token_hash, prefix, permissions,
             created_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, created_at
        "#,
        target.realm_id.0,
        target.id.0,
        name,
        hash(&presented),
        prefix,
        &names,
        creator.user_id.0,
        new.expires_at,
    )
    .fetch_one(db)
    .await
    .map_err(|e| translate(e, "creating an API token"))?;

    Ok(Minted {
        token: ApiToken {
            id: row.id,
            realm_id: target.realm_id,
            user_id: target.id,
            name: name.to_owned(),
            prefix,
            permissions: new.permissions.to_vec(),
            created_at: row.created_at,
            expires_at: new.expires_at,
            last_used_at: None,
            revoked_at: None,
        },
        secret: presented,
    })
}

/// The hash a presented token is looked up by.
fn hash(presented: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(presented.as_bytes()).to_vec()
}

/// Resolve a presented token to the authority it actually carries.
///
/// The returned [`Actor`] holds the **intersection** of the token's grant and
/// what the bound account currently has. Everything downstream then works
/// unchanged: a use case takes an `Actor` and checks it, and cannot tell
/// whether a person or a token is behind it — which is the point.
///
/// `None` covers unknown, revoked, expired, and disabled: one answer, because
/// distinguishing them tells a caller holding a dead token which kind of dead
/// it is.
///
/// # Errors
///
/// Returns an internal error if the lookup fails.
pub async fn authenticate(db: &Db, presented: &str) -> Result<Option<Actor>> {
    // Cheap rejection before touching the database. A bearer token that is not
    // ours — a JWT, say — should not cost a query.
    if !presented.starts_with(PREFIX) {
        return Ok(None);
    }

    let row = sqlx::query!(
        r#"
        SELECT id, user_id, permissions
          FROM api_tokens
         WHERE token_hash = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > now())
        "#,
        hash(presented),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up an API token", e))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let user_id = UserId(row.user_id);
    let account = user::by_id(db, user_id).await?;
    if !account.enabled {
        return Ok(None);
    }

    // What the account holds *now*, not what it held when the token was made.
    let current = user::permissions(db, user_id).await?;

    // The intersection. A name in the column that this build does not know is
    // dropped rather than refused: a token written by a newer version must not
    // lock out an older one, and dropping narrows rather than widens.
    let granted: Vec<Permission> = row
        .permissions
        .iter()
        .filter_map(|name| name.parse::<Permission>().ok())
        .filter(|permission| holds(&current, *permission))
        .collect();

    touch(db, row.id).await;

    Ok(Some(Actor {
        user_id,
        realm_id: account.realm_id,
        username: account.username,
        // Deliberately empty. A token's authority is its permissions; role
        // names are for display, and a use case that branched on one would be
        // reading something this path does not carry.
        roles: Vec::new(),
        permissions: granted,
    }))
}

/// Whether a permission set covers this permission, honouring `implies`.
fn holds(held: &[Permission], wanted: Permission) -> bool {
    held.iter()
        .any(|&have| have == wanted || have.implies() == Some(wanted))
}

/// Record that a token was used.
///
/// Failures are logged and swallowed. This is bookkeeping: an API request that
/// is otherwise fine must not fail because the timestamp could not be written,
/// and a caller cannot tell the difference anyway.
async fn touch(db: &Db, id: uuid::Uuid) {
    let result = sqlx::query!(
        "UPDATE api_tokens SET last_used_at = now() WHERE id = $1",
        id
    )
    .execute(db)
    .await;

    if let Err(error) = result {
        tracing::error!(%error, "could not record an API token's use");
    }
}

/// The tokens an account holds.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, user_id: UserId) -> Result<Vec<ApiToken>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, realm_id, user_id, name, prefix, permissions, created_at,
               expires_at, last_used_at, revoked_at
          FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC
        "#,
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing API tokens", e))?;

    Ok(rows
        .into_iter()
        .map(|row| ApiToken {
            id: row.id,
            realm_id: RealmId(row.realm_id),
            user_id: UserId(row.user_id),
            name: row.name,
            prefix: row.prefix,
            permissions: row
                .permissions
                .iter()
                .filter_map(|name| name.parse().ok())
                .collect(),
            created_at: row.created_at,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            revoked_at: row.revoked_at,
        })
        .collect())
}

/// Every token in a realm, for an administrator auditing what exists.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list_in_realm(db: &Db, realm_id: RealmId) -> Result<Vec<ApiToken>> {
    let rows = sqlx::query_scalar!(
        "SELECT user_id FROM api_tokens WHERE realm_id = $1 GROUP BY user_id",
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing API tokens", e))?;

    let mut all = Vec::new();
    for user_id in rows {
        all.extend(list(db, UserId(user_id)).await?);
    }
    all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(all)
}

/// Revoke a token.
///
/// Idempotent in effect: revoking an already-revoked token leaves it revoked,
/// and reports the same success, because the caller's intent is satisfied
/// either way.
///
/// # Errors
///
/// [`AppError::NotFound`] if no such token exists.
pub async fn revoke(db: &Db, id: uuid::Uuid) -> Result<()> {
    let result = sqlx::query!(
        "UPDATE api_tokens SET revoked_at = coalesce(revoked_at, now()) WHERE id = $1",
        id,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking an API token", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("api token"));
    }
    Ok(())
}

/// Look one up.
///
/// # Errors
///
/// [`AppError::NotFound`] if no token has that id.
pub async fn by_id(db: &Db, id: uuid::Uuid) -> Result<ApiToken> {
    let row = sqlx::query!(
        r#"
        SELECT id, realm_id, user_id, name, prefix, permissions, created_at,
               expires_at, last_used_at, revoked_at
          FROM api_tokens WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading an API token", e))?
    .ok_or(AppError::NotFound("api token"))?;

    Ok(ApiToken {
        id: row.id,
        realm_id: RealmId(row.realm_id),
        user_id: UserId(row.user_id),
        name: row.name,
        prefix: row.prefix,
        permissions: row
            .permissions
            .iter()
            .filter_map(|name| name.parse().ok())
            .collect(),
        created_at: row.created_at,
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
        revoked_at: row.revoked_at,
    })
}

/// Delete tokens that expired before now, for `authenc purge`.
///
/// Revoked ones are kept: they are the record that a credential existed and
/// was withdrawn, which is what an incident review looks for.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let result =
        sqlx::query!("DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at < now()",)
            .execute(db)
            .await
            .map_err(|e| AppError::internal_from("purging API tokens", e))?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use authenc_contract::model::User;

    use crate::{password::PasswordHasher, realm, role, user::NewUser};
    use time::Duration;

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

    /// Give a user a role carrying exactly these permissions.
    async fn grant(db: &Db, realm_id: RealmId, user: &User, permissions: &[Permission]) {
        let role = role::ensure(db, realm_id, &format!("{}-role", user.username), None)
            .await
            .unwrap();
        role::set_permissions(db, realm_id, role.id, permissions)
            .await
            .unwrap();
        role::grant(db, user.id, role.id).await.unwrap();
    }

    /// The actor a user currently resolves to.
    async fn actor_for(db: &Db, user: &User) -> Actor {
        Actor {
            user_id: user.id,
            realm_id: user.realm_id,
            username: user.username.clone(),
            roles: user::role_names(db, user.id).await.unwrap(),
            permissions: user::permissions(db, user.id).await.unwrap(),
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_token_works_and_carries_what_it_was_granted(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(
            &db,
            realm.id,
            &owner,
            &[Permission::UserRead, Permission::RoleRead],
        )
        .await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await
        .unwrap();

        assert!(
            minted.secret.starts_with(PREFIX),
            "a minted token must carry its prefix"
        );

        let actor = authenticate(&db, &minted.secret).await.unwrap().unwrap();
        assert_eq!(actor.user_id, owner.id);
        assert!(actor.can(Permission::UserRead));
        // Granted to the account, but not to this token.
        assert!(!actor.can(Permission::RoleRead));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_token_cannot_be_granted_more_than_its_maker_has(db: Db) {
        // The escalation this check exists to stop: somebody who may read
        // users minting a token that may write them.
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "reader").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let refused = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserWrite],
                expires_at: None,
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 403);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn losing_a_role_narrows_every_token_that_account_holds(db: Db) {
        // The rule that makes offboarding work. A token that kept what it was
        // granted would carry on with authority the account no longer has.
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(
            &db,
            realm.id,
            &owner,
            &[Permission::UserRead, Permission::RoleWrite],
        )
        .await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead, Permission::RoleWrite],
                expires_at: None,
            },
        )
        .await
        .unwrap();

        let before = authenticate(&db, &minted.secret).await.unwrap().unwrap();
        assert!(before.can(Permission::RoleWrite));

        // The account's role is narrowed to just `user:read`.
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let after = authenticate(&db, &minted.secret).await.unwrap().unwrap();
        assert!(after.can(Permission::UserRead));
        assert!(
            !after.can(Permission::RoleWrite),
            "the token outlived the authority that made it"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn disabling_the_account_kills_its_tokens(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await
        .unwrap();

        sqlx::query!("UPDATE users SET enabled = false WHERE id = $1", owner.id.0)
            .execute(&db)
            .await
            .unwrap();

        assert!(authenticate(&db, &minted.secret).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_revoked_token_stops_working(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await
        .unwrap();

        assert!(authenticate(&db, &minted.secret).await.unwrap().is_some());
        revoke(&db, minted.token.id).await.unwrap();
        assert!(authenticate(&db, &minted.secret).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_token_stops_working(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
            },
        )
        .await
        .unwrap();

        assert!(authenticate(&db, &minted.secret).await.unwrap().is_some());

        sqlx::query!(
            "UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1",
            minted.token.id,
        )
        .execute(&db)
        .await
        .unwrap();

        assert!(authenticate(&db, &minted.secret).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expiry_in_the_past_is_refused(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let refused = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: Some(OffsetDateTime::now_utc() - Duration::hours(1)),
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 400);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_token_with_no_permissions_is_refused(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let refused = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[],
                expires_at: None,
            },
        )
        .await;

        assert_eq!(refused.unwrap_err().status(), 400);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_token_cannot_be_bound_to_another_realms_account(db: Db) {
        let acme = realm::create(&db, "acme", "Acme").await.unwrap();
        let other = realm::create(&db, "other", "Other").await.unwrap();

        let maker = a_user(&db, acme.id, "admin").await;
        grant(&db, acme.id, &maker, Permission::ALL).await;
        let elsewhere = a_user(&db, other.id, "stranger").await;

        let refused = mint(
            &db,
            &actor_for(&db, &maker).await,
            NewToken {
                user_id: elsewhere.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await;

        // 404, not 403: an account in another realm is one this caller cannot
        // learn the existence of.
        assert_eq!(refused.unwrap_err().status(), 404);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_secret_is_not_stored_and_not_listed_back(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await
        .unwrap();

        let listed = list(&db, owner.id).await.unwrap();
        assert_eq!(listed.len(), 1);

        let json = serde_json::to_string(&listed[0]).unwrap();
        assert!(!json.contains(&minted.secret), "{json}");

        // The prefix is public and is how an operator tells two apart.
        assert!(minted.secret.starts_with(&listed[0].prefix));
        assert!(listed[0].prefix.starts_with(PREFIX));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_bearer_token_that_is_not_ours_costs_no_query(db: Db) {
        // A JWT sent to `/api/v1` should be rejected on its shape, not looked
        // up. Behavioural proof is only that it returns `None`; the reason to
        // write it is that the prefix check is easy to delete by accident.
        assert!(
            authenticate(&db, "eyJhbGciOiJub25lIn0.e30.")
                .await
                .unwrap()
                .is_none()
        );
        assert!(authenticate(&db, "").await.unwrap().is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn two_tokens_on_one_account_cannot_share_a_name(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;
        let actor = actor_for(&db, &owner).await;

        let new = || NewToken {
            user_id: owner.id,
            name: "ci",
            permissions: &[Permission::UserRead],
            expires_at: None,
        };

        mint(&db, &actor, new()).await.unwrap();
        assert_eq!(mint(&db, &actor, new()).await.unwrap_err().status(), 409);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn using_a_token_records_that_it_was_used(db: Db) {
        // So "is anything still using this?" has an answer before somebody
        // revokes it.
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;

        let minted = mint(
            &db,
            &actor_for(&db, &owner).await,
            NewToken {
                user_id: owner.id,
                name: "ci",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await
        .unwrap();

        assert!(minted.token.last_used_at.is_none());
        authenticate(&db, &minted.secret).await.unwrap().unwrap();
        assert!(
            by_id(&db, minted.token.id)
                .await
                .unwrap()
                .last_used_at
                .is_some()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_keeps_revoked_tokens_and_removes_expired_ones(db: Db) {
        // A revoked token is the record that a credential existed and was
        // withdrawn, which is what an incident review looks for.
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let owner = a_user(&db, realm.id, "robot").await;
        grant(&db, realm.id, &owner, &[Permission::UserRead]).await;
        let actor = actor_for(&db, &owner).await;

        let revoked = mint(
            &db,
            &actor,
            NewToken {
                user_id: owner.id,
                name: "revoked",
                permissions: &[Permission::UserRead],
                expires_at: None,
            },
        )
        .await
        .unwrap();
        revoke(&db, revoked.token.id).await.unwrap();

        let expired = mint(
            &db,
            &actor,
            NewToken {
                user_id: owner.id,
                name: "expired",
                permissions: &[Permission::UserRead],
                expires_at: Some(OffsetDateTime::now_utc() + Duration::hours(1)),
            },
        )
        .await
        .unwrap();
        sqlx::query!(
            "UPDATE api_tokens SET expires_at = now() - interval '1 day' WHERE id = $1",
            expired.token.id,
        )
        .execute(&db)
        .await
        .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
        assert!(by_id(&db, revoked.token.id).await.is_ok());
        assert!(by_id(&db, expired.token.id).await.is_err());
    }
}
