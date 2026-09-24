//! Organisations: a tenant boundary inside a realm.
//!
//! # Why this is not a group with a different name
//!
//! Three things an organisation does that a group does not:
//!
//! 1. **It can be suspended.** [`set_enabled`] stops its members signing in
//!    without touching a single user row — the "suspend this customer" control
//!    a B2B deployment needs.
//! 2. **People join by invitation**, through a link sent to an address, rather
//!    than by an administrator adding them.
//! 3. **Membership carries a role inside the organisation.** Owner, admin,
//!    member — who runs the customer's account, deliberately separate from the
//!    realm's RBAC. An organisation owner holds no realm permissions, and a
//!    realm administrator is not thereby an owner of anything.
//!
//! A group remains a bucket for realm role assignment, arranged in a
//! hierarchy. Neither replaces the other.

use authenc_contract::{
    AppError, InvitationId, OrganizationId, RealmId, Result, UserId, model::User,
};
use time::{Duration, OffsetDateTime};

use crate::{db::Db, token::SecretToken};

/// How long an invitation link stays usable.
///
/// Long enough to survive a weekend and a spam folder, short enough that an
/// invitation forwarded once and forgotten does not stay redeemable for months.
pub const INVITATION_LIFETIME: Duration = Duration::days(7);

/// Someone's standing inside an organisation.
///
/// Not a [`Permission`](authenc_contract::Permission): these say who runs the
/// customer's account, and they confer nothing over the realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// May do anything within the organisation, including removing owners.
    Owner,
    /// May invite and remove members, but not owners.
    Admin,
    /// Belongs to it, and nothing more.
    Member,
}

impl MemberRole {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
        }
    }

    /// Parse a stored name.
    ///
    /// # Errors
    ///
    /// Returns a validation error for anything else. Deliberately not a
    /// `Default`: an unrecognised role silently becoming `Member` would be a
    /// downgrade nobody asked for, and becoming `Owner` would be worse.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "member" => Ok(Self::Member),
            other => Err(AppError::field(
                "role",
                format!("`{other}` is not an organisation role"),
            )),
        }
    }

    /// Whether this role may manage membership at all.
    #[must_use]
    pub const fn can_manage_members(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// Whether this role may act on a member holding `target`.
    ///
    /// An admin may not remove or demote an owner. Without this an admin could
    /// evict every owner and take the organisation, which is the whole reason
    /// the two roles are distinct.
    #[must_use]
    pub const fn outranks(self, target: Self) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => !matches!(target, Self::Owner),
            Self::Member => false,
        }
    }
}

/// An organisation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Organization {
    /// Stable identifier.
    pub id: OrganizationId,
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// URL-safe handle, unique within the realm.
    pub slug: String,
    /// Human-facing name.
    pub name: String,
    /// Whether its members may sign in.
    pub enabled: bool,
    /// When it was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// A member, with their standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    /// The organisation.
    pub organization_id: OrganizationId,
    /// The user.
    pub user_id: UserId,
    /// Their role inside it.
    pub role: MemberRole,
    /// Whether the organisation itself is enabled.
    pub organization_enabled: bool,
}

fn translate(error: sqlx::Error, context: &'static str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error
        && db_error.code().as_deref() == Some("23505")
    {
        return AppError::conflict("that already exists in this realm");
    }
    AppError::internal_from(context, error)
}

/// Create an organisation.
///
/// # Errors
///
/// [`AppError::Validation`] for a blank or malformed slug, or
/// [`AppError::Conflict`] if the slug is taken in this realm.
pub async fn create(db: &Db, realm_id: RealmId, slug: &str, name: &str) -> Result<Organization> {
    let slug = slug.trim();
    let name = name.trim();

    if name.is_empty() {
        return Err(AppError::field("name", "must not be empty"));
    }
    // The slug appears in URLs, so it is restricted rather than escaped: a
    // handle that needs encoding is one that will eventually be compared
    // before decoding somewhere.
    if slug.is_empty()
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(AppError::field(
            "slug",
            "must be lowercase letters, digits, and hyphens",
        ));
    }

    let row = sqlx::query!(
        r#"
        INSERT INTO organizations (realm_id, slug, name)
        VALUES ($1, $2, $3)
        RETURNING id, realm_id, slug, name, enabled, created_at
        "#,
        realm_id.0,
        slug,
        name,
    )
    .fetch_one(db)
    .await
    .map_err(|e| translate(e, "creating an organisation"))?;

    Ok(Organization {
        id: OrganizationId(row.id),
        realm_id: RealmId(row.realm_id),
        slug: row.slug,
        name: row.name,
        enabled: row.enabled,
        created_at: row.created_at,
    })
}

/// Look one up.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn by_id(db: &Db, id: OrganizationId) -> Result<Organization> {
    let row = sqlx::query!(
        "SELECT id, realm_id, slug, name, enabled, created_at FROM organizations WHERE id = $1",
        id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading an organisation", e))?
    .ok_or(AppError::NotFound("organization"))?;

    Ok(Organization {
        id: OrganizationId(row.id),
        realm_id: RealmId(row.realm_id),
        slug: row.slug,
        name: row.name,
        enabled: row.enabled,
        created_at: row.created_at,
    })
}

/// Every organisation in a realm.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, realm_id: RealmId) -> Result<Vec<Organization>> {
    let rows = sqlx::query!(
        "SELECT id, realm_id, slug, name, enabled, created_at FROM organizations \
         WHERE realm_id = $1 ORDER BY name",
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing organisations", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Organization {
            id: OrganizationId(row.id),
            realm_id: RealmId(row.realm_id),
            slug: row.slug,
            name: row.name,
            enabled: row.enabled,
            created_at: row.created_at,
        })
        .collect())
}

/// Suspend or restore an organisation.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn set_enabled(db: &Db, id: OrganizationId, enabled: bool) -> Result<Organization> {
    let result = sqlx::query!(
        "UPDATE organizations SET enabled = $2 WHERE id = $1",
        id.0,
        enabled,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("changing an organisation", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("organization"));
    }
    by_id(db, id).await
}

/// Delete an organisation, its membership, and its invitations.
///
/// The users themselves are untouched: an organisation is a grouping, and
/// deleting one must not delete people.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn delete(db: &Db, id: OrganizationId) -> Result<()> {
    let result = sqlx::query!("DELETE FROM organizations WHERE id = $1", id.0)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("deleting an organisation", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("organization"));
    }
    Ok(())
}

/// Add someone, or change the role they already hold.
///
/// # Errors
///
/// [`AppError::NotFound`] if either side is unknown or they are in different
/// realms.
pub async fn set_member(
    db: &Db,
    organization_id: OrganizationId,
    user_id: UserId,
    role: MemberRole,
) -> Result<()> {
    let organization = by_id(db, organization_id).await?;
    let user = crate::user::by_id(db, user_id).await?;

    if organization.realm_id != user.realm_id {
        return Err(AppError::NotFound("organization"));
    }

    sqlx::query!(
        "INSERT INTO organization_members (organization_id, user_id, role) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        organization_id.0,
        user_id.0,
        role.as_str(),
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("adding an organisation member", e))?;

    Ok(())
}

/// Remove someone.
///
/// Refuses to remove the last owner: an organisation nobody can administer is
/// one that needs a database console to fix.
///
/// # Errors
///
/// [`AppError::Validation`] if they are the last owner.
pub async fn remove_member(
    db: &Db,
    organization_id: OrganizationId,
    user_id: UserId,
) -> Result<()> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("removing an organisation member", e))?;

    // Lock the organisation row, not the membership rows: `FOR UPDATE` cannot
    // be combined with an aggregate, and locking the parent serialises every
    // membership change for this organisation — which is what stops two
    // concurrent removals from each seeing the other owner and both
    // proceeding, leaving none.
    sqlx::query_scalar!(
        "SELECT id FROM organizations WHERE id = $1 FOR UPDATE",
        organization_id.0
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("locking an organisation", e))?
    .ok_or(AppError::NotFound("organization"))?;

    let owners = sqlx::query_scalar!(
        r#"SELECT count(*) AS "count!" FROM organization_members
           WHERE organization_id = $1 AND role = 'owner'"#,
        organization_id.0,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("counting organisation owners", e))?;

    let leaving_role = sqlx::query_scalar!(
        "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
        organization_id.0,
        user_id.0,
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("loading a membership", e))?;

    if leaving_role.as_deref() == Some("owner") && owners <= 1 {
        return Err(AppError::validation(
            "an organisation must keep at least one owner",
        ));
    }

    sqlx::query!(
        "DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2",
        organization_id.0,
        user_id.0,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("removing an organisation member", e))?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("removing an organisation member", e))?;

    Ok(())
}

/// Everyone in an organisation, with their role.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn members(db: &Db, organization_id: OrganizationId) -> Result<Vec<(User, MemberRole)>> {
    let rows = sqlx::query!(
        "SELECT user_id, role FROM organization_members \
         WHERE organization_id = $1 ORDER BY joined_at",
        organization_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing organisation members", e))?;

    let mut members = Vec::with_capacity(rows.len());
    for row in rows {
        members.push((
            crate::user::by_id(db, UserId(row.user_id)).await?,
            MemberRole::parse(&row.role)?,
        ));
    }
    Ok(members)
}

/// What a user belongs to.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn of_user(db: &Db, user_id: UserId) -> Result<Vec<Membership>> {
    let rows = sqlx::query!(
        r#"
        SELECT m.organization_id, m.role, o.enabled
          FROM organization_members m
          JOIN organizations o ON o.id = m.organization_id
         WHERE m.user_id = $1
         ORDER BY o.name
        "#,
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing a user's organisations", e))?;

    rows.into_iter()
        .map(|row| {
            Ok(Membership {
                organization_id: OrganizationId(row.organization_id),
                user_id,
                role: MemberRole::parse(&row.role)?,
                organization_enabled: row.enabled,
            })
        })
        .collect()
}

/// Whether this user's organisations should stop them signing in.
///
/// The rule is more careful than "any disabled organisation blocks you", and
/// the difference matters:
///
/// * belongs to no organisation → not blocked, because the account is a plain
///   realm user and organisations are not involved;
/// * belongs to one, suspended → blocked, which is what suspending a customer
///   is meant to do;
/// * belongs to two, one still enabled → **not** blocked, because a consultant
///   working with two customers must not lose their account when one of them
///   is suspended.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn blocks_sign_in(db: &Db, user_id: UserId) -> Result<bool> {
    let row = sqlx::query!(
        r#"
        SELECT count(*) AS "total!",
               count(*) FILTER (WHERE o.enabled) AS "enabled!"
          FROM organization_members m
          JOIN organizations o ON o.id = m.organization_id
         WHERE m.user_id = $1
        "#,
        user_id.0,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("checking organisation status", e))?;

    Ok(row.total > 0 && row.enabled == 0)
}

// ---------------------------------------------------------------------------
// Invitations
// ---------------------------------------------------------------------------

/// An invitation as an administrator sees it.
///
/// Carries no token: the link exists once, at the moment it is created, and is
/// not recoverable afterwards. A list endpoint that could hand one back would
/// let anyone who can read the list join as anyone who was invited.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Invitation {
    /// Stable identifier.
    pub id: InvitationId,
    /// The organisation.
    pub organization_id: OrganizationId,
    /// Who was invited.
    pub email: String,
    /// The role they will hold.
    pub role: MemberRole,
    /// Whether it has been used.
    pub accepted: bool,
    /// When it stops working, RFC 3339.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// A freshly created invitation, with the link to send.
#[derive(Debug)]
pub struct Invited {
    /// The stored record.
    pub invitation: Invitation,
    /// The token for the link. Available exactly once.
    pub token: SecretToken,
}

/// Invite an address to an organisation.
///
/// Replaces any invitation to the same address that has not been accepted, so
/// re-inviting does not leave two live links to one seat.
///
/// # Errors
///
/// [`AppError::NotFound`] if the organisation does not exist, or
/// [`AppError::Validation`] for a malformed address.
pub async fn invite(
    db: &Db,
    organization_id: OrganizationId,
    email: &str,
    role: MemberRole,
    invited_by: Option<UserId>,
) -> Result<Invited> {
    by_id(db, organization_id).await?;

    let email = email.trim();
    authenc_contract::validate::email(email)?;

    let token = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating an invitation token", e))?;
    let expires_at = OffsetDateTime::now_utc() + INVITATION_LIFETIME;

    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("creating an invitation", e))?;

    sqlx::query!(
        "DELETE FROM organization_invitations \
         WHERE organization_id = $1 AND lower(email) = lower($2) AND accepted_at IS NULL",
        organization_id.0,
        email,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("replacing an invitation", e))?;

    let row = sqlx::query!(
        r#"
        INSERT INTO organization_invitations
            (organization_id, email, role, token_hash, invited_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
        "#,
        organization_id.0,
        email,
        role.as_str(),
        token.hash(),
        invited_by.map(|id| id.0),
        expires_at,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("creating an invitation", e))?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("creating an invitation", e))?;

    Ok(Invited {
        invitation: Invitation {
            id: InvitationId(row.id),
            organization_id,
            email: email.to_owned(),
            role,
            accepted: false,
            expires_at,
        },
        token,
    })
}

/// What an invitation token refers to, without spending it.
///
/// Lets a signed-out visitor be shown which organisation they are joining
/// before being asked to sign in. Returns `None` for anything unusable —
/// unknown, expired, or already accepted are one answer to the caller.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn peek_invitation(db: &Db, token: &SecretToken) -> Result<Option<Invitation>> {
    let row = sqlx::query!(
        r#"
        SELECT id, organization_id, email, role, expires_at
          FROM organization_invitations
         WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
        "#,
        token.hash(),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("looking up an invitation", e))?;

    row.map(|row| {
        Ok(Invitation {
            id: InvitationId(row.id),
            organization_id: OrganizationId(row.organization_id),
            email: row.email,
            role: MemberRole::parse(&row.role)?,
            accepted: false,
            expires_at: row.expires_at,
        })
    })
    .transpose()
}

/// Accept an invitation as the given user.
///
/// The claim is atomic, so one link admits exactly one person however many
/// times it is presented.
///
/// The accepting account is recorded separately from the invited address. A
/// link forwarded to somebody else and accepted by them cannot be prevented by
/// a link — possession of it *is* the proof — but it must be visible
/// afterwards, and a row storing only the invited address would hide it.
///
/// # Errors
///
/// * [`AppError::Unauthenticated`] — unknown, expired, or already spent.
/// * [`AppError::NotFound`] — the accepting user is in a different realm.
pub async fn accept_invitation(
    db: &Db,
    token: &SecretToken,
    user_id: UserId,
) -> Result<Organization> {
    let claimed = sqlx::query!(
        r#"
        UPDATE organization_invitations
           SET accepted_at = now(), accepted_by = $2
         WHERE token_hash = $1 AND accepted_at IS NULL AND expires_at > now()
        RETURNING organization_id, role, email
        "#,
        token.hash(),
        user_id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("accepting an invitation", e))?
    .ok_or(AppError::Unauthenticated)?;

    let role = MemberRole::parse(&claimed.role)?;
    let organization = by_id(db, OrganizationId(claimed.organization_id)).await?;
    let user = crate::user::by_id(db, user_id).await?;

    if organization.realm_id != user.realm_id {
        // The claim has already been spent, which is deliberate: a link
        // presented by the wrong realm's account is burnt rather than left
        // live for a second attempt.
        return Err(AppError::NotFound("organization"));
    }

    if !user.email.eq_ignore_ascii_case(&claimed.email) {
        tracing::warn!(
            %user_id,
            organization = %organization.slug,
            "an organisation invitation was accepted by an account it was not addressed to",
        );
    }

    set_member(db, organization.id, user_id, role).await?;
    Ok(organization)
}

/// Invitations for an organisation, newest first.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn invitations(db: &Db, organization_id: OrganizationId) -> Result<Vec<Invitation>> {
    let rows = sqlx::query!(
        "SELECT id, organization_id, email, role, expires_at, accepted_at \
         FROM organization_invitations WHERE organization_id = $1 ORDER BY created_at DESC",
        organization_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing invitations", e))?;

    rows.into_iter()
        .map(|row| {
            Ok(Invitation {
                id: InvitationId(row.id),
                organization_id: OrganizationId(row.organization_id),
                email: row.email,
                role: MemberRole::parse(&row.role)?,
                accepted: row.accepted_at.is_some(),
                expires_at: row.expires_at,
            })
        })
        .collect()
}

/// Withdraw an invitation that has not been accepted.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist or has already been used.
pub async fn revoke_invitation(db: &Db, id: InvitationId) -> Result<()> {
    let result = sqlx::query!(
        "DELETE FROM organization_invitations WHERE id = $1 AND accepted_at IS NULL",
        id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking an invitation", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("invitation"));
    }
    Ok(())
}

/// Delete invitations that are past their expiry, for `authenc purge`.
///
/// Accepted ones are kept: they are the record of who joined and when.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let result = sqlx::query!(
        "DELETE FROM organization_invitations \
         WHERE accepted_at IS NULL AND expires_at < now()",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("purging invitations", e))?;

    Ok(result.rows_affected())
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

    async fn fixture(db: &Db) -> (RealmId, Organization, User) {
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let org = create(db, realm.id, "widgets", "Widgets Inc")
            .await
            .unwrap();
        let owner = a_user(db, realm.id, "alice").await;
        set_member(db, org.id, owner.id, MemberRole::Owner)
            .await
            .unwrap();
        (realm.id, org, owner)
    }

    #[test]
    fn an_admin_may_not_act_on_an_owner() {
        // Without this an admin could evict every owner and take the
        // organisation, which is the only reason the two roles differ.
        assert!(MemberRole::Owner.outranks(MemberRole::Owner));
        assert!(MemberRole::Owner.outranks(MemberRole::Admin));
        assert!(MemberRole::Admin.outranks(MemberRole::Member));
        assert!(!MemberRole::Admin.outranks(MemberRole::Owner));
        assert!(!MemberRole::Member.outranks(MemberRole::Member));
    }

    #[test]
    fn an_unknown_role_is_an_error_not_a_default() {
        // Defaulting to `Member` would be a silent downgrade; defaulting to
        // `Owner` would be worse.
        assert!(MemberRole::parse("owner").is_ok());
        assert!(MemberRole::parse("root").is_err());
        assert!(MemberRole::parse("").is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_slug_must_be_url_safe_and_unique(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        assert!(create(&db, realm.id, "widgets", "Widgets").await.is_ok());

        // Taken. (`"Widgets"` would be a 400 rather than a 409 — validation
        // refuses an uppercase slug before the database is asked, so the
        // case-insensitive index below it is belt and braces.)
        assert_eq!(
            create(&db, realm.id, "widgets", "Other")
                .await
                .unwrap_err()
                .status(),
            409,
        );

        for bad in [
            "",
            "Widgets",
            "Widgets Inc",
            "wid/gets",
            "wid gets",
            "widgets!",
        ] {
            assert_eq!(
                create(&db, realm.id, bad, "X").await.unwrap_err().status(),
                400,
                "{bad:?} was accepted as a slug",
            );
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn suspending_an_organisation_blocks_its_only_members(db: Db) {
        let (_, org, owner) = fixture(&db).await;
        assert!(!blocks_sign_in(&db, owner.id).await.unwrap());

        set_enabled(&db, org.id, false).await.unwrap();
        assert!(
            blocks_sign_in(&db, owner.id).await.unwrap(),
            "suspending a customer must stop their people signing in",
        );

        set_enabled(&db, org.id, true).await.unwrap();
        assert!(!blocks_sign_in(&db, owner.id).await.unwrap());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_user_in_no_organisation_is_unaffected(db: Db) {
        let realm = realm::create(&db, "acme", "Acme").await.unwrap();
        let loner = a_user(&db, realm.id, "loner").await;
        create(&db, realm.id, "widgets", "Widgets").await.unwrap();

        assert!(
            !blocks_sign_in(&db, loner.id).await.unwrap(),
            "a plain realm user has nothing to do with organisations",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_suspended_organisation_does_not_lock_out_a_member_of_another(db: Db) {
        // A consultant working with two customers must not lose their account
        // because one of them was suspended. This is the case a naive "any
        // disabled organisation blocks you" rule gets wrong.
        let (realm_id, first, user) = fixture(&db).await;
        let second = create(&db, realm_id, "gadgets", "Gadgets Ltd")
            .await
            .unwrap();
        set_member(&db, second.id, user.id, MemberRole::Member)
            .await
            .unwrap();

        set_enabled(&db, first.id, false).await.unwrap();
        assert!(
            !blocks_sign_in(&db, user.id).await.unwrap(),
            "the still-enabled organisation must keep them working",
        );

        set_enabled(&db, second.id, false).await.unwrap();
        assert!(
            blocks_sign_in(&db, user.id).await.unwrap(),
            "with every organisation suspended, there is nothing left to sign in for",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_last_owner_cannot_be_removed(db: Db) {
        // An organisation nobody can administer needs a database console to
        // fix, which is not a state a UI should be able to reach.
        let (realm_id, org, owner) = fixture(&db).await;

        assert_eq!(
            remove_member(&db, org.id, owner.id)
                .await
                .unwrap_err()
                .status(),
            400,
        );

        // With a second owner, the first may go.
        let bob = a_user(&db, realm_id, "bob").await;
        set_member(&db, org.id, bob.id, MemberRole::Owner)
            .await
            .unwrap();
        assert!(remove_member(&db, org.id, owner.id).await.is_ok());
        assert_eq!(members(&db, org.id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_member_may_be_removed_freely(db: Db) {
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;
        set_member(&db, org.id, bob.id, MemberRole::Member)
            .await
            .unwrap();

        assert!(remove_member(&db, org.id, bob.id).await.is_ok());
        assert_eq!(members(&db, org.id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn setting_a_member_twice_changes_their_role(db: Db) {
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;

        set_member(&db, org.id, bob.id, MemberRole::Member)
            .await
            .unwrap();
        set_member(&db, org.id, bob.id, MemberRole::Admin)
            .await
            .unwrap();

        let roles: Vec<_> = members(&db, org.id)
            .await
            .unwrap()
            .into_iter()
            .map(|(user, role)| (user.username, role))
            .collect();
        assert!(roles.contains(&("bob".to_owned(), MemberRole::Admin)));
        assert_eq!(roles.len(), 2, "it must update, not duplicate");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_organisation_cannot_hold_a_user_from_another_realm(db: Db) {
        let (_, org, _) = fixture(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap();
        let stranger = a_user(&db, other.id, "stranger").await;

        assert_eq!(
            set_member(&db, org.id, stranger.id, MemberRole::Member)
                .await
                .unwrap_err()
                .status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_invitation_admits_exactly_one_person(db: Db) {
        let (realm_id, org, owner) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;
        let carol = a_user(&db, realm_id, "carol").await;

        let invited = invite(
            &db,
            org.id,
            "bob@example.com",
            MemberRole::Member,
            Some(owner.id),
        )
        .await
        .unwrap();

        assert!(accept_invitation(&db, &invited.token, bob.id).await.is_ok());
        assert_eq!(
            accept_invitation(&db, &invited.token, carol.id)
                .await
                .unwrap_err()
                .status(),
            401,
            "one link, one seat",
        );

        let usernames: Vec<_> = members(&db, org.id)
            .await
            .unwrap()
            .into_iter()
            .map(|(user, _)| user.username)
            .collect();
        assert!(usernames.contains(&"bob".to_owned()));
        assert!(!usernames.contains(&"carol".to_owned()));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_invitation_is_refused(db: Db) {
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;
        let invited = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();

        sqlx::query("UPDATE organization_invitations SET expires_at = now() - interval '1 second'")
            .execute(&db)
            .await
            .unwrap();

        assert!(
            peek_invitation(&db, &invited.token)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            accept_invitation(&db, &invited.token, bob.id)
                .await
                .unwrap_err()
                .status(),
            401,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_token_is_not_recoverable_from_the_database(db: Db) {
        let (_, org, _) = fixture(&db).await;
        let invited = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();

        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM organization_invitations")
            .fetch_one(&db)
            .await
            .unwrap();

        assert_eq!(stored, invited.token.hash());
        assert_ne!(stored, invited.token.expose().as_bytes());

        // And nothing that lists invitations hands one back.
        let listed = invitations(&db, org.id).await.unwrap();
        let rendered = serde_json::to_string(&listed).unwrap();
        assert!(!rendered.contains(invited.token.expose()), "{rendered}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn re_inviting_replaces_the_previous_link(db: Db) {
        // Otherwise two live links exist for one seat, and revoking the
        // visible one leaves the other working.
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;

        let first = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();
        let second = invite(&db, org.id, "bob@example.com", MemberRole::Admin, None)
            .await
            .unwrap();

        assert!(peek_invitation(&db, &first.token).await.unwrap().is_none());
        assert!(accept_invitation(&db, &first.token, bob.id).await.is_err());
        assert!(accept_invitation(&db, &second.token, bob.id).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_revoked_invitation_stops_working(db: Db) {
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;
        let invited = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();

        revoke_invitation(&db, invited.invitation.id).await.unwrap();
        assert!(
            accept_invitation(&db, &invited.token, bob.id)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_accepted_invitation_cannot_be_revoked(db: Db) {
        // It is no longer an invitation; it is the record of someone joining.
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;
        let invited = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();
        accept_invitation(&db, &invited.token, bob.id)
            .await
            .unwrap();

        assert_eq!(
            revoke_invitation(&db, invited.invitation.id)
                .await
                .unwrap_err()
                .status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn accepting_records_who_actually_used_the_link(db: Db) {
        // An invitation forwarded and accepted by somebody else cannot be
        // prevented by a link — possession is the proof — but it must be
        // visible afterwards.
        let (realm_id, org, _) = fixture(&db).await;
        let carol = a_user(&db, realm_id, "carol").await;

        let invited = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();
        accept_invitation(&db, &invited.token, carol.id)
            .await
            .unwrap();

        let (email, accepted_by): (String, Option<uuid::Uuid>) =
            sqlx::query_as("SELECT email, accepted_by FROM organization_invitations WHERE id = $1")
                .bind(invited.invitation.id.0)
                .fetch_one(&db)
                .await
                .unwrap();

        assert_eq!(email, "bob@example.com");
        assert_eq!(
            accepted_by,
            Some(carol.id.0),
            "the mismatch must be on record"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn purging_keeps_accepted_invitations(db: Db) {
        // They are the record of who joined and when.
        let (realm_id, org, _) = fixture(&db).await;
        let bob = a_user(&db, realm_id, "bob").await;

        let accepted = invite(&db, org.id, "bob@example.com", MemberRole::Member, None)
            .await
            .unwrap();
        accept_invitation(&db, &accepted.token, bob.id)
            .await
            .unwrap();
        invite(&db, org.id, "dave@example.com", MemberRole::Member, None)
            .await
            .unwrap();

        sqlx::query("UPDATE organization_invitations SET expires_at = now() - interval '1 day'")
            .execute(&db)
            .await
            .unwrap();

        assert_eq!(purge_expired(&db).await.unwrap(), 1);
        let left = invitations(&db, org.id).await.unwrap();
        assert_eq!(left.len(), 1);
        assert!(left[0].accepted);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deleting_an_organisation_keeps_the_people(db: Db) {
        let (_, org, owner) = fixture(&db).await;
        delete(&db, org.id).await.unwrap();

        assert_eq!(by_id(&db, org.id).await.unwrap_err().status(), 404);
        assert!(
            user::by_id(&db, owner.id).await.is_ok(),
            "an organisation is a grouping; deleting one must not delete people",
        );
        assert!(of_user(&db, owner.id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_realm_cannot_see_anothers_organisations(db: Db) {
        let (_, _, _) = fixture(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap();
        assert!(list(&db, other.id).await.unwrap().is_empty());
    }
}
