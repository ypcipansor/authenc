//! Groups: a hierarchy of users within a realm, carrying role grants.
//!
//! # What makes this access control rather than an org chart
//!
//! [`crate::user::permissions`] resolves *through* the tree. A member of
//! `/engineering/backend` holds the roles granted to `backend` and to
//! `engineering` above it, and that union is what every `Actor` is built from.
//! A group feature that stores a hierarchy and never consults it during
//! authorisation is a diagram.
//!
//! # Which way inheritance runs
//!
//! Upward: from a group to its ancestors. That is the direction people expect,
//! and it is the safer of the two — adding a child group can never widen what
//! its parent's members can do, so nesting is not a privilege escalation.
//!
//! # Cycles
//!
//! Refused by a database trigger, not by this module. A cycle is not merely
//! invalid data: every ancestry walk over it is a query that does not
//! terminate, and one runs on every authorised request. The rule belongs where
//! nothing can route around it. This module's job is to turn the resulting
//! error into something a caller can read.

use authenc_contract::{AppError, GroupId, RealmId, Result, RoleId, UserId, model::Role};
use time::OffsetDateTime;

use crate::db::Db;

/// A group, as callers see it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Group {
    /// Stable identifier.
    pub id: GroupId,
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// Parent, if it is not at the root.
    pub parent_id: Option<GroupId>,
    /// Name, unique among its siblings.
    pub name: String,
    /// What it is for.
    pub description: Option<String>,
    /// Full path from the root, e.g. `/engineering/backend`.
    ///
    /// Computed rather than stored. A stored path is a denormalisation that has
    /// to be rewritten for an entire subtree whenever a group is renamed or
    /// moved, and the failure mode is a path that no longer matches the tree.
    pub path: String,
    /// When it was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Turn a database error into the right application error.
///
/// The trigger and the unique indexes are the real enforcement; this is the
/// translation layer that makes their refusals legible.
fn translate(error: sqlx::Error, context: &'static str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        match db_error.code().as_deref() {
            // 23505 unique_violation — a sibling already has this name.
            Some("23505") => {
                return AppError::conflict("a group with that name already exists here");
            }
            // 23514 check_violation — raised by `groups_reject_cycle`, and by
            // the `groups_not_own_parent` constraint.
            Some("23514") => {
                return AppError::validation(
                    "that would put a group inside itself; a group tree has no cycles",
                );
            }
            _ => {}
        }
    }
    AppError::internal_from(context, error)
}

/// What a new group needs.
#[derive(Debug, Clone, Copy)]
pub struct NewGroup<'a> {
    /// Realm it belongs to.
    pub realm_id: RealmId,
    /// Parent, or `None` for a root group.
    pub parent_id: Option<GroupId>,
    /// Name, unique among its siblings.
    pub name: &'a str,
    /// What it is for.
    pub description: Option<&'a str>,
}

/// Create a group.
///
/// # Errors
///
/// * [`AppError::Validation`] — a blank name, or a parent in another realm.
/// * [`AppError::Conflict`] — a sibling already has that name.
/// * [`AppError::NotFound`] — the named parent does not exist.
pub async fn create(db: &Db, new: NewGroup<'_>) -> Result<Group> {
    let name = new.name.trim();
    if name.is_empty() {
        return Err(AppError::field("name", "must not be empty"));
    }
    // A slash would make the computed path ambiguous, and a path is what an
    // operator matches on.
    if name.contains('/') {
        return Err(AppError::field("name", "must not contain a slash"));
    }

    if let Some(parent_id) = new.parent_id {
        let parent = by_id(db, parent_id).await?;
        if parent.realm_id != new.realm_id {
            // Not `Forbidden`: a group in another realm is one this caller
            // cannot learn the existence of.
            return Err(AppError::NotFound("group"));
        }
    }

    let row = sqlx::query!(
        r#"
        INSERT INTO groups (realm_id, parent_id, name, description)
        VALUES ($1, $2, $3, $4)
        RETURNING id, realm_id, parent_id, name, description, created_at
        "#,
        new.realm_id.0,
        new.parent_id.map(|id| id.0),
        name,
        new.description,
    )
    .fetch_one(db)
    .await
    .map_err(|e| translate(e, "creating a group"))?;

    Ok(Group {
        path: path_of(db, GroupId(row.id)).await?,
        id: GroupId(row.id),
        realm_id: RealmId(row.realm_id),
        parent_id: row.parent_id.map(GroupId),
        name: row.name,
        description: row.description,
        created_at: row.created_at,
    })
}

/// Look one up.
///
/// # Errors
///
/// [`AppError::NotFound`] if no group has that id.
pub async fn by_id(db: &Db, id: GroupId) -> Result<Group> {
    let row = sqlx::query!(
        r#"
        SELECT id, realm_id, parent_id, name, description, created_at
          FROM groups WHERE id = $1
        "#,
        id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading a group", e))?
    .ok_or(AppError::NotFound("group"))?;

    Ok(Group {
        path: path_of(db, GroupId(row.id)).await?,
        id: GroupId(row.id),
        realm_id: RealmId(row.realm_id),
        parent_id: row.parent_id.map(GroupId),
        name: row.name,
        description: row.description,
        created_at: row.created_at,
    })
}

/// The full path of a group, from the root.
///
/// # Errors
///
/// Returns an internal error if the walk fails.
pub async fn path_of(db: &Db, id: GroupId) -> Result<String> {
    let names = sqlx::query_scalar!(
        r#"
        WITH RECURSIVE ancestry AS (
            SELECT id, parent_id, name, 0 AS depth FROM groups WHERE id = $1
            UNION
            SELECT g.id, g.parent_id, g.name, a.depth + 1
              FROM groups g JOIN ancestry a ON g.id = a.parent_id
        )
        SELECT name AS "name!" FROM ancestry ORDER BY depth DESC
        "#,
        id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("computing a group path", e))?;

    Ok(format!("/{}", names.join("/")))
}

/// Every group in a realm, ordered by path so the tree reads top-down.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, realm_id: RealmId) -> Result<Vec<Group>> {
    // One query for the whole realm rather than a path lookup per row: the
    // console renders the tree, and N+1 over a recursive CTE is how a group
    // page becomes the slowest thing in the console.
    let rows = sqlx::query!(
        r#"
        WITH RECURSIVE tree AS (
            SELECT id, realm_id, parent_id, name, description, created_at,
                   '/' || name AS path
              FROM groups
             WHERE realm_id = $1 AND parent_id IS NULL
            UNION ALL
            SELECT g.id, g.realm_id, g.parent_id, g.name, g.description,
                   g.created_at, t.path || '/' || g.name
              FROM groups g JOIN tree t ON g.parent_id = t.id
        )
        -- Every column is annotated non-null: a recursive CTE makes sqlx
        -- infer nullability it cannot see through, and each of these is
        -- `NOT NULL` on the table it came from.
        SELECT id AS "id!", realm_id AS "realm_id!", parent_id,
               name AS "name!", description, created_at AS "created_at!",
               path AS "path!"
          FROM tree ORDER BY path
        "#,
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing groups", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Group {
            id: GroupId(row.id),
            realm_id: RealmId(row.realm_id),
            parent_id: row.parent_id.map(GroupId),
            name: row.name,
            description: row.description,
            path: row.path,
            created_at: row.created_at,
        })
        .collect())
}

/// Move a group under a different parent, or to the root.
///
/// # Errors
///
/// * [`AppError::Validation`] — the move would create a cycle.
/// * [`AppError::Conflict`] — the destination already has a child by that name.
/// * [`AppError::NotFound`] — the group or the new parent does not exist, or
///   they are in different realms.
pub async fn move_to(db: &Db, id: GroupId, parent_id: Option<GroupId>) -> Result<Group> {
    let group = by_id(db, id).await?;

    if let Some(parent_id) = parent_id {
        let parent = by_id(db, parent_id).await?;
        if parent.realm_id != group.realm_id {
            return Err(AppError::NotFound("group"));
        }
    }

    sqlx::query!(
        "UPDATE groups SET parent_id = $2 WHERE id = $1",
        id.0,
        parent_id.map(|id| id.0),
    )
    .execute(db)
    .await
    .map_err(|e| translate(e, "moving a group"))?;

    by_id(db, id).await
}

/// Delete a group **and its whole subtree**.
///
/// # Errors
///
/// [`AppError::NotFound`] if it does not exist.
pub async fn delete(db: &Db, id: GroupId) -> Result<()> {
    let result = sqlx::query!("DELETE FROM groups WHERE id = $1", id.0)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("deleting a group", e))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("group"));
    }
    Ok(())
}

/// Put a user in a group. Idempotent.
///
/// # Errors
///
/// [`AppError::NotFound`] if either side is unknown, or [`AppError::Validation`]
/// if they are in different realms.
pub async fn add_member(db: &Db, group_id: GroupId, user_id: UserId) -> Result<()> {
    let group = by_id(db, group_id).await?;
    let user = crate::user::by_id(db, user_id).await?;

    if group.realm_id != user.realm_id {
        // A group in one realm holding a user from another would let a role
        // grant cross a tenant boundary, which is the one thing realms exist
        // to prevent.
        return Err(AppError::NotFound("group"));
    }

    sqlx::query!(
        "INSERT INTO group_members (group_id, user_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
        group_id.0,
        user_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("adding a group member", e))?;

    Ok(())
}

/// Take a user out of a group. Idempotent.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn remove_member(db: &Db, group_id: GroupId, user_id: UserId) -> Result<()> {
    sqlx::query!(
        "DELETE FROM group_members WHERE group_id = $1 AND user_id = $2",
        group_id.0,
        user_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("removing a group member", e))?;
    Ok(())
}

/// Who is directly in a group.
///
/// Direct membership only. Ancestry carries *roles* downward to members, not
/// membership upward — someone in `/engineering/backend` is not thereby a
/// member of `/engineering`, and reporting otherwise would make a membership
/// list disagree with what an administrator set.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn members(db: &Db, group_id: GroupId) -> Result<Vec<UserId>> {
    let ids = sqlx::query_scalar!(
        "SELECT user_id FROM group_members WHERE group_id = $1 ORDER BY added_at",
        group_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing group members", e))?;

    Ok(ids.into_iter().map(UserId).collect())
}

/// The groups a user is directly in.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn of_user(db: &Db, user_id: UserId) -> Result<Vec<Group>> {
    let ids = sqlx::query_scalar!(
        "SELECT group_id FROM group_members WHERE user_id = $1",
        user_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing a user's groups", e))?;

    let mut groups = Vec::with_capacity(ids.len());
    for id in ids {
        groups.push(by_id(db, GroupId(id)).await?);
    }
    groups.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(groups)
}

/// Grant a role to everyone in a group, and in its descendants. Idempotent.
///
/// # Errors
///
/// [`AppError::NotFound`] if either side is unknown, or if they are in
/// different realms.
pub async fn grant_role(db: &Db, group_id: GroupId, role_id: RoleId) -> Result<()> {
    let group = by_id(db, group_id).await?;
    let realm_of_role = sqlx::query_scalar!("SELECT realm_id FROM roles WHERE id = $1", role_id.0)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::internal_from("looking up a role's realm", e))?
        .ok_or(AppError::NotFound("role"))?;

    if RealmId(realm_of_role) != group.realm_id {
        return Err(AppError::NotFound("role"));
    }

    sqlx::query!(
        "INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2) \
         ON CONFLICT DO NOTHING",
        group_id.0,
        role_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("granting a role to a group", e))?;

    Ok(())
}

/// Take a role away from a group. Idempotent.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn revoke_role(db: &Db, group_id: GroupId, role_id: RoleId) -> Result<()> {
    sqlx::query!(
        "DELETE FROM group_roles WHERE group_id = $1 AND role_id = $2",
        group_id.0,
        role_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking a role from a group", e))?;
    Ok(())
}

/// The roles granted directly to a group.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn roles(db: &Db, group_id: GroupId) -> Result<Vec<Role>> {
    let rows = sqlx::query!(
        r#"
        SELECT r.id, r.realm_id, r.name, r.description
          FROM group_roles gr JOIN roles r ON r.id = gr.role_id
         WHERE gr.group_id = $1
         ORDER BY r.name
        "#,
        group_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing a group's roles", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Role {
            id: RoleId(row.id),
            realm_id: RealmId(row.realm_id),
            name: row.name,
            description: row.description,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;
    use crate::{
        password::PasswordHasher,
        realm, role,
        user::{self, NewUser},
    };
    use authenc_contract::{Permission, model::User};

    async fn a_realm_with_a_user(db: &Db, slug: &str) -> (RealmId, User) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, slug, slug).await.unwrap();
        let user = user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: &format!("alice@{slug}.example"),
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();
        (realm.id, user)
    }

    async fn group(db: &Db, realm_id: RealmId, parent: Option<GroupId>, name: &str) -> Group {
        create(
            db,
            NewGroup {
                realm_id,
                parent_id: parent,
                name,
                description: None,
            },
        )
        .await
        .unwrap()
    }

    /// A role in `realm_id` carrying exactly `permissions`.
    async fn role_with(
        db: &Db,
        realm_id: RealmId,
        name: &str,
        permissions: &[Permission],
    ) -> RoleId {
        let role = role::ensure(db, realm_id, name, None).await.unwrap();
        role::set_permissions(db, realm_id, role.id, permissions)
            .await
            .unwrap();
        role.id
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_group_knows_its_path(db: Db) {
        let (realm_id, _) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let back = group(&db, realm_id, Some(eng.id), "backend").await;
        let deep = group(&db, realm_id, Some(back.id), "payments").await;

        assert_eq!(eng.path, "/engineering");
        assert_eq!(back.path, "/engineering/backend");
        assert_eq!(deep.path, "/engineering/backend/payments");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_member_inherits_roles_from_every_ancestor(db: Db) {
        // The property that makes this access control rather than an org chart.
        let (realm_id, alice) = a_realm_with_a_user(&db, "acme").await;

        let eng = group(&db, realm_id, None, "engineering").await;
        let back = group(&db, realm_id, Some(eng.id), "backend").await;

        let readers = role_with(&db, realm_id, "readers", &[Permission::UserRead]).await;
        let writers = role_with(&db, realm_id, "writers", &[Permission::ClientWrite]).await;

        grant_role(&db, eng.id, readers).await.unwrap();
        grant_role(&db, back.id, writers).await.unwrap();

        // Membership of the *child* only.
        add_member(&db, back.id, alice.id).await.unwrap();

        let permissions = user::permissions(&db, alice.id).await.unwrap();
        assert!(
            permissions.contains(&Permission::UserRead),
            "the ancestor's role must reach a member of the child: {permissions:?}",
        );
        assert!(
            permissions.contains(&Permission::ClientWrite),
            "{permissions:?}"
        );

        let names = user::role_names(&db, alice.id).await.unwrap();
        assert_eq!(names, vec!["readers".to_owned(), "writers".to_owned()]);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn inheritance_does_not_run_downward(db: Db) {
        // A member of the parent must NOT pick up the child's roles. If it did,
        // adding a nested group would silently widen what everyone above it can
        // do — nesting would be a privilege escalation.
        let (realm_id, alice) = a_realm_with_a_user(&db, "acme").await;

        let eng = group(&db, realm_id, None, "engineering").await;
        let back = group(&db, realm_id, Some(eng.id), "backend").await;

        let writers = role_with(&db, realm_id, "writers", &[Permission::ClientWrite]).await;
        grant_role(&db, back.id, writers).await.unwrap();
        add_member(&db, eng.id, alice.id).await.unwrap();

        let permissions = user::permissions(&db, alice.id).await.unwrap();
        assert!(
            !permissions.contains(&Permission::ClientWrite),
            "a child's role leaked upward: {permissions:?}",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn leaving_a_group_takes_the_roles_with_it(db: Db) {
        let (realm_id, alice) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let readers = role_with(&db, realm_id, "readers", &[Permission::UserRead]).await;

        grant_role(&db, eng.id, readers).await.unwrap();
        add_member(&db, eng.id, alice.id).await.unwrap();
        assert!(
            user::permissions(&db, alice.id)
                .await
                .unwrap()
                .contains(&Permission::UserRead),
        );

        remove_member(&db, eng.id, alice.id).await.unwrap();
        assert!(
            user::permissions(&db, alice.id).await.unwrap().is_empty(),
            "removal must take effect immediately; nothing is cached in a token",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_cycle_is_refused_rather_than_hanging(db: Db) {
        // Enforced by a database trigger. A cycle would make every ancestry
        // walk non-terminating, and one runs on every authorised request.
        let (realm_id, _) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let back = group(&db, realm_id, Some(eng.id), "backend").await;
        let deep = group(&db, realm_id, Some(back.id), "payments").await;

        let error = move_to(&db, eng.id, Some(deep.id)).await.unwrap_err();
        assert_eq!(error.status(), 400, "{error}");

        // And the tree is untouched.
        assert_eq!(by_id(&db, eng.id).await.unwrap().parent_id, None);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_group_cannot_be_its_own_parent(db: Db) {
        let (realm_id, _) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;

        assert_eq!(
            move_to(&db, eng.id, Some(eng.id))
                .await
                .unwrap_err()
                .status(),
            400,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn siblings_may_not_share_a_name_but_cousins_may(db: Db) {
        let (realm_id, _) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let sales = group(&db, realm_id, None, "sales").await;

        group(&db, realm_id, Some(eng.id), "leads").await;
        // Same name, different parent: fine.
        group(&db, realm_id, Some(sales.id), "leads").await;

        // Same name, same parent: refused, case-insensitively.
        let clash = create(
            &db,
            NewGroup {
                realm_id,
                parent_id: Some(eng.id),
                name: "LEADS",
                description: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(clash.status(), 409, "{clash}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_group_cannot_hold_a_user_from_another_realm(db: Db) {
        // A role grant crossing a tenant boundary is the one thing realms
        // exist to prevent.
        let (acme, _) = a_realm_with_a_user(&db, "acme").await;
        let (_, bob) = a_realm_with_a_user(&db, "other").await;

        let eng = group(&db, acme, None, "engineering").await;
        assert_eq!(
            add_member(&db, eng.id, bob.id).await.unwrap_err().status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_group_cannot_be_granted_another_realms_role(db: Db) {
        let (acme, _) = a_realm_with_a_user(&db, "acme").await;
        let (other, _) = a_realm_with_a_user(&db, "other").await;

        let eng = group(&db, acme, None, "engineering").await;
        let foreign = role_with(&db, other, "readers", &[Permission::UserRead]).await;

        assert_eq!(
            grant_role(&db, eng.id, foreign).await.unwrap_err().status(),
            404,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_group_cannot_be_nested_under_another_realms_group(db: Db) {
        let (acme, _) = a_realm_with_a_user(&db, "acme").await;
        let (other, _) = a_realm_with_a_user(&db, "other").await;

        let theirs = group(&db, other, None, "theirs").await;
        let error = create(
            &db,
            NewGroup {
                realm_id: acme,
                parent_id: Some(theirs.id),
                name: "ours",
                description: None,
            },
        )
        .await
        .unwrap_err();

        assert_eq!(error.status(), 404);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deleting_a_group_takes_its_subtree_and_its_grants(db: Db) {
        let (realm_id, alice) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let back = group(&db, realm_id, Some(eng.id), "backend").await;

        let readers = role_with(&db, realm_id, "readers", &[Permission::UserRead]).await;
        grant_role(&db, back.id, readers).await.unwrap();
        add_member(&db, back.id, alice.id).await.unwrap();

        delete(&db, eng.id).await.unwrap();

        assert_eq!(by_id(&db, back.id).await.unwrap_err().status(), 404);
        assert!(
            user::permissions(&db, alice.id).await.unwrap().is_empty(),
            "the grants must go with the subtree",
        );
        // The user themself is untouched.
        assert!(user::by_id(&db, alice.id).await.is_ok());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_listing_reads_as_a_tree(db: Db) {
        let (realm_id, _) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        group(&db, realm_id, Some(eng.id), "backend").await;
        group(&db, realm_id, None, "sales").await;

        let paths: Vec<_> = list(&db, realm_id)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.path)
            .collect();

        assert_eq!(
            paths,
            vec!["/engineering", "/engineering/backend", "/sales"],
            "ordering by path is what makes the listing render as a tree",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_realms_groups_are_invisible_to_another(db: Db) {
        let (acme, _) = a_realm_with_a_user(&db, "acme").await;
        let (other, _) = a_realm_with_a_user(&db, "other").await;
        group(&db, acme, None, "engineering").await;

        assert!(list(&db, other).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_moved_group_carries_its_members_roles_with_it(db: Db) {
        // Moving a group changes which ancestors it inherits from, and that has
        // to take effect at once rather than at the next login.
        let (realm_id, alice) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let sales = group(&db, realm_id, None, "sales").await;
        let team = group(&db, realm_id, Some(eng.id), "team").await;

        let readers = role_with(&db, realm_id, "readers", &[Permission::UserRead]).await;
        let closers = role_with(&db, realm_id, "closers", &[Permission::ClientRead]).await;
        grant_role(&db, eng.id, readers).await.unwrap();
        grant_role(&db, sales.id, closers).await.unwrap();
        add_member(&db, team.id, alice.id).await.unwrap();

        assert_eq!(
            user::permissions(&db, alice.id).await.unwrap(),
            vec![Permission::UserRead],
        );

        let moved = move_to(&db, team.id, Some(sales.id)).await.unwrap();
        assert_eq!(moved.path, "/sales/team");
        assert_eq!(
            user::permissions(&db, alice.id).await.unwrap(),
            vec![Permission::ClientRead],
            "the old ancestor's role must stop applying",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_blank_or_slashed_name_is_refused(db: Db) {
        let (realm_id, _) = a_realm_with_a_user(&db, "acme").await;
        for bad in ["", "   ", "eng/back"] {
            let error = create(
                &db,
                NewGroup {
                    realm_id,
                    parent_id: None,
                    name: bad,
                    description: None,
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.status(), 400, "{bad:?} was accepted");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn membership_and_grants_are_idempotent(db: Db) {
        let (realm_id, alice) = a_realm_with_a_user(&db, "acme").await;
        let eng = group(&db, realm_id, None, "engineering").await;
        let readers = role_with(&db, realm_id, "readers", &[Permission::UserRead]).await;

        for _ in 0..3 {
            add_member(&db, eng.id, alice.id).await.unwrap();
            grant_role(&db, eng.id, readers).await.unwrap();
        }

        assert_eq!(members(&db, eng.id).await.unwrap(), vec![alice.id]);
        assert_eq!(roles(&db, eng.id).await.unwrap().len(), 1);
        assert_eq!(of_user(&db, alice.id).await.unwrap().len(), 1);
    }
}
