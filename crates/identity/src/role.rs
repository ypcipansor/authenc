//! Roles and their assignment to users.

use authenc_contract::{AppError, Permission, RealmId, Result, RoleId, UserId, model::Role};

use crate::db::Db;

/// Create a role if it does not exist, and return it either way.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn ensure(
    db: &Db,
    realm_id: RealmId,
    name: &str,
    description: Option<&str>,
) -> Result<Role> {
    let row = sqlx::query!(
        r#"
        INSERT INTO roles (realm_id, name, description)
        VALUES ($1, $2, $3)
        ON CONFLICT (realm_id, name)
            DO UPDATE SET description = COALESCE(EXCLUDED.description, roles.description)
        RETURNING id, realm_id, name, description
        "#,
        realm_id.0,
        name,
        description,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("creating role", e))?;

    Ok(Role {
        id: RoleId(row.id),
        realm_id: RealmId(row.realm_id),
        name: row.name,
        description: row.description,
    })
}

/// Make these the role's permissions, creating the permission rows as needed.
///
/// **Replaces.** Anything the role holds and this set does not is removed, in
/// the same transaction. That is what "set" has to mean: `PUT
/// /api/v1/roles/{id}/permissions` documents the body as the complete set, and
/// an earlier version of this function only ever inserted — so withdrawing a
/// permission returned 200 and kept it. Withdrawing one is the operation an
/// incident needs, and it was the one that did not work.
///
/// Idempotent, so it is safe to call on every seed or upgrade.
///
/// # Errors
///
/// Returns an internal error if a write fails.
pub async fn set_permissions(
    db: &Db,
    realm_id: RealmId,
    role_id: RoleId,
    permissions: &[Permission],
) -> Result<()> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("beginning transaction", e))?;

    for permission in permissions {
        let permission_id = sqlx::query_scalar!(
            r#"
            INSERT INTO permissions (realm_id, name, description)
            VALUES ($1, $2, $3)
            ON CONFLICT (realm_id, name) DO UPDATE SET description = EXCLUDED.description
            RETURNING id
            "#,
            realm_id.0,
            permission.as_str(),
            permission.description(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AppError::internal_from("creating permission", e))?;

        sqlx::query!(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
            role_id.0,
            permission_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::internal_from("attaching permission to role", e))?;
    }

    // Then withdraw whatever is no longer in the set. Inside the same
    // transaction, so a role is never briefly empty and never briefly holds
    // the union of the old and new sets.
    let keep: Vec<String> = permissions
        .iter()
        .map(|permission| permission.as_str().to_owned())
        .collect();

    sqlx::query!(
        r#"
        DELETE FROM role_permissions
         WHERE role_id = $1
           AND permission_id IN (
               SELECT id FROM permissions
                WHERE realm_id = $2 AND NOT (name = ANY($3))
           )
        "#,
        role_id.0,
        realm_id.0,
        &keep,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("withdrawing permissions from role", e))?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("committing transaction", e))?;

    Ok(())
}

/// Grant a role to a user. Granting a role twice is not an error.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn grant(db: &Db, user_id: UserId, role_id: RoleId) -> Result<()> {
    sqlx::query!(
        "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        user_id.0,
        role_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("granting role", e))?;

    Ok(())
}

/// Revoke a role from a user. Revoking a role they do not hold is not an error.
///
/// # Errors
///
/// Returns an internal error if the write fails.
pub async fn revoke(db: &Db, user_id: UserId, role_id: RoleId) -> Result<()> {
    sqlx::query!(
        "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
        user_id.0,
        role_id.0,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("revoking role", e))?;

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
    use authenc_contract::Permission;

    async fn fixture(db: &Db) -> (RealmId, UserId) {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        let user = user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "alice",
                email: "alice@example.com",
                password: test_support::password(),
                first_name: None,
                last_name: None,
            },
        )
        .await
        .unwrap();
        (realm.id, user.id)
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn ensure_is_idempotent(db: Db) {
        let (realm_id, _) = fixture(&db).await;

        let first = ensure(&db, realm_id, "admin", Some("Full access"))
            .await
            .unwrap();
        let second = ensure(&db, realm_id, "admin", None).await.unwrap();

        assert_eq!(first.id, second.id, "must reuse, not duplicate");
        assert_eq!(
            second.description.as_deref(),
            Some("Full access"),
            "a later call without a description must not erase the existing one",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn granting_a_role_makes_it_visible_on_the_user(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "admin", None).await.unwrap();

        assert!(user::role_names(&db, user_id).await.unwrap().is_empty());

        grant(&db, user_id, role.id).await.unwrap();
        assert_eq!(
            user::role_names(&db, user_id).await.unwrap(),
            vec!["admin".to_owned()],
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn granting_twice_is_not_an_error(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "admin", None).await.unwrap();

        grant(&db, user_id, role.id).await.unwrap();
        grant(&db, user_id, role.id).await.unwrap();

        assert_eq!(user::role_names(&db, user_id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn revoking_removes_the_role(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "admin", None).await.unwrap();

        grant(&db, user_id, role.id).await.unwrap();
        revoke(&db, user_id, role.id).await.unwrap();

        assert!(user::role_names(&db, user_id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn permissions_attached_to_a_role_reach_the_users_holding_it(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "auditor", None).await.unwrap();

        set_permissions(&db, realm_id, role.id, &[Permission::UserRead])
            .await
            .unwrap();

        // Before the grant the role's permissions are irrelevant to the user.
        assert!(user::permissions(&db, user_id).await.unwrap().is_empty());

        grant(&db, user_id, role.id).await.unwrap();
        assert_eq!(
            user::permissions(&db, user_id).await.unwrap(),
            vec![Permission::UserRead],
        );

        // Revoking the role takes the permission with it.
        revoke(&db, user_id, role.id).await.unwrap();
        assert!(user::permissions(&db, user_id).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn setting_permissions_is_idempotent(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "auditor", None).await.unwrap();
        grant(&db, user_id, role.id).await.unwrap();

        for _ in 0..3 {
            set_permissions(&db, realm_id, role.id, Permission::ALL)
                .await
                .unwrap();
        }

        let held = user::permissions(&db, user_id).await.unwrap();
        assert_eq!(held.len(), Permission::ALL.len(), "no duplicates: {held:?}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unrecognised_permission_row_is_ignored_not_guessed(db: Db) {
        let (realm_id, user_id) = fixture(&db).await;
        let role = ensure(&db, realm_id, "auditor", None).await.unwrap();
        grant(&db, user_id, role.id).await.unwrap();
        set_permissions(&db, realm_id, role.id, &[Permission::UserRead])
            .await
            .unwrap();

        // A row left behind by a rename must neither lock everyone out nor be
        // mapped onto some other permission.
        let stray: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO permissions (realm_id, name) VALUES ($1, 'user:destroy') RETURNING id",
        )
        .bind(realm_id.0)
        .fetch_one(&db)
        .await
        .unwrap();
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)")
            .bind(role.id.0)
            .bind(stray)
            .execute(&db)
            .await
            .unwrap();

        assert_eq!(
            user::permissions(&db, user_id).await.unwrap(),
            vec![Permission::UserRead],
        );
    }

    /// The permissions a role currently holds, sorted so comparisons are
    /// stable.
    async fn permissions_of(db: &Db, role_id: RoleId) -> Vec<Permission> {
        let names = sqlx::query_scalar!(
            "SELECT p.name FROM role_permissions rp \
             JOIN permissions p ON p.id = rp.permission_id \
             WHERE rp.role_id = $1 ORDER BY p.name",
            role_id.0,
        )
        .fetch_all(db)
        .await
        .unwrap();

        names.iter().filter_map(|name| name.parse().ok()).collect()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn setting_permissions_withdraws_the_ones_left_out(db: Db) {
        // "Set" has to mean set. An earlier version only inserted, so
        // `PUT /api/v1/roles/{id}/permissions` reported success for a
        // withdrawal and kept the permission — which is the operation an
        // incident actually needs.
        let (realm_id, _user) = fixture(&db).await;
        let role = ensure(&db, realm_id, "operator", None).await.unwrap();

        set_permissions(
            &db,
            realm_id,
            role.id,
            &[Permission::UserRead, Permission::UserWrite],
        )
        .await
        .unwrap();
        assert_eq!(permissions_of(&db, role.id).await.len(), 2);

        set_permissions(&db, realm_id, role.id, &[Permission::UserRead])
            .await
            .unwrap();

        let held = permissions_of(&db, role.id).await;
        assert_eq!(held, vec![Permission::UserRead], "user:write survived");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn setting_permissions_does_not_disturb_another_role(db: Db) {
        // The withdrawal is scoped to this role. Deleting by permission name
        // across the realm would empty every other role that shared one.
        let (realm_id, _user) = fixture(&db).await;
        let keeper = ensure(&db, realm_id, "keeper", None).await.unwrap();
        let loser = ensure(&db, realm_id, "loser", None).await.unwrap();

        set_permissions(&db, realm_id, keeper.id, &[Permission::UserWrite])
            .await
            .unwrap();
        set_permissions(&db, realm_id, loser.id, &[Permission::UserWrite])
            .await
            .unwrap();

        set_permissions(&db, realm_id, loser.id, &[Permission::RoleRead])
            .await
            .unwrap();

        assert_eq!(
            permissions_of(&db, keeper.id).await,
            vec![Permission::UserWrite]
        );
        assert_eq!(
            permissions_of(&db, loser.id).await,
            vec![Permission::RoleRead]
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn roles_are_scoped_to_their_realm(db: Db) {
        let (realm_id, _) = fixture(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap();

        let here = ensure(&db, realm_id, "admin", None).await.unwrap();
        let there = ensure(&db, other.id, "admin", None).await.unwrap();

        assert_ne!(
            here.id, there.id,
            "the same role name in two realms must be two roles",
        );
    }
}
