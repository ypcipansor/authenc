//! Recording and querying the audit log.
//!
//! # The write must not decide whether the action happens
//!
//! There are two honest positions on what to do when an audit write fails, and
//! this module takes one of them deliberately rather than by accident.
//!
//! The strict position: if it cannot be recorded, it must not happen. That is
//! right for a system where the log is the product — a ledger, a court record.
//! It is wrong here, because it turns every audit-table problem into a total
//! authentication outage, and an IAM server that will not let anyone in is
//! itself the incident.
//!
//! So [`record`] returns a `Result` and [`observe`] swallows it into a loud
//! `tracing::error!`. Call sites in the middle of an operation use `observe`;
//! the failure is visible in the logs and in metrics, and the operation
//! proceeds. This is a real gap and it is written down here rather than
//! discovered later: **a dropped audit write is not detectable from the audit
//! log itself.**
//!
//! # What must never be written here
//!
//! Passwords, tokens, codes, secrets, or anything derived from them. `detail`
//! is a `serde_json::Value` and would happily take any of it. There is no
//! automated guard — the guard is that no function in this crate constructs a
//! `detail` from a credential, and review keeps it that way.

use authenc_contract::{
    AppError, RealmId, Result, UserId,
    event::{Action, AuditEvent, Outcome},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{db::Db, session::Origin};

/// Something that happened, on its way to being recorded.
///
/// Built with the struct-update syntax from [`Entry::new`], so a call site
/// names only the fields it actually knows.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    /// Realm the event belongs to, if it has one.
    pub realm_id: Option<RealmId>,
    /// What happened.
    pub action: Action,
    /// Whether it worked.
    pub outcome: Outcome,
    /// Who did it, if a known user did.
    pub actor_id: Option<UserId>,
    /// Their name at the time. Stored as given.
    pub actor_name: Option<&'a str>,
    /// What kind of thing it was done to.
    pub target_type: Option<&'a str>,
    /// Which one.
    pub target: Option<&'a str>,
    /// Where the request came from.
    pub origin: Origin<'a>,
    /// Anything action-specific. Never a credential.
    pub detail: serde_json::Value,
}

impl<'a> Entry<'a> {
    /// A minimal entry: what happened, and whether it worked.
    #[must_use]
    pub fn new(action: Action, outcome: Outcome) -> Self {
        Self {
            realm_id: None,
            action,
            outcome,
            actor_id: None,
            actor_name: None,
            target_type: None,
            target: None,
            origin: Origin::default(),
            detail: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// A successful action.
    #[must_use]
    pub fn success(action: Action) -> Self {
        Self::new(action, Outcome::Success)
    }

    /// A refused action.
    #[must_use]
    pub fn failure(action: Action) -> Self {
        Self::new(action, Outcome::Failure)
    }

    /// Attach the realm.
    #[must_use]
    pub const fn in_realm(mut self, realm_id: RealmId) -> Self {
        self.realm_id = Some(realm_id);
        self
    }

    /// Attach who did it.
    #[must_use]
    pub const fn by(mut self, actor_id: UserId, actor_name: &'a str) -> Self {
        self.actor_id = Some(actor_id);
        self.actor_name = Some(actor_name);
        self
    }

    /// Attach who did it, when only the id is known.
    ///
    /// Separate from [`Entry::by`] rather than taking an `Option<&str>`,
    /// because the tempting shortcut at such a call site is an empty string —
    /// which reads in the console as an account with no name rather than as an
    /// unrecorded one.
    #[must_use]
    pub const fn by_id(mut self, actor_id: UserId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    /// Attach who did it, when only the name is known — a failed login naming
    /// an account that does not exist, for instance.
    #[must_use]
    pub const fn by_name(mut self, actor_name: &'a str) -> Self {
        self.actor_name = Some(actor_name);
        self
    }

    /// Attach what it was done to.
    #[must_use]
    pub const fn to(mut self, target_type: &'a str, target: &'a str) -> Self {
        self.target_type = Some(target_type);
        self.target = Some(target);
        self
    }

    /// Attach where the request came from.
    #[must_use]
    pub const fn from(mut self, origin: Origin<'a>) -> Self {
        self.origin = origin;
        self
    }

    /// Attach action-specific detail.
    ///
    /// # Panics
    ///
    /// Never. A non-object value is replaced by an empty object rather than
    /// stored, because the column is queried with JSON object operators.
    #[must_use]
    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = if detail.is_object() {
            detail
        } else {
            serde_json::Value::Object(serde_json::Map::new())
        };
        self
    }
}

/// Write an entry.
///
/// # Errors
///
/// Returns an internal error if the insert fails. Most call sites should use
/// [`observe`] instead — see the module documentation for why.
pub async fn record(db: &Db, entry: Entry<'_>) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO audit_events
            (realm_id, action, outcome, actor_id, actor_name,
             target_type, target, ip_address, user_agent, detail)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text::inet, $9, $10)
        "#,
        entry.realm_id.map(|id| id.0),
        entry.action.as_str(),
        entry.outcome.as_str(),
        entry.actor_id.map(|id| id.0),
        entry.actor_name,
        entry.target_type,
        entry.target,
        entry.origin.ip_address.map(|ip| ip.to_string()),
        entry.origin.user_agent,
        entry.detail,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("recording an audit event", e))?;

    Ok(())
}

/// Write an entry, reporting a failure to the log rather than to the caller.
///
/// This is what a call site in the middle of an operation uses. A failure here
/// is a real gap in the trail — it is logged at `error` so it is visible in
/// whatever collects logs, because by definition it will not be visible in the
/// audit log.
pub async fn observe(db: &Db, entry: Entry<'_>) {
    let action = entry.action;
    if let Err(error) = record(db, entry).await {
        tracing::error!(
            %error,
            %action,
            "failed to record an audit event; the trail has a gap here",
        );
    }
}

/// What to narrow a query to.
///
/// Every field is optional and they combine with AND. `None` everywhere means
/// "this realm, newest first", which is what the console opens with.
#[derive(Debug, Clone, Copy, Default)]
pub struct Filter<'a> {
    /// Only this action.
    pub action: Option<Action>,
    /// Only actions whose stored name starts with this, so `mfa.` selects a
    /// whole category without listing its members.
    pub prefix: Option<&'a str>,
    /// Only this outcome.
    pub outcome: Option<Outcome>,
    /// Only what this user did.
    pub actor_id: Option<UserId>,
    /// Only events at or after this moment.
    pub since: Option<OffsetDateTime>,
    /// Only events before this moment.
    pub until: Option<OffsetDateTime>,
}

/// Largest page a caller may ask for.
///
/// The console pages; an export streams by walking pages. Neither needs an
/// unbounded query, and allowing one turns a busy realm's audit log into a way
/// to exhaust the server's memory from a single request.
pub const MAX_LIMIT: i64 = 500;

/// Read events for a realm, newest first.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(
    db: &Db,
    realm_id: RealmId,
    filter: Filter<'_>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditEvent>> {
    let limit = limit.clamp(1, MAX_LIMIT);
    let offset = offset.max(0);

    let rows = sqlx::query!(
        r#"
        SELECT id, realm_id, action, outcome, actor_id, actor_name,
               target_type, target, host(ip_address) AS ip_address,
               user_agent, occurred_at
          FROM audit_events
         WHERE realm_id = $1
           AND ($2::text IS NULL OR action = $2)
           AND ($3::text IS NULL OR action LIKE $3 || '%')
           AND ($4::text IS NULL OR outcome = $4)
           AND ($5::uuid IS NULL OR actor_id = $5)
           AND ($6::timestamptz IS NULL OR occurred_at >= $6)
           AND ($7::timestamptz IS NULL OR occurred_at < $7)
         ORDER BY occurred_at DESC, id DESC
         LIMIT $8 OFFSET $9
        "#,
        realm_id.0,
        filter.action.map(Action::as_str),
        filter.prefix,
        filter.outcome.map(Outcome::as_str),
        filter.actor_id.map(|id| id.0),
        filter.since,
        filter.until,
        limit,
        offset,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing audit events", e))?;

    rows.into_iter()
        .map(|row| {
            Ok(AuditEvent {
                id: row.id,
                realm_id: RealmId(
                    row.realm_id
                        .ok_or_else(|| AppError::internal("an audit row lost its realm"))?,
                ),
                // A row whose action no longer parses is a bug in a migration,
                // not a reason to hide the row: report it rather than dropping
                // it silently from a trail somebody is relying on.
                action: row
                    .action
                    .parse()
                    .map_err(|_| AppError::internal("an audit row has an unknown action"))?,
                outcome: if row.outcome == Outcome::Success.as_str() {
                    Outcome::Success
                } else {
                    Outcome::Failure
                },
                actor_id: row.actor_id.map(UserId),
                actor_name: row.actor_name,
                target_type: row.target_type,
                target: row.target,
                ip_address: row.ip_address,
                user_agent: row.user_agent,
                occurred_at: row
                    .occurred_at
                    .format(&Rfc3339)
                    .map_err(|e| AppError::internal_from("formatting an audit timestamp", e))?,
            })
        })
        .collect()
}

/// How many events match, for paging.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn count(db: &Db, realm_id: RealmId, filter: Filter<'_>) -> Result<i64> {
    sqlx::query_scalar!(
        r#"
        SELECT count(*) AS "count!"
          FROM audit_events
         WHERE realm_id = $1
           AND ($2::text IS NULL OR action = $2)
           AND ($3::text IS NULL OR action LIKE $3 || '%')
           AND ($4::text IS NULL OR outcome = $4)
           AND ($5::uuid IS NULL OR actor_id = $5)
           AND ($6::timestamptz IS NULL OR occurred_at >= $6)
           AND ($7::timestamptz IS NULL OR occurred_at < $7)
        "#,
        realm_id.0,
        filter.action.map(Action::as_str),
        filter.prefix,
        filter.outcome.map(Outcome::as_str),
        filter.actor_id.map(|id| id.0),
        filter.since,
        filter.until,
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::internal_from("counting audit events", e))
}

/// Delete events older than a cut-off, returning how many went.
///
/// The only path in this module that removes anything. Retention is an
/// explicit operator decision — `authenc purge --audit-older-than` — rather
/// than something that happens quietly, because an audit log that trims itself
/// on a schedule nobody chose is one that will be empty when it is needed.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_before(db: &Db, cutoff: OffsetDateTime) -> Result<u64> {
    let result = sqlx::query!("DELETE FROM audit_events WHERE occurred_at < $1", cutoff)
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("purging audit events", e))?;

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
    use authenc_contract::model::User;

    async fn fixture(db: &Db) -> User {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        user::create(
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
        .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_recorded_event_comes_back(db: Db) {
        let user = fixture(&db).await;

        record(
            &db,
            Entry::success(Action::LoginSucceeded)
                .in_realm(user.realm_id)
                .by(user.id, &user.username)
                .from(Origin {
                    user_agent: Some("curl/8"),
                    ip_address: Some("203.0.113.7".parse().unwrap()),
                }),
        )
        .await
        .unwrap();

        let events = list(&db, user.realm_id, Filter::default(), 50, 0)
            .await
            .unwrap();

        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.action, Action::LoginSucceeded);
        assert_eq!(event.outcome, Outcome::Success);
        assert_eq!(event.actor_id, Some(user.id));
        assert_eq!(event.actor_name.as_deref(), Some("alice"));
        assert_eq!(event.ip_address.as_deref(), Some("203.0.113.7"));
        assert_eq!(event.user_agent.as_deref(), Some("curl/8"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_record_outlives_the_account_it_names(db: Db) {
        // The property the denormalised `actor_name` exists for. Without it,
        // deleting a user turns their whole history into "somebody".
        let user = fixture(&db).await;

        record(
            &db,
            Entry::success(Action::RoleGranted)
                .in_realm(user.realm_id)
                .by(user.id, &user.username)
                .to("role", "admin"),
        )
        .await
        .unwrap();

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user.id.0)
            .execute(&db)
            .await
            .unwrap();

        let events = list(&db, user.realm_id, Filter::default(), 50, 0)
            .await
            .unwrap();

        assert_eq!(events.len(), 1, "the record must survive the deletion");
        assert_eq!(events[0].actor_name.as_deref(), Some("alice"));
        assert_eq!(events[0].actor_id, None, "the id is gone, the name is not");
        assert_eq!(events[0].target.as_deref(), Some("admin"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn events_come_back_newest_first(db: Db) {
        let user = fixture(&db).await;

        for action in [
            Action::LoginFailed,
            Action::LoginSucceeded,
            Action::LoggedOut,
        ] {
            record(&db, Entry::success(action).in_realm(user.realm_id))
                .await
                .unwrap();
            // Postgres `now()` is the transaction start time, so distinct
            // statements are needed for distinct timestamps; the id tiebreak
            // in the ORDER BY covers the rest.
            sqlx::query("SELECT pg_sleep(0.01)")
                .execute(&db)
                .await
                .unwrap();
        }

        let events = list(&db, user.realm_id, Filter::default(), 50, 0)
            .await
            .unwrap();

        assert_eq!(events[0].action, Action::LoggedOut);
        assert_eq!(events[2].action, Action::LoginFailed);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn filtering_narrows_by_action_outcome_and_actor(db: Db) {
        let user = fixture(&db).await;
        let realm_id = user.realm_id;

        record(
            &db,
            Entry::success(Action::LoginSucceeded)
                .in_realm(realm_id)
                .by(user.id, "alice"),
        )
        .await
        .unwrap();
        record(
            &db,
            Entry::failure(Action::LoginFailed)
                .in_realm(realm_id)
                .by_name("mallory"),
        )
        .await
        .unwrap();

        let failures = list(
            &db,
            realm_id,
            Filter {
                outcome: Some(Outcome::Failure),
                ..Filter::default()
            },
            50,
            0,
        )
        .await
        .unwrap();
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].actor_name.as_deref(), Some("mallory"));

        let by_action = list(
            &db,
            realm_id,
            Filter {
                action: Some(Action::LoginSucceeded),
                ..Filter::default()
            },
            50,
            0,
        )
        .await
        .unwrap();
        assert_eq!(by_action.len(), 1);

        let by_actor = list(
            &db,
            realm_id,
            Filter {
                actor_id: Some(user.id),
                ..Filter::default()
            },
            50,
            0,
        )
        .await
        .unwrap();
        assert_eq!(by_actor.len(), 1);
        assert_eq!(by_actor[0].action, Action::LoginSucceeded);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_prefix_selects_a_whole_namespace(db: Db) {
        // What makes `mfa.` a usable filter without listing its members.
        let user = fixture(&db).await;

        for action in [
            Action::TotpEnrolled,
            Action::PasskeyRegistered,
            Action::LoginSucceeded,
        ] {
            record(&db, Entry::success(action).in_realm(user.realm_id))
                .await
                .unwrap();
        }

        let mfa = list(
            &db,
            user.realm_id,
            Filter {
                prefix: Some("mfa."),
                ..Filter::default()
            },
            50,
            0,
        )
        .await
        .unwrap();

        assert_eq!(mfa.len(), 2);
        assert!(mfa.iter().all(|e| e.action.as_str().starts_with("mfa.")));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn one_realm_cannot_read_anothers_trail(db: Db) {
        // The same tenant boundary the rest of the system enforces. An audit
        // log that leaks across realms is worse than none, because it is
        // trusted.
        let alice = fixture(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap();

        record(
            &db,
            Entry::success(Action::LoginSucceeded).in_realm(alice.realm_id),
        )
        .await
        .unwrap();

        let events = list(&db, other.id, Filter::default(), 50, 0).await.unwrap();
        assert!(events.is_empty());
        assert_eq!(count(&db, other.id, Filter::default()).await.unwrap(), 0);
        assert_eq!(
            count(&db, alice.realm_id, Filter::default()).await.unwrap(),
            1,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_caller_cannot_ask_for_an_unbounded_page(db: Db) {
        let user = fixture(&db).await;
        for _ in 0..3 {
            record(
                &db,
                Entry::success(Action::LoginSucceeded).in_realm(user.realm_id),
            )
            .await
            .unwrap();
        }

        // Absurd limits are clamped rather than refused, so a caller asking for
        // too much gets the maximum instead of an error.
        let huge = list(&db, user.realm_id, Filter::default(), i64::MAX, 0)
            .await
            .unwrap();
        assert_eq!(huge.len(), 3);

        // And a nonsensical one still returns something usable.
        let zero = list(&db, user.realm_id, Filter::default(), 0, -5)
            .await
            .unwrap();
        assert_eq!(zero.len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn paging_walks_the_whole_trail_without_repeats(db: Db) {
        let user = fixture(&db).await;
        for _ in 0..5 {
            record(
                &db,
                Entry::success(Action::LoginSucceeded).in_realm(user.realm_id),
            )
            .await
            .unwrap();
        }

        let mut seen = std::collections::HashSet::new();
        for offset in (0..5).step_by(2) {
            for event in list(&db, user.realm_id, Filter::default(), 2, offset)
                .await
                .unwrap()
            {
                assert!(seen.insert(event.id), "an event appeared on two pages");
            }
        }
        assert_eq!(seen.len(), 5);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn retention_removes_only_what_is_older_than_the_cutoff(db: Db) {
        let user = fixture(&db).await;

        record(
            &db,
            Entry::success(Action::LoginSucceeded).in_realm(user.realm_id),
        )
        .await
        .unwrap();
        record(
            &db,
            Entry::success(Action::LoggedOut).in_realm(user.realm_id),
        )
        .await
        .unwrap();

        sqlx::query(
            "UPDATE audit_events SET occurred_at = now() - interval '400 days' \
             WHERE action = 'login.succeeded'",
        )
        .execute(&db)
        .await
        .unwrap();

        let cutoff = OffsetDateTime::now_utc() - time::Duration::days(365);
        assert_eq!(purge_before(&db, cutoff).await.unwrap(), 1);

        let left = list(&db, user.realm_id, Filter::default(), 50, 0)
            .await
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].action, Action::LoggedOut);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn observing_never_propagates_a_failure(db: Db) {
        // The documented trade-off, asserted: an audit problem must not be
        // able to stop a login.
        let user = fixture(&db).await;
        sqlx::query("DROP TABLE audit_events")
            .execute(&db)
            .await
            .unwrap();

        // Returns, rather than panicking or erroring.
        observe(
            &db,
            Entry::success(Action::LoginSucceeded).in_realm(user.realm_id),
        )
        .await;
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn detail_is_stored_and_a_non_object_is_dropped(db: Db) {
        let user = fixture(&db).await;

        record(
            &db,
            Entry::success(Action::ClientSecretRotated)
                .in_realm(user.realm_id)
                .detail(serde_json::json!({ "client_id": "console" })),
        )
        .await
        .unwrap();

        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT detail FROM audit_events LIMIT 1")
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(stored["client_id"], "console");

        // The column is queried with object operators, so a bare scalar would
        // make those error rather than simply miss.
        let entry = Entry::success(Action::LoginSucceeded).detail(serde_json::json!("nope"));
        assert!(entry.detail.is_object());
    }

    #[test]
    fn the_builder_starts_empty_and_only_sets_what_it_is_told() {
        let entry = Entry::failure(Action::LoginFailed);
        assert_eq!(entry.outcome, Outcome::Failure);
        assert!(entry.realm_id.is_none());
        assert!(entry.actor_id.is_none());
        assert!(entry.actor_name.is_none());
        assert!(entry.target.is_none());
        assert!(entry.detail.is_object());
    }
}
