//! The REST API over HTTP.
//!
//! What these prove is not "the handler works" but "the handler cannot be
//! reached without the right permission". That is the property the previous
//! design could not have: authorisation there was middleware matched on URL
//! prefixes, so a route mounted on the wrong router silently lost it.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_contract::Permission;
use authenc_identity::{
    Db, PasswordHasher, realm, role,
    user::{self, NewUser},
};
use axum::http::StatusCode;
use axum_test::TestServer;
use leptos::prelude::LeptosOptions;
use serde_json::json;
use sqlx::PgPool;

/// A password generated at runtime.
///
/// Tests are the one place a credential can be written down; generating it
/// instead keeps the fixture from looking like — or becoming — an embedded
/// secret. Stable for the process, so the same value is used to create an
/// account and to sign in as it.
fn password() -> &'static str {
    static P: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    P.get_or_init(|| uuid::Uuid::new_v4().to_string()).as_str()
}
fn server(db: Db) -> TestServer {
    let leptos_options = LeptosOptions::builder()
        .output_name("authenc")
        .site_root(std::sync::Arc::<str>::from("target/site"))
        .build();

    let config = authenc_server::config::Config::default();
    let state = authenc_server::state::AppState {
        master_key: std::sync::Arc::new(config.master_key().unwrap()),
        relying_party: std::sync::Arc::new(config.relying_party().unwrap()),
        config: std::sync::Arc::new(config),
        db,
        hasher: PasswordHasher::new(),
        mailer: std::sync::Arc::new(authenc_identity::mail::CapturingMailer::new()),
        leptos_options,
    };

    let mut server = TestServer::new(authenc_server::http::router(state));
    server.save_cookies();
    server
}

/// Create a realm, and a user holding exactly `permissions`.
async fn seed_with(db: &Db, username: &str, permissions: &[Permission]) {
    let hasher = PasswordHasher::new();
    let realm = match realm::by_name(db, "master").await {
        Ok(existing) => existing,
        Err(_) => realm::create(db, "master", "Master").await.unwrap(),
    };

    let user = user::create(
        db,
        &hasher,
        NewUser {
            realm_id: realm.id,
            username,
            email: &format!("{username}@example.com"),
            password: password(),
            first_name: None,
            last_name: None,
        },
    )
    .await
    .unwrap();

    if !permissions.is_empty() {
        let role = role::ensure(db, realm.id, username, None).await.unwrap();
        role::set_permissions(db, realm.id, role.id, permissions)
            .await
            .unwrap();
        role::grant(db, user.id, role.id).await.unwrap();
    }
}

/// Sign in and start sending the session's CSRF token, as a real client must.
async fn sign_in(server: &mut TestServer, username: &str) {
    server
        .post("/api/sfn/login")
        .json(&json!({
            "request": { "realm": "master", "identifier": username, "password": password() }
        }))
        .await
        .assert_status_ok();

    let csrf = server.get("/api/v1/csrf").await;
    csrf.assert_status_ok();
    let token = csrf.json::<serde_json::Value>()["token"]
        .as_str()
        .expect("a csrf token")
        .to_owned();

    server.add_header("x-csrf-token", token);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_api_is_closed_to_anonymous_callers(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let server = server(db);

    for path in [
        "/api/v1/whoami",
        "/api/v1/users",
        "/api/v1/roles",
        "/api/v1/realm",
        "/api/v1/clients",
    ] {
        server
            .get(path)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_openapi_document_is_public_and_describes_every_route(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;

    // Public on purpose: a client needs the schema before it has credentials,
    // and the schema reveals shape, not contents.
    let response = server(db).get("/api/v1/openapi.json").await;
    response.assert_status_ok();

    let doc: serde_json::Value = response.json();
    let paths = doc["paths"].as_object().expect("paths object");

    for expected in [
        "/api/v1/whoami",
        "/api/v1/users",
        "/api/v1/users/{user_id}",
        "/api/v1/roles",
        "/api/v1/realm",
        "/api/v1/clients",
        "/api/v1/clients/{client_id}",
        "/api/v1/clients/{client_id}/secret",
    ] {
        assert!(
            paths.contains_key(expected),
            "missing {expected} from {paths:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn whoami_reports_the_permissions_actually_held(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    let response = server.get("/api/v1/whoami").await;
    response.assert_status_ok();

    let body: serde_json::Value = response.json();
    assert_eq!(body["permissions"], json!(["user:read"]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_with_no_permissions_is_refused_everything(db: PgPool) {
    seed_with(&db, "nobody", &[]).await;
    let mut server = server(db);
    sign_in(&mut server, "nobody").await;

    // Authenticated but unauthorised: 403, not 401. Telling them to log in
    // again would be misleading.
    for path in ["/api/v1/users", "/api/v1/roles", "/api/v1/realm"] {
        server.get(path).await.assert_status(StatusCode::FORBIDDEN);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_permission_does_not_confer_write(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    server.get("/api/v1/users").await.assert_status_ok();

    server
        .post("/api/v1/users")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": password(),
        }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn user_permissions_do_not_confer_role_management(db: PgPool) {
    seed_with(&db, "usermgr", &[Permission::UserWrite]).await;
    let mut server = server(db);
    sign_in(&mut server, "usermgr").await;

    server
        .post("/api/v1/roles")
        .json(&json!({ "name": "auditor" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_administrator_can_run_the_full_user_lifecycle(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let created = server
        .post("/api/v1/users")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": password(),
            "first_name": "Carol",
        }))
        .await;
    created.assert_status(StatusCode::CREATED);
    let user_id = created.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = server.get("/api/v1/users").await;
    listed.assert_status_ok();
    assert_eq!(listed.json::<serde_json::Value>()["total"], 2);

    server
        .post(&format!("/api/v1/users/{user_id}/enabled"))
        .json(&json!({ "enabled": false }))
        .await
        .assert_status_ok();

    server
        .delete(&format!("/api/v1/users/{user_id}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(
        server
            .get("/api/v1/users")
            .await
            .json::<serde_json::Value>()["total"],
        1,
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_created_user_never_carries_a_credential_in_the_response(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let response = server
        .post("/api/v1/users")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": password(),
        }))
        .await;

    let body = response.text().to_lowercase();
    for forbidden in ["password", "phc", "argon2", "hash"] {
        assert!(!body.contains(forbidden), "{forbidden} leaked: {body}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn creating_a_user_with_a_weak_password_is_a_400(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let response = server
        .post("/api/v1/users")
        .json(&json!({ "username": "carol", "email": "carol@example.com", "password": "x" }))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.header("content-type"),
        "application/problem+json",
        "errors must be RFC 9457 problem documents",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_administrator_cannot_delete_their_own_account(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let me = server.get("/api/v1/whoami").await;
    me.assert_status_ok();

    let users = server
        .get("/api/v1/users")
        .await
        .json::<serde_json::Value>();
    let my_id = users["items"][0]["id"].as_str().unwrap().to_owned();

    server
        .delete(&format!("/api/v1/users/{my_id}"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn disabling_a_user_ends_their_session_over_http(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    seed_with(&db, "victim", &[]).await;

    let mut admin = server(db.clone());
    sign_in(&mut admin, "admin").await;

    let mut victim = server(db);
    sign_in(&mut victim, "victim").await;
    // `whoami` needs no permission — it only reports who you are — so a
    // session with none still answers 200 while it is alive.
    victim.get("/api/v1/whoami").await.assert_status_ok();

    let users = admin.get("/api/v1/users").await.json::<serde_json::Value>();
    let victim_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "victim")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    admin
        .post(&format!("/api/v1/users/{victim_id}/enabled"))
        .json(&json!({ "enabled": false }))
        .await
        .assert_status_ok();

    // 401 now, not 403: the session itself is gone.
    victim
        .get("/api/v1/whoami")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

// --- the admin console -----------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_console_redirects_an_anonymous_visitor_to_login(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;

    // The redirect happens on the server, before any console markup is
    // produced. The previous console decided this in the browser by reading
    // `localStorage`, so the page was delivered first and redirected after.
    let response = server(db).get("/admin/users").await;

    assert_eq!(
        response.header("location"),
        "/login",
        "an unauthenticated visitor must be sent to the login page",
    );
    assert!(
        !response.text().contains("Add a user"),
        "no console markup may reach an anonymous visitor",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_console_renders_the_user_table_server_side(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let response = server.get("/admin/users").await;
    response.assert_status_ok();

    let html = response.text();
    // Rendered by the server, not left for JavaScript to fill in.
    assert!(html.contains("Users"), "got: {html}");
    assert!(
        html.contains("admin@example.com"),
        "the row must be in the HTML"
    );
    assert!(html.contains("Add a user"), "an admin may create users");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_console_hides_actions_the_viewer_may_not_take(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    let response = server.get("/admin/users").await;
    response.assert_status_ok();

    let html = response.text();
    assert!(html.contains("reader@example.com"), "may read the list");
    assert!(
        !html.contains("Add a user"),
        "a read-only viewer must not be offered the create form",
    );
    assert!(
        !html.contains(">Delete<"),
        "a read-only viewer must not be offered destructive actions",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn hiding_an_action_is_a_hint_not_the_check(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    // The console hides the create form, but the server function is what
    // actually decides — calling it directly must still be refused.
    server
        .post("/api/sfn/users-create")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": password(),
        }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_console_shows_the_permissions_the_viewer_holds(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    let html = server.get("/admin").await.text();
    assert!(html.contains("user:read"), "got: {html}");
    assert!(
        !html.contains("role:write"),
        "must not claim what is not held"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_with_no_permissions_sees_the_console_but_no_data(db: PgPool) {
    seed_with(&db, "nobody", &[]).await;
    let mut server = server(db);
    sign_in(&mut server, "nobody").await;

    // Signed in, so not redirected — but every list is refused.
    let overview = server.get("/admin").await;
    overview.assert_status_ok();
    assert!(
        overview.text().contains("no permissions"),
        "{}",
        overview.text()
    );
}

// ---------------------------------------------------------------------------
// OAuth clients
// ---------------------------------------------------------------------------

/// Register a client through the API and return the response body.
async fn register(server: &TestServer, body: serde_json::Value) -> serde_json::Value {
    let response = server.post("/api/v1/clients").json(&body).await;
    response.assert_status(StatusCode::CREATED);
    response.json()
}

fn a_confidential_client() -> serde_json::Value {
    json!({
        "client_id": "console",
        "name": "Console",
        "redirect_uris": ["https://app.example.com/callback"],
        "scopes": ["openid", "profile"],
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn registering_a_client_returns_its_secret_exactly_once(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let created = register(&server, a_confidential_client()).await;
    let secret = created["client_secret"]
        .as_str()
        .expect("a confidential client is issued a secret")
        .to_owned();
    assert!(!secret.is_empty());
    assert_eq!(created["client"]["client_id"], "console");

    // Every later read of the same client is secret-free: only the hash is
    // stored, so there is nowhere to read it back from.
    let fetched: serde_json::Value = server.get("/api/v1/clients/console").await.json();
    assert!(fetched.get("client_secret").is_none(), "{fetched}");
    assert!(
        !serde_json::to_string(&fetched).unwrap().contains(&secret),
        "the secret must not reappear in any later response",
    );

    let listed: serde_json::Value = server.get("/api/v1/clients").await.json();
    assert!(!serde_json::to_string(&listed).unwrap().contains(&secret));
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_api_never_exposes_the_internal_row_id(db: PgPool) {
    // The database key and the realm id are ours; publishing either turns an
    // implementation detail into a compatibility obligation.
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;
    register(&server, a_confidential_client()).await;

    let fetched: serde_json::Value = server.get("/api/v1/clients/console").await.json();
    assert!(fetched.get("key").is_none(), "{fetched}");
    assert!(fetched.get("realm_id").is_none(), "{fetched}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_public_client_is_issued_no_secret(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let created = register(
        &server,
        json!({
            "client_id": "spa",
            "name": "SPA",
            "public": true,
            "redirect_uris": ["https://app.example.com/callback"],
        }),
    )
    .await;

    assert!(created["client_secret"].is_null(), "{created}");
    assert_eq!(created["client"]["is_public"], true);

    // And there is nothing to rotate.
    server
        .post("/api/v1/clients/spa/secret")
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn rotating_a_secret_returns_a_different_one(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let first = register(&server, a_confidential_client()).await["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = server.post("/api/v1/clients/console/secret").await;
    response.assert_status_ok();
    let second = response.json::<serde_json::Value>()["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();

    assert_ne!(first, second);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_redirect_uri_that_cannot_be_matched_is_refused(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    for bad in [
        "https://app.example.com/*",
        "/callback",
        "javascript:alert(1)",
    ] {
        server
            .post("/api/v1/clients")
            .json(&json!({
                "client_id": "bad",
                "name": "Bad",
                "redirect_uris": [bad],
            }))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn updating_replaces_the_redirect_uris(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;
    register(&server, a_confidential_client()).await;

    let response = server
        .patch("/api/v1/clients/console")
        .json(&json!({ "redirect_uris": ["https://new.example.com/callback"] }))
        .await;
    response.assert_status_ok();

    let updated: serde_json::Value = response.json();
    assert_eq!(
        updated["redirect_uris"],
        json!(["https://new.example.com/callback"]),
    );
    // Scopes were not named, so they are left alone.
    assert_eq!(updated["scopes"], json!(["openid", "profile"]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn managing_clients_requires_the_client_permissions(db: PgPool) {
    // The console hides these controls without the permission; this asserts
    // that hiding them is only a hint, and the server refuses regardless.
    seed_with(&db, "admin", Permission::ALL).await;
    seed_with(&db, "reader", &[Permission::ClientRead]).await;
    seed_with(&db, "nobody", &[]).await;

    let mut owner = server(db.clone());
    sign_in(&mut owner, "admin").await;
    register(&owner, a_confidential_client()).await;

    let mut reader = server(db.clone());
    sign_in(&mut reader, "reader").await;
    reader.get("/api/v1/clients").await.assert_status_ok();
    reader
        .post("/api/v1/clients")
        .json(&a_confidential_client())
        .await
        .assert_status(StatusCode::FORBIDDEN);
    reader
        .post("/api/v1/clients/console/secret")
        .await
        .assert_status(StatusCode::FORBIDDEN);
    reader
        .delete("/api/v1/clients/console")
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let mut nobody = server(db);
    sign_in(&mut nobody, "nobody").await;
    nobody
        .get("/api/v1/clients")
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn deleting_a_client_removes_it(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;
    register(&server, a_confidential_client()).await;

    server
        .delete("/api/v1/clients/console")
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .get("/api/v1/clients/console")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .delete("/api/v1/clients/console")
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_audit_page_needs_the_audit_permission(db: PgPool) {
    // The trail names every account in the realm and where each signed in
    // from. Being allowed to list users is not the same as being allowed to
    // read everyone's movements, and the console must apply the same rule the
    // server does.
    seed_with(
        &db,
        "operator",
        &[Permission::UserRead, Permission::RoleRead],
    )
    .await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let refused = server
        .post("/api/sfn/audit")
        .json(&serde_json::json!({
            "action_prefix": null, "outcome": null, "limit": 20, "offset": 0
        }))
        .await;

    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_auditor_reads_the_trail_and_sees_their_own_sign_in(db: PgPool) {
    seed_with(&db, "auditor", &[Permission::AuditRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "auditor").await;

    let response = server
        .post("/api/sfn/audit")
        .json(&serde_json::json!({
            "action_prefix": null, "outcome": null, "limit": 20, "offset": 0
        }))
        .await;

    response.assert_status_ok();
    let page: serde_json::Value = response.json();
    assert!(page["total"].as_i64().unwrap() >= 1, "{page}");
    // The stored name, matching what `/api/v1/audit` returns. There is one
    // spelling now; there used to be two.
    assert_eq!(page["events"][0]["action"], "login.succeeded", "{page}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_trail_filters_by_namespace(db: PgPool) {
    seed_with(&db, "auditor", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "auditor").await;

    let page: serde_json::Value = server
        .post("/api/sfn/audit")
        .json(&serde_json::json!({
            "action_prefix": "mfa.", "outcome": null, "limit": 20, "offset": 0
        }))
        .await
        .json();

    // The sign-in was password-only, so a second-factor filter matches nothing
    // — which is the interesting assertion: the filter narrows rather than
    // being ignored.
    assert_eq!(page["total"], 0, "{page}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_rest_audit_surface_is_filtered_and_bounded(db: PgPool) {
    seed_with(&db, "auditor", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "auditor").await;

    let page: serde_json::Value = server.get("/api/v1/audit").await.json();
    assert!(page["total"].as_i64().unwrap() >= 1, "{page}");

    // The rule the console uses is published rather than left to be
    // re-derived, so a consumer cannot reach a different answer from ours.
    assert_eq!(page["items"][0]["action"], "login.succeeded");
    assert_eq!(page["items"][0]["security_signal"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unparseable_audit_filter_is_refused_not_ignored(db: PgPool) {
    // A caller asking for `outcome=failed` and receiving every event would
    // draw exactly the wrong conclusion from the answer.
    seed_with(&db, "auditor", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "auditor").await;

    for query in [
        "outcome=failed",
        "action=login.maybe",
        "since=yesterday",
        "until=not-a-time",
    ] {
        let response = server.get(&format!("/api/v1/audit?{query}")).await;
        assert_eq!(
            response.status_code(),
            StatusCode::BAD_REQUEST,
            "{query} was accepted: {}",
            response.text(),
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_csv_export_neutralises_spreadsheet_formulas(db: PgPool) {
    // An audit log holds attacker-supplied strings — a user agent is whatever
    // the client sent — and the export exists to be opened in a spreadsheet.
    // A cell beginning `=` is a formula there.
    use authenc_contract::event::Action;
    use authenc_identity::{
        audit::{self, Entry},
        session::Origin,
    };

    seed_with(&db, "auditor", Permission::ALL).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    audit::record(
        &db,
        Entry::failure(Action::LoginFailed)
            .in_realm(realm.id)
            .from(Origin {
                user_agent: Some("=cmd|'/c calc'!A1"),
                ip_address: None,
            }),
    )
    .await
    .unwrap();

    let mut server = server(db);
    sign_in(&mut server, "auditor").await;

    let response = server.get("/api/v1/audit.csv").await;
    response.assert_status_ok();
    assert!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/csv"),
    );

    let csv = response.text();
    assert!(csv.starts_with("occurred_at,action,outcome"), "{csv}");
    assert!(
        csv.contains("\"'=cmd|'/c calc'!A1\""),
        "the formula was not neutralised: {csv}",
    );
    assert!(!csv.contains("\"=cmd"), "{csv}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_csv_export_needs_the_audit_permission(db: PgPool) {
    seed_with(&db, "operator", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    assert_eq!(
        server.get("/api/v1/audit.csv").await.status_code(),
        StatusCode::FORBIDDEN,
    );
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn the_group_tree_is_built_and_read_over_rest(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let eng: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": null, "name": "engineering" }))
        .await
        .json();
    assert_eq!(eng["path"], "/engineering");

    let back: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": eng["id"], "name": "backend" }))
        .await
        .json();
    assert_eq!(back["path"], "/engineering/backend");

    let tree: serde_json::Value = server.get("/api/v1/groups").await.json();
    let paths: Vec<_> = tree
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, vec!["/engineering", "/engineering/backend"]);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_cycle_is_refused_over_rest_rather_than_hanging_the_request(db: PgPool) {
    // The guard is a database trigger, and this asserts it reaches the caller
    // as a 400 rather than as a request that never returns.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let eng: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": null, "name": "engineering" }))
        .await
        .json();
    let back: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": eng["id"], "name": "backend" }))
        .await
        .json();

    let response = server
        .post(&format!(
            "/api/v1/groups/{}/parent",
            eng["id"].as_str().unwrap()
        ))
        .json(&json!({ "parent_id": back["id"] }))
        .await;

    assert_eq!(
        response.status_code(),
        StatusCode::BAD_REQUEST,
        "{}",
        response.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn group_membership_changes_what_a_user_may_do(db: PgPool) {
    // The end-to-end version of the property the whole feature exists for: a
    // role granted to an ancestor group reaches a member of its child, and
    // `/api/v1/whoami` — which resolves permissions per request — says so.
    seed_with(&db, "operator", Permission::ALL).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let hasher = PasswordHasher::new();
    let bob = user::create(
        &db,
        &hasher,
        NewUser {
            realm_id: realm.id,
            username: "bob",
            email: "bob@example.com",
            password: password(),
            first_name: None,
            last_name: None,
        },
    )
    .await
    .unwrap();

    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let eng: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": null, "name": "engineering" }))
        .await
        .json();
    let back: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": eng["id"], "name": "backend" }))
        .await
        .json();

    let role: serde_json::Value = server
        .post("/api/v1/roles")
        .json(&json!({ "name": "auditors", "description": null }))
        .await
        .json();
    server
        .put(&format!(
            "/api/v1/roles/{}/permissions",
            role["id"].as_str().unwrap()
        ))
        .json(&json!({ "permissions": ["audit:read"] }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Granted to the *parent*, membership of the *child*.
    server
        .post(&format!(
            "/api/v1/groups/{}/roles/{}",
            eng["id"].as_str().unwrap(),
            role["id"].as_str().unwrap()
        ))
        .await
        .assert_status(StatusCode::NO_CONTENT);
    server
        .post(&format!(
            "/api/v1/groups/{}/members/{}",
            back["id"].as_str().unwrap(),
            bob.id
        ))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Sign in as bob and ask what he holds.
    let mut bobs = server;
    bobs.clear_cookies();
    sign_in(&mut bobs, "bob").await;

    let me: serde_json::Value = bobs.get("/api/v1/whoami").await.json();
    let permissions = me["permissions"].as_array().unwrap();
    assert!(
        permissions.iter().any(|p| p == "audit:read"),
        "the ancestor's role must reach a member of the child: {me}",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn granting_a_role_to_a_group_needs_role_write_too(db: PgPool) {
    seed_with(&db, "operator", &[Permission::GroupWrite]).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let eng: serde_json::Value = server
        .post("/api/v1/groups")
        .json(&json!({ "parent_id": null, "name": "engineering" }))
        .await
        .json();

    let response = server
        .post(&format!(
            "/api/v1/groups/{}/roles/{}",
            eng["id"].as_str().unwrap(),
            uuid::Uuid::new_v4()
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_field_is_refused_rather_than_ignored(db: PgPool) {
    // Found the hard way: a request sending `permissions` to `POST /roles` —
    // a field that endpoint does not have — got a 201 and a role that could do
    // nothing. Serde ignores unknown fields by default, so the caller's
    // intent was dropped and the response said it had worked.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let response = server
        .post("/api/v1/roles")
        .json(&json!({ "name": "auditors", "permissions": ["audit:read"] }))
        .await;

    // 422, which is what axum returns for a body that parses as JSON but does
    // not match the type. The point is that it is refused at all.
    assert_eq!(
        response.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "an invented field must not be silently dropped: {}",
        response.text(),
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_role_can_be_given_permissions_over_rest(db: PgPool) {
    // Until this endpoint existed, `/api/v1` could create a role and never
    // empower it, so every role made through the API was inert.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let role: serde_json::Value = server
        .post("/api/v1/roles")
        .json(&json!({ "name": "auditors", "description": null }))
        .await
        .json();
    let id = role["id"].as_str().unwrap();

    server
        .put(&format!("/api/v1/roles/{id}/permissions"))
        .json(&json!({ "permissions": ["audit:read", "user:read"] }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // Replacement, not accumulation: the second call is the whole truth.
    server
        .put(&format!("/api/v1/roles/{id}/permissions"))
        .json(&json!({ "permissions": ["user:read"] }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let roles: serde_json::Value = server.get("/api/v1/roles").await.json();
    assert!(
        roles
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "auditors")
    );

    let unknown = server
        .put(&format!("/api/v1/roles/{id}/permissions"))
        .json(&json!({ "permissions": ["user:destroy"] }))
        .await;
    assert_eq!(unknown.status_code(), StatusCode::BAD_REQUEST);
    assert!(
        unknown.text().contains("user:destroy"),
        "the error must name the offending permission: {}",
        unknown.text(),
    );
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn suspending_an_organisation_stops_its_members_signing_in_over_http(db: PgPool) {
    // The end-to-end version of the property the feature exists for. A
    // suspension nothing enforces at the login endpoint is a boolean.
    seed_with(&db, "operator", Permission::ALL).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let bob = user::create(
        &db,
        &PasswordHasher::new(),
        NewUser {
            realm_id: realm.id,
            username: "bob",
            email: "bob@example.com",
            password: password(),
            first_name: None,
            last_name: None,
        },
    )
    .await
    .unwrap();

    // One server per identity. Reusing a single `TestServer` across sign-ins
    // carries the previous session's CSRF header into the next one, and the
    // resulting 403 looks exactly like a permission failure.
    let mut ops = server(db.clone());
    sign_in(&mut ops, "operator").await;

    let org: serde_json::Value = ops
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap().to_owned();

    ops.put(&format!("/api/v1/organizations/{id}/members/{}", bob.id))
        .json(&json!({ "role": "member" }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let login = json!({
        "request": { "realm": "master", "identifier": "bob", "password": password() }
    });

    server(db.clone())
        .post("/api/sfn/login")
        .json(&login)
        .await
        .assert_status_ok();

    ops.post(&format!("/api/v1/organizations/{id}/enabled"))
        .json(&json!({ "enabled": false }))
        .await
        .assert_status_ok();

    let refused = server(db.clone()).post("/api/sfn/login").json(&login).await;
    assert_eq!(
        refused.status_code(),
        StatusCode::UNAUTHORIZED,
        "a suspended organisation must stop its members signing in",
    );

    // And restoring it gives them back.
    ops.post(&format!("/api/v1/organizations/{id}/enabled"))
        .json(&json!({ "enabled": true }))
        .await
        .assert_status_ok();

    server(db)
        .post("/api/sfn/login")
        .json(&login)
        .await
        .assert_status_ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invitation_is_handed_over_once_and_never_listed(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let org: serde_json::Value = server
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap().to_owned();

    let invited: serde_json::Value = server
        .post(&format!("/api/v1/organizations/{id}/invitations"))
        .json(&json!({ "email": "bob@example.com", "role": "member" }))
        .await
        .json();

    let token = invited["token"]
        .as_str()
        .expect("the token, once")
        .to_owned();
    assert!(!token.is_empty());

    // And never again: a listing that could return one would let anyone who
    // may read it join as anyone who was invited.
    let listed = server
        .get(&format!("/api/v1/organizations/{id}/invitations"))
        .await
        .text();
    assert!(
        !listed.contains(&token),
        "the token was listed back: {listed}"
    );
    assert!(listed.contains("bob@example.com"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn organisation_endpoints_need_their_permission(db: PgPool) {
    seed_with(&db, "operator", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    assert_eq!(
        server.get("/api/v1/organizations").await.status_code(),
        StatusCode::FORBIDDEN,
    );
    assert_eq!(
        server
            .post("/api/v1/organizations")
            .json(&json!({ "slug": "widgets", "name": "Widgets" }))
            .await
            .status_code(),
        StatusCode::FORBIDDEN,
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_organisation_role_is_refused(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let org: serde_json::Value = server
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap();

    let refused = server
        .post(&format!("/api/v1/organizations/{id}/invitations"))
        .json(&json!({ "email": "bob@example.com", "role": "root" }))
        .await;

    assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
    assert!(refused.text().contains("root"), "{}", refused.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_last_owner_cannot_be_removed_over_http(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let owner = user::id_by_email(&db, realm.id, "operator@example.com")
        .await
        .unwrap()
        .unwrap();

    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let org: serde_json::Value = server
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap();

    server
        .put(&format!("/api/v1/organizations/{id}/members/{owner}"))
        .json(&json!({ "role": "owner" }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let refused = server
        .delete(&format!("/api/v1/organizations/{id}/members/{owner}"))
        .await;
    assert_eq!(
        refused.status_code(),
        StatusCode::BAD_REQUEST,
        "{}",
        refused.text()
    );
}

// ---------------------------------------------------------------------------
// The console's own surface for groups and organisations
// ---------------------------------------------------------------------------
//
// Server functions and `/api/v1` are two thin surfaces over one use case, so
// what needs proving here is that they agree — particularly about refusal. A
// console that renders a page the REST API would refuse is a console that has
// its own, second access-control policy.

#[sqlx::test(migrations = "../../migrations")]
async fn the_group_page_needs_the_group_permission(db: PgPool) {
    seed_with(&db, "operator", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let refused = server.post("/api/sfn/groups").await;
    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_group_page_reports_depth_roles_and_membership(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let user_id = user::id_by_email(&db, realm.id, "operator@example.com")
        .await
        .unwrap()
        .unwrap();

    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let engineering: serde_json::Value = server
        .post("/api/sfn/groups/create")
        .json(&json!({ "parent_id": null, "name": "engineering" }))
        .await
        .json();
    let parent = engineering["id"].as_str().unwrap().to_owned();

    server
        .post("/api/sfn/groups/create")
        .json(&json!({ "parent_id": parent, "name": "backend" }))
        .await
        .assert_status_ok();

    // Grant a role to the parent and put a user in the child, so the page has
    // something to report in every column.
    let role: serde_json::Value = server
        .post("/api/v1/roles")
        .json(&json!({ "name": "deployer", "description": null }))
        .await
        .json();
    let role_id = role["id"].as_str().unwrap();
    server
        .post(&format!("/api/v1/groups/{parent}/roles/{role_id}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let groups: serde_json::Value = server.post("/api/sfn/groups").await.json();
    let child = groups[1]["id"].as_str().unwrap().to_owned();
    server
        .post(&format!("/api/v1/groups/{child}/members/{user_id}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let groups: serde_json::Value = server.post("/api/sfn/groups").await.json();

    // Ordered by path, so the parent comes first and indentation reproduces
    // the tree without the browser parsing anything.
    assert_eq!(groups[0]["path"], "/engineering", "{groups}");
    assert_eq!(groups[0]["depth"], 0, "{groups}");
    assert_eq!(groups[0]["roles"][0], "deployer", "{groups}");

    assert_eq!(groups[1]["path"], "/engineering/backend", "{groups}");
    assert_eq!(groups[1]["depth"], 1, "{groups}");
    assert_eq!(groups[1]["members"], 1, "{groups}");
    // Direct grants only: the child inherits the role for *authorisation*, but
    // reporting it as granted here would misrepresent what an administrator set.
    assert_eq!(groups[1]["roles"].as_array().unwrap().len(), 0, "{groups}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_console_and_the_rest_api_describe_the_same_group_tree(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    server
        .post("/api/sfn/groups/create")
        .json(&json!({ "parent_id": null, "name": "engineering" }))
        .await
        .assert_status_ok();

    let console: serde_json::Value = server.post("/api/sfn/groups").await.json();
    let rest: serde_json::Value = server.get("/api/v1/groups").await.json();

    assert_eq!(console[0]["id"], rest[0]["id"], "{console} vs {rest}");
    assert_eq!(console[0]["path"], rest[0]["path"], "{console} vs {rest}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_group_deleted_from_the_console_is_gone_from_the_api(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let created: serde_json::Value = server
        .post("/api/sfn/groups/create")
        .json(&json!({ "parent_id": null, "name": "temporary" }))
        .await
        .json();
    let id = created["id"].as_str().unwrap().to_owned();

    server
        .post("/api/sfn/groups/delete")
        .json(&json!({ "id": id }))
        .await
        .assert_status_ok();

    server
        .get(&format!("/api/v1/groups/{id}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_organisation_page_needs_the_organization_permission(db: PgPool) {
    seed_with(&db, "operator", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let refused = server.post("/api/sfn/organizations").await;
    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_organisation_page_counts_members_and_outstanding_invitations(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let user_id = user::id_by_email(&db, realm.id, "operator@example.com")
        .await
        .unwrap()
        .unwrap();

    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let created: serde_json::Value = server
        .post("/api/sfn/organizations/create")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = created["id"].as_str().unwrap().to_owned();

    server
        .put(&format!("/api/v1/organizations/{id}/members/{user_id}"))
        .json(&json!({ "role": "owner" }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .post(&format!("/api/v1/organizations/{id}/invitations"))
        .json(&json!({ "email": "new@example.com", "role": "member" }))
        .await
        .assert_status(StatusCode::CREATED);

    let page: serde_json::Value = server.post("/api/sfn/organizations").await.json();
    assert_eq!(page[0]["slug"], "widgets", "{page}");
    assert_eq!(page[0]["members"], 1, "{page}");
    assert_eq!(page[0]["pending_invitations"], 1, "{page}");
    assert_eq!(page[0]["enabled"], true, "{page}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn suspending_an_organisation_from_the_console_stops_its_members_signing_in(db: PgPool) {
    // The console's suspend button has to do the thing suspension means. A
    // page that flips a badge and nothing else is the failure this proves
    // against.
    seed_with(&db, "operator", Permission::ALL).await;
    seed_with(&db, "tenant", &[]).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let tenant_id = user::id_by_email(&db, realm.id, "tenant@example.com")
        .await
        .unwrap()
        .unwrap();

    let mut admin = server(db.clone());
    sign_in(&mut admin, "operator").await;

    let created: serde_json::Value = admin
        .post("/api/sfn/organizations/create")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = created["id"].as_str().unwrap().to_owned();

    admin
        .put(&format!("/api/v1/organizations/{id}/members/{tenant_id}"))
        .json(&json!({ "role": "member" }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let login = json!({
        "request": { "realm": "master", "identifier": "tenant", "password": password() }
    });

    // The credentials work before the suspension. Without this half, the
    // refusal below would be satisfied by a typo in the password.
    server(db.clone())
        .post("/api/sfn/login")
        .json(&login)
        .await
        .assert_status_ok();

    admin
        .post("/api/sfn/organizations/enabled")
        .json(&json!({ "id": id, "enabled": false }))
        .await
        .assert_status_ok();

    // A separate server from the administrator's: `clear_cookies()` leaves the
    // CSRF header in place, and a stale one produces a 403 that would look
    // like this refusal without being it.
    let refused = server(db).post("/api/sfn/login").json(&login).await;

    // 401, the same answer a wrong password gets. Suspension is checked after
    // the password precisely so the two are indistinguishable — reporting
    // "suspended" here would confirm the account exists to anyone guessing.
    assert_eq!(
        refused.status_code(),
        StatusCode::UNAUTHORIZED,
        "{}",
        refused.text()
    );
}

// ---------------------------------------------------------------------------
// Social-login providers over REST
// ---------------------------------------------------------------------------

/// The body every provider test starts from.
fn a_provider(alias: &str) -> serde_json::Value {
    json!({
        "alias": alias,
        "kind": "google",
        "display_name": "Google",
        "client_id": "our-client-id",
        "client_secret": "our-client-secret",
        "authorization_endpoint": "https://accounts.example/authorize",
        "token_endpoint": "https://accounts.example/token",
        "userinfo_endpoint": null,
        "issuer": "https://accounts.example",
        "scopes": ["openid", "email"],
    })
}

#[sqlx::test(migrations = "../../migrations")]
async fn configuring_a_provider_needs_its_own_permission(db: PgPool) {
    // Not folded into `realm:write`, deliberately: configuring a provider is
    // effectively the power to add a new way of becoming any user in the
    // realm, and it should be grantable on its own.
    seed_with(
        &db,
        "operator",
        &[Permission::RealmWrite, Permission::UserWrite],
    )
    .await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let refused = server
        .post("/api/v1/identity-providers")
        .json(&a_provider("google"))
        .await;

    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_client_secret_never_comes_back_out(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let created = server
        .post("/api/v1/identity-providers")
        .json(&a_provider("google"))
        .await;
    created.assert_status(StatusCode::CREATED);
    assert!(
        !created.text().contains("our-client-secret"),
        "the creation response carried the secret back: {}",
        created.text()
    );

    let id = created.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    for path in [
        "/api/v1/identity-providers".to_owned(),
        format!("/api/v1/identity-providers/{id}"),
    ] {
        let body = server.get(&path).await.text();
        assert!(
            !body.contains("our-client-secret"),
            "{path} carried the secret: {body}"
        );
        // The client id is public and is expected.
        assert!(body.contains("our-client-id"), "{path}: {body}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn account_adoption_is_off_unless_asked_for(db: PgPool) {
    // The default is the safe half of this feature. A body that does not
    // mention `link_by_verified_email` must not get it.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let created: serde_json::Value = server
        .post("/api/v1/identity-providers")
        .json(&a_provider("google"))
        .await
        .json();

    assert_eq!(created["link_by_verified_email"], false, "{created}");
    // Provisioning, which only ever creates a *new* account, defaults on.
    assert_eq!(created["allow_provisioning"], true, "{created}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_provider_kind_says_which_one(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let mut body = a_provider("okta");
    body["kind"] = json!("okta");

    let refused = server.post("/api/v1/identity-providers").json(&body).await;

    assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
    assert!(refused.text().contains("kind"), "{}", refused.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invented_field_is_refused_rather_than_ignored(db: PgPool) {
    // `deny_unknown_fields`, as everywhere. A caller who misspells
    // `link_by_verified_email` must not get a 201 and a provider that does not
    // do what they asked.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let mut body = a_provider("google");
    body["link_by_verified_emails"] = json!(true);

    let refused = server.post("/api/v1/identity-providers").json(&body).await;

    assert_eq!(
        refused.status_code(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_disabled_provider_disappears_from_the_login_page(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "operator").await;

    let created: serde_json::Value = server
        .post("/api/v1/identity-providers")
        .json(&a_provider("google"))
        .await
        .json();
    let id = created["id"].as_str().unwrap();

    let offered: serde_json::Value = server
        .post("/api/sfn/sign-in-providers")
        .json(&json!({ "realm": "master" }))
        .await
        .json();
    assert_eq!(offered.as_array().unwrap().len(), 1, "{offered}");

    server
        .post(&format!("/api/v1/identity-providers/{id}/enabled"))
        .json(&json!({ "enabled": false }))
        .await
        .assert_status_ok();

    let offered: serde_json::Value = server
        .post("/api/sfn/sign-in-providers")
        .json(&json!({ "realm": "master" }))
        .await
        .json();
    assert!(offered.as_array().unwrap().is_empty(), "{offered}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_login_page_does_not_reveal_which_realms_exist(db: PgPool) {
    // An unknown realm answers with an empty list, exactly as a realm with no
    // providers does. Anything else turns an unauthenticated endpoint into a
    // realm-enumeration oracle.
    seed_with(&db, "operator", Permission::ALL).await;
    let server = server(db);

    let response = server
        .post("/api/sfn/sign-in-providers")
        .json(&json!({ "realm": "no-such-realm" }))
        .await;

    response.assert_status_ok();
    assert!(
        response
            .json::<serde_json::Value>()
            .as_array()
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Machine-to-machine API tokens
// ---------------------------------------------------------------------------

/// A server that sends a bearer token and no cookies — an automated client.
fn machine(db: Db, secret: &str) -> TestServer {
    let leptos_options = LeptosOptions::builder()
        .output_name("authenc")
        .site_root(std::sync::Arc::<str>::from("target/site"))
        .build();

    let config = authenc_server::config::Config::default();
    let state = authenc_server::state::AppState {
        master_key: std::sync::Arc::new(config.master_key().unwrap()),
        relying_party: std::sync::Arc::new(config.relying_party().unwrap()),
        config: std::sync::Arc::new(config),
        db,
        hasher: PasswordHasher::new(),
        mailer: std::sync::Arc::new(authenc_identity::mail::CapturingMailer::new()),
        leptos_options,
    };

    let mut server = TestServer::new(authenc_server::http::router(state));
    server.add_header("authorization", format!("Bearer {secret}"));
    server
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_authenticates_the_api_without_a_cookie_or_a_csrf_header(db: PgPool) {
    // The gap this closes: `/api/v1` otherwise needs a session cookie and a
    // CSRF token, so a Terraform provider had to hold somebody's password.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut human = server(db.clone());
    sign_in(&mut human, "operator").await;

    let minted: serde_json::Value = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:read", "role:write"] }))
        .await
        .json();
    let secret = minted["secret"].as_str().unwrap();

    let robot = machine(db, secret);
    robot.get("/api/v1/users").await.assert_status_ok();

    // The state-changing half, and it has to *succeed*. Asserting a refusal
    // here would prove nothing: a missing CSRF header is also a 403, so the
    // test would pass whether or not the token path skips that check. A token
    // is attached deliberately by the client and never automatically by a
    // browser, so there is nothing for CSRF to protect against.
    robot
        .post("/api/v1/roles")
        .json(&json!({ "name": "from-a-token", "description": null }))
        .await
        .assert_status(StatusCode::CREATED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_is_narrowed_to_what_it_was_granted(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut human = server(db.clone());
    sign_in(&mut human, "operator").await;

    let minted: serde_json::Value = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:read"] }))
        .await
        .json();
    let secret = minted["secret"].as_str().unwrap();

    let robot = machine(db, secret);
    robot.get("/api/v1/users").await.assert_status_ok();
    // Its maker holds every permission. The token holds one.
    robot
        .get("/api/v1/clients")
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_cannot_be_minted_beyond_its_makers_authority(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut human = server(db);
    sign_in(&mut human, "reader").await;

    let refused = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:write"] }))
        .await;

    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn revoking_a_token_stops_it_immediately(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut human = server(db.clone());
    sign_in(&mut human, "operator").await;

    let minted: serde_json::Value = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:read"] }))
        .await
        .json();
    let secret = minted["secret"].as_str().unwrap().to_owned();
    let id = minted["id"].as_str().unwrap();

    let robot = machine(db.clone(), &secret);
    robot.get("/api/v1/users").await.assert_status_ok();

    human
        .delete(&format!("/api/v1/tokens/{id}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    machine(db, &secret)
        .get("/api/v1/users")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_secret_is_returned_once_and_never_listed(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut human = server(db);
    sign_in(&mut human, "operator").await;

    let created = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:read"] }))
        .await;
    created.assert_status(StatusCode::CREATED);

    let secret = created.json::<serde_json::Value>()["secret"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = human.get("/api/v1/tokens").await.text();
    assert!(!listed.contains(&secret), "the listing carried the secret");
    // The prefix is public and is how an operator identifies it.
    assert!(listed.contains("authenc_pat_"), "{listed}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_permission_name_says_which_one(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    let mut human = server(db);
    sign_in(&mut human, "operator").await;

    let refused = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:reed"] }))
        .await;

    assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
    assert!(refused.text().contains("user:reed"), "{}", refused.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_bearer_token_that_is_not_ours_is_refused(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;

    machine(db, "eyJhbGciOiJub25lIn0.e30.")
        .get("/api/v1/users")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn withdrawing_a_permission_from_a_role_narrows_its_tokens(db: PgPool) {
    // The property that makes offboarding work end to end, over HTTP: the
    // token's authority is the intersection with what the account holds *now*.
    seed_with(&db, "operator", Permission::ALL).await;
    let mut human = server(db.clone());
    sign_in(&mut human, "operator").await;

    let minted: serde_json::Value = human
        .post("/api/v1/tokens")
        .json(&json!({ "name": "ci", "permissions": ["user:read", "client:read"] }))
        .await
        .json();
    let secret = minted["secret"].as_str().unwrap().to_owned();

    machine(db.clone(), &secret)
        .get("/api/v1/clients")
        .await
        .assert_status_ok();

    // Narrow the operator's own role. `seed_with` named it after the user.
    let roles: serde_json::Value = human.get("/api/v1/roles").await.json();
    let role_id = roles
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["name"] == "operator")
        .expect("the seeded role")["id"]
        .as_str()
        .unwrap()
        .to_owned();

    human
        .put(&format!("/api/v1/roles/{role_id}/permissions"))
        .json(&json!({ "permissions": ["user:read"] }))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let robot = machine(db, &secret);
    robot.get("/api/v1/users").await.assert_status_ok();
    robot
        .get("/api/v1/clients")
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Joining an organisation
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn an_invitation_can_actually_be_accepted(db: PgPool) {
    // Found by auditing for public functions with no caller:
    // `accept_organization_invitation` existed, was tested, and had no HTTP
    // surface at all — so a link could be issued and never redeemed, while the
    // README implied otherwise.
    seed_with(&db, "operator", Permission::ALL).await;
    seed_with(&db, "newcomer", &[]).await;

    let mut admin = server(db.clone());
    sign_in(&mut admin, "operator").await;

    let org: serde_json::Value = admin
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap();

    let invited: serde_json::Value = admin
        .post(&format!("/api/v1/organizations/{id}/invitations"))
        .json(&json!({ "email": "newcomer@example.com", "role": "member" }))
        .await
        .json();
    let token = invited["token"].as_str().unwrap().to_owned();

    // The invited person, signed in as themselves.
    let mut newcomer = server(db.clone());
    sign_in(&mut newcomer, "newcomer").await;

    let joined = newcomer
        .post("/api/v1/invitations/accept")
        .json(&json!({ "token": token }))
        .await;
    joined.assert_status_ok();
    assert_eq!(joined.json::<serde_json::Value>()["slug"], "widgets");

    // And they are a member now, which is the part that matters.
    let members: serde_json::Value = admin
        .get(&format!("/api/v1/organizations/{id}/members"))
        .await
        .json();
    assert!(
        members
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["username"] == "newcomer"),
        "{members}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invitation_is_spent_by_the_first_person_to_accept_it(db: PgPool) {
    seed_with(&db, "operator", Permission::ALL).await;
    seed_with(&db, "first", &[]).await;
    seed_with(&db, "second", &[]).await;

    let mut admin = server(db.clone());
    sign_in(&mut admin, "operator").await;

    let org: serde_json::Value = admin
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap();

    let invited: serde_json::Value = admin
        .post(&format!("/api/v1/organizations/{id}/invitations"))
        .json(&json!({ "email": "first@example.com", "role": "member" }))
        .await
        .json();
    let token = invited["token"].as_str().unwrap().to_owned();

    let mut first = server(db.clone());
    sign_in(&mut first, "first").await;
    first
        .post("/api/v1/invitations/accept")
        .json(&json!({ "token": token }))
        .await
        .assert_status_ok();

    let mut second = server(db);
    sign_in(&mut second, "second").await;
    let refused = second
        .post("/api/v1/invitations/accept")
        .json(&json!({ "token": token }))
        .await;

    assert_eq!(
        refused.status_code(),
        StatusCode::UNAUTHORIZED,
        "one link admits one person: {}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn peeking_shows_what_is_being_joined_without_spending_the_link(db: PgPool) {
    // A signed-out visitor following a link needs to see what they are being
    // asked to join before being asked to sign in.
    seed_with(&db, "operator", Permission::ALL).await;
    seed_with(&db, "newcomer", &[]).await;

    let mut admin = server(db.clone());
    sign_in(&mut admin, "operator").await;

    let org: serde_json::Value = admin
        .post("/api/v1/organizations")
        .json(&json!({ "slug": "widgets", "name": "Widgets Inc" }))
        .await
        .json();
    let id = org["id"].as_str().unwrap();

    let invited: serde_json::Value = admin
        .post(&format!("/api/v1/organizations/{id}/invitations"))
        .json(&json!({ "email": "newcomer@example.com", "role": "member" }))
        .await
        .json();
    let token = invited["token"].as_str().unwrap().to_owned();

    // Unauthenticated, deliberately.
    let anonymous = server(db.clone());
    let preview = anonymous
        .post("/api/v1/invitations/peek")
        .json(&json!({ "token": token }))
        .await;
    preview.assert_status_ok();

    let preview: serde_json::Value = preview.json();
    assert_eq!(preview["organization"], "Widgets Inc");
    assert_eq!(preview["email"], "newcomer@example.com");
    assert_eq!(preview["role"], "member");

    // Peeking did not spend it.
    let mut newcomer = server(db);
    sign_in(&mut newcomer, "newcomer").await;
    newcomer
        .post("/api/v1/invitations/accept")
        .json(&json!({ "token": token }))
        .await
        .assert_status_ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_invented_invitation_token_is_a_404_not_a_hint(db: PgPool) {
    // Unknown, expired, and already-accepted are one answer, so the endpoint
    // cannot tell a spent link from an invented one.
    seed_with(&db, "operator", Permission::ALL).await;
    let anonymous = server(db);

    anonymous
        .post("/api/v1/invitations/peek")
        .json(&json!({ "token": "not-a-real-token" }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}
