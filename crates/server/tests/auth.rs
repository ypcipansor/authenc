//! End-to-end authentication over HTTP.
//!
//! These drive the assembled router — server functions, cookies, middleware —
//! rather than calling the use case directly, because the properties that
//! matter here (what is in the `Set-Cookie` header, what a browser can read)
//! only exist at that level.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here. `unwrap` in a
// test is an assertion, which is exactly what we want it to be.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_identity::{
    Db, PasswordHasher, realm,
    user::{self, NewUser},
};
use axum::http::{StatusCode, header::SET_COOKIE};
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

/// A password that will not match any account, generated at runtime.
fn wrong_password() -> String {
    let mut p = password().to_owned();
    p.push_str("-wrong");
    p
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
    // Keep cookies between requests, the way a browser does.
    server.save_cookies();
    server
}

async fn seed(db: &Db) {
    let hasher = PasswordHasher::new();
    let realm = realm::create(db, "master", "Master").await.unwrap();
    user::create(
        db,
        &hasher,
        NewUser {
            realm_id: realm.id,
            username: "alice",
            email: "alice@example.com",
            password: password(),
            first_name: None,
            last_name: None,
        },
    )
    .await
    .unwrap();
}

fn login_body(identifier: &str, password: &str) -> serde_json::Value {
    json!({ "request": { "realm": "master", "identifier": identifier, "password": password } })
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_correct_login_sets_an_http_only_session_cookie(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await;

    response.assert_status_ok();

    let set_cookie = response.header("set-cookie");
    let set_cookie = set_cookie.to_str().unwrap();

    // The three properties that make the session unreachable from page script
    // and unusable cross-site.
    assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "got: {set_cookie}");
    assert!(set_cookie.contains("Path=/"), "got: {set_cookie}");
    assert!(
        set_cookie.starts_with("authenc_session="),
        "got: {set_cookie}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_login_response_body_carries_no_credential(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await;

    let body = response.text();
    for forbidden in ["password", "phc", "argon2", "token", "hash"] {
        assert!(
            !body.to_lowercase().contains(forbidden),
            "{forbidden} appeared in the login response: {body}",
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_session_cookie_identifies_the_user_on_the_next_request(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    // `save_cookies` replays the session cookie, as a browser would.
    let me = server.post("/api/sfn/me").await;
    me.assert_status_ok();
    assert!(me.text().contains("alice"), "got: {}", me.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn nobody_is_signed_in_without_a_cookie(db: PgPool) {
    seed(&db).await;

    let response = server(db).post("/api/sfn/me").await;

    response.assert_status_ok();
    assert!(
        !response.text().contains("alice"),
        "an anonymous request must not resolve to a user",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn logging_out_clears_the_cookie_and_the_session(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let logout = server.post("/api/sfn/logout").await;
    logout.assert_status_ok();

    let set_cookie = logout.header("set-cookie");
    let set_cookie = set_cookie.to_str().unwrap();
    assert!(
        set_cookie.contains("Max-Age=0"),
        "the cookie must be expired, got: {set_cookie}",
    );

    // And the server side must be gone too — clearing only the cookie would
    // leave a working session for anyone who captured the value.
    assert!(!server.post("/api/sfn/me").await.text().contains("alice"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_password_is_rejected_without_a_cookie(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", &wrong_password()))
        .await;

    // 401 specifically: asserting merely "not 200" would also pass on a 500
    // from a malformed request, which is how this test first passed while the
    // login endpoint was in fact rejecting its own argument encoding.
    response.assert_status(StatusCode::UNAUTHORIZED);
    assert!(
        response.maybe_header("set-cookie").is_none(),
        "a failed login must not establish a session",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_login_does_not_reveal_whether_the_account_exists(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    let wrong_password = server
        .post("/api/sfn/login")
        .json(&login_body("alice", &wrong_password()))
        .await;
    let unknown_user = server
        .post("/api/sfn/login")
        .json(&login_body("nobody", password()))
        .await;

    assert_eq!(wrong_password.status_code(), unknown_user.status_code());
    assert_eq!(wrong_password.text(), unknown_user.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn repeated_failures_are_rate_limited_over_http(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    for _ in 0..authenc_identity::login::MAX_ATTEMPTS_PER_IDENTIFIER {
        server
            .post("/api/sfn/login")
            .json(&login_body("alice", &wrong_password()))
            .await;
    }

    // Even the correct password must now be refused.
    let response = server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response.maybe_header("set-cookie").is_none(),
        "a locked-out attempt must not establish a session",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_login_page_renders_server_side(db: PgPool) {
    seed(&db).await;

    let response = server(db).get("/login").await;

    response.assert_status_ok();
    let html = response.text();
    // Server-rendered, not an empty shell waiting for JavaScript — which is
    // exactly what the previous deployment served.
    assert!(html.contains("Sign in"), "got: {html}");
    assert!(
        html.contains("autocomplete=\"current-password\""),
        "got: {html}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_password_reset_request_looks_the_same_for_unknown_addresses(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    let known = server
        .post("/api/sfn/password-reset")
        .json(&json!({ "realm": "master", "email": "alice@example.com" }))
        .await;
    let unknown = server
        .post("/api/sfn/password-reset")
        .json(&json!({ "realm": "master", "email": "nobody@example.com" }))
        .await;
    let unknown_realm = server
        .post("/api/sfn/password-reset")
        .json(&json!({ "realm": "no-such-realm", "email": "alice@example.com" }))
        .await;

    // Identical responses: this endpoint must not be an account oracle.
    known.assert_status_ok();
    assert_eq!(unknown.status_code(), known.status_code());
    assert_eq!(unknown.text(), known.text());
    assert_eq!(unknown_realm.status_code(), known.status_code());
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_reset_token_is_refused_over_http(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/password-reset-complete")
        .json(&json!({ "token": "not-a-real-token", "new_password": "a brand new passphrase" }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_verification_token_is_refused_over_http(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/verify-email")
        .json(&json!({ "token": "not-a-real-token" }))
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_recovery_pages_render_server_side(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    for (path, expected) in [
        ("/forgot-password", "Reset your password"),
        ("/reset-password?token=abc", "Choose a new password"),
        ("/verify-email?token=abc", "Confirm your email"),
    ] {
        let response = server.get(path).await;
        response.assert_status_ok();
        assert!(
            response.text().contains(expected),
            "{path}: {}",
            response.text()
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_reset_link_without_a_token_says_so_rather_than_failing_silently(db: PgPool) {
    seed(&db).await;

    // The previous console read the token with `use_params` on a route with no
    // path segment, so it was always absent and the page simply did nothing.
    let response = server(db).get("/reset-password").await;

    response.assert_status_ok();
    assert!(
        response.text().contains("missing its token"),
        "got: {}",
        response.text(),
    );
}

// ---------------------------------------------------------------------------
// Second factors
// ---------------------------------------------------------------------------
//
// The domain tests in `authenc-identity` prove the rules. These prove the rules
// are what the HTTP surface actually applies — a rule that exists but is not
// reachable through the endpoints is a rule that does not run.

/// Enrol a confirmed authenticator for `alice`, returning its secret.
///
/// Goes through the database rather than the endpoints, because the point of
/// these tests is the *login* path; enrolment over HTTP is covered separately.
async fn enrol_authenticator(db: &Db) -> authenc_identity::mfa::totp::Secret {
    use authenc_identity::mfa::totp;

    let config = authenc_server::config::Config::default();
    let master = config.master_key().unwrap();
    let realm = realm::by_name(db, "master").await.unwrap();
    let alice = user::id_by_email(db, realm.id, "alice@example.com")
        .await
        .unwrap()
        .unwrap();

    let enrolling = totp::begin_enrolment(db, &master, alice, "Phone")
        .await
        .unwrap();
    let secret = enrolling.secret.clone();

    // The previous step's code: confirming spends whichever step it matches,
    // and these tests need the current one still unspent.
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let code = totp::code_at(secret.as_bytes(), totp::step_at(now) - 1, totp::DIGITS);
    assert!(totp::confirm(db, &master, alice, &code).await.unwrap());

    secret
}

fn current_code(secret: &authenc_identity::mfa::totp::Secret) -> String {
    use authenc_identity::mfa::totp;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    totp::code_at(secret.as_bytes(), totp::step_at(now), totp::DIGITS)
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_password_alone_sets_no_session_cookie_when_a_factor_is_enrolled(db: PgPool) {
    // The property the whole design exists for, asserted where a browser would
    // see it: the response to a correct password carries no session.
    seed(&db).await;
    enrol_authenticator(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "second_factor_required", "{body}");
    assert_eq!(body["totp"], true);

    let cookies = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !cookies.contains("authenc_session="),
        "a session cookie was set before the second factor: {cookies}",
    );
    assert!(
        cookies.contains("authenc_mfa="),
        "the challenge cookie is missing: {cookies}",
    );
    assert!(cookies.contains("HttpOnly"), "{cookies}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_session_endpoint_reports_nobody_until_the_second_factor(db: PgPool) {
    // Not just "no cookie was set" — nothing the server hands back may resolve
    // to a signed-in user.
    seed(&db).await;
    enrol_authenticator(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    // The challenge cookie is now in the jar and travels with this request.
    let me = server.post("/api/sfn/me").await;
    me.assert_status_ok();
    assert_eq!(me.json::<serde_json::Value>(), serde_json::Value::Null);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_correct_code_finishes_the_login_over_http(db: PgPool) {
    seed(&db).await;
    let secret = enrol_authenticator(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let response = server
        .post("/api/sfn/mfa/verify")
        .json(&json!({ "factor": { "kind": "totp", "code": current_code(&secret) } }))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["user"]["username"], "alice", "{body}");

    // And the session is now real.
    let me = server.post("/api/sfn/me").await;
    me.assert_status_ok();
    assert_eq!(me.json::<serde_json::Value>()["user"]["username"], "alice");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_code_does_not_finish_the_login(db: PgPool) {
    seed(&db).await;
    enrol_authenticator(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let response = server
        .post("/api/sfn/mfa/verify")
        .json(&json!({ "factor": { "kind": "totp", "code": "000000" } }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        server.post("/api/sfn/me").await.json::<serde_json::Value>(),
        serde_json::Value::Null,
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_second_step_cannot_be_taken_without_a_first(db: PgPool) {
    // No challenge cookie, no login — even with a code that is arithmetically
    // correct for somebody.
    seed(&db).await;
    let secret = enrol_authenticator(&db).await;

    let response = server(db)
        .post("/api/sfn/mfa/verify")
        .json(&json!({ "factor": { "kind": "totp", "code": current_code(&secret) } }))
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_login_with_no_second_factor_still_signs_in(db: PgPool) {
    // The change must not have broken the ordinary path.
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await;

    response.assert_status_ok();
    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "complete", "{body}");
    assert_eq!(body["user"]["username"], "alice");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_recovery_code_finishes_the_login_and_is_then_spent(db: PgPool) {
    use authenc_identity::mfa::recovery;

    seed(&db).await;
    enrol_authenticator(&db).await;

    let realm = realm::by_name(&db, "master").await.unwrap();
    let alice = user::id_by_email(&db, realm.id, "alice@example.com")
        .await
        .unwrap()
        .unwrap();
    let codes = recovery::generate(&db, alice).await.unwrap();
    let code = codes.expose()[0].clone();

    let server = server(db);
    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    server
        .post("/api/sfn/mfa/verify")
        .json(&json!({ "factor": { "kind": "recovery_code", "code": code } }))
        .await
        .assert_status_ok();

    // Sign out, then try the same code again.
    server.post("/api/sfn/logout").await.assert_status_ok();
    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let replayed = server
        .post("/api/sfn/mfa/verify")
        .json(&json!({ "factor": { "kind": "recovery_code", "code": code } }))
        .await;

    assert_eq!(replayed.status_code(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn managing_your_own_factors_needs_a_session(db: PgPool) {
    // Every one of these acts on the caller's account, so an anonymous caller
    // has no account for them to act on.
    seed(&db).await;
    let server = server(db);

    for endpoint in [
        "/api/sfn/mfa/status",
        "/api/sfn/mfa/totp/disable",
        "/api/sfn/mfa/recovery/regenerate",
        "/api/sfn/mfa/passkey/register/begin",
    ] {
        let response = server.post(endpoint).await;
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "{endpoint} answered an anonymous caller: {}",
            response.text(),
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn enrolling_an_authenticator_over_http_issues_recovery_codes(db: PgPool) {
    use authenc_identity::mfa::totp;

    seed(&db).await;
    let server = server(db.clone());

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let begun = server
        .post("/api/sfn/mfa/totp/begin")
        .json(&json!({ "label": "Phone" }))
        .await;
    begun.assert_status_ok();

    let body: serde_json::Value = begun.json();
    let secret = body["secret"].as_str().unwrap().to_owned();
    assert!(
        body["provisioning_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/"),
        "{body}",
    );

    // Reconstruct the authenticator from what the page was shown, which is the
    // only thing a real user has.
    let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let code = totp::code_at(&raw, totp::step_at(now), totp::DIGITS);

    let confirmed = server
        .post("/api/sfn/mfa/totp/confirm")
        .json(&json!({ "code": code }))
        .await;
    confirmed.assert_status_ok();

    let codes: Vec<String> = confirmed.json();
    assert_eq!(
        codes.len(),
        authenc_identity::mfa::recovery::COUNT,
        "turning on a second factor must hand over a way past it",
    );

    let status = server.post("/api/sfn/mfa/status").await;
    status.assert_status_ok();
    let status: serde_json::Value = status.json();
    assert_eq!(status["totp"], true);
    assert_eq!(status["enforced"], true);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_security_page_redirects_an_anonymous_visitor_to_login(db: PgPool) {
    // Written after finding the opposite. The page first guarded itself on
    // `mfa_status`, which refuses an anonymous caller with 401 — and by the
    // time that answer arrived the response status was already set, so
    // `leptos_axum::redirect` could not override it and the visitor got a bare
    // 401 with no page at all. The guard is now `current_user`, which answers
    // `Ok(None)` rather than failing, leaving the redirect free to be the
    // response.
    seed(&db).await;

    let response = server(db).get("/security").await;

    assert_eq!(
        response.header("location"),
        "/login",
        "an unauthenticated visitor must be sent to the login page",
    );
    assert!(
        !response.text().contains("Recovery codes"),
        "no security markup may reach an anonymous visitor",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_security_page_renders_server_side_for_a_signed_in_user(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let html = server.get("/security").await.text();
    for expected in [
        "Two-step verification",
        "Authenticator app",
        "Recovery codes",
        "Passkeys",
    ] {
        assert!(
            html.contains(expected),
            "{expected} is missing from the page"
        );
    }
}

// ---------------------------------------------------------------------------
// Cross-origin server-function calls
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_cross_site_server_function_call_is_refused(db: PgPool) {
    // Found by driving a release build with curl: `/api/sfn` had no CSRF gate
    // at all. `is_same_origin` existed and was unit-tested, and nothing called
    // it — the same shape of defect as the six middleware modules the previous
    // tree wrote and never mounted.
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let refused = server
        .post("/api/sfn/logout")
        .add_header("sec-fetch-site", "cross-site")
        .await;

    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );

    // And the session it tried to end is still live.
    server.post("/api/sfn/me").await.assert_status_ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_forged_origin_header_is_refused_too(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    let refused = server
        .post("/api/sfn/logout")
        .add_header("origin", "https://evil.example")
        .await;

    assert_eq!(
        refused.status_code(),
        StatusCode::FORBIDDEN,
        "{}",
        refused.text()
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_console_s_own_calls_are_not_refused(db: PgPool) {
    // The guard must not break the thing it protects. The console posts from
    // the page it was served by, so the browser sends `same-origin`.
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .add_header("sec-fetch-site", "same-origin")
        .json(&login_body("alice", password()))
        .await
        .assert_status_ok();

    server
        .post("/api/sfn/logout")
        .add_header("sec-fetch-site", "same-origin")
        .await
        .assert_status_ok();
}
