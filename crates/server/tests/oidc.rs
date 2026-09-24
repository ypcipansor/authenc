//! The OAuth 2.0 and OpenID Connect endpoints, over HTTP.
//!
//! The unit tests in `authenc-oauth` prove the rules. These prove that the
//! rules are actually *reachable through the router* — which is the half the
//! previous build got wrong. Its correct OIDC implementation was dead code;
//! the one that was mounted issued a signed token for `demo_user` to anyone
//! who asked.
//!
//! The centrepiece is `a_public_client_completes_the_whole_code_flow`, which
//! drives a full authorization-code + PKCE exchange the way a real client
//! would: discovery, authorize, redeem, call UserInfo, refresh, and rotate.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_identity::{
    Db, PasswordHasher, realm,
    user::{self, NewUser},
};
use authenc_oauth::client::{self, NewClient};
use axum::http::StatusCode;
use axum_test::TestServer;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use leptos::prelude::LeptosOptions;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

const REDIRECT_URI: &str = "https://app.example.com/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

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
fn challenge() -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(VERIFIER.as_bytes()))
}

/// `Authorization: Basic` uses **standard** base64 over `id:secret`, not the
/// URL-safe alphabet the rest of this protocol uses.
fn basic(client_id: &str, secret: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}")),
    )
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
    // Redirects are not followed: they *are* the protocol's answer here, and
    // following them would hide exactly what these tests check.
    server
}

/// A realm, a user, and one registered client.
struct Fixture {
    /// The generated client secret, for confidential clients.
    secret: Option<String>,
}

async fn seed(db: &Db, client_id: &str, is_public: bool) -> Fixture {
    let hasher = PasswordHasher::new();
    let realm = match realm::by_name(db, "master").await {
        Ok(existing) => existing,
        Err(_) => realm::create(db, "master", "Master").await.unwrap(),
    };

    if user::id_by_email(db, realm.id, "ada@example.com")
        .await
        .unwrap()
        .is_none()
    {
        user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "ada",
                email: "ada@example.com",
                password: password(),
                first_name: Some("Ada"),
                last_name: Some("Lovelace"),
            },
        )
        .await
        .unwrap();
    }

    let scopes: Vec<String> = ["openid", "profile", "email", "offline_access"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let uris = vec![REDIRECT_URI.to_owned()];

    let registered = client::register(
        db,
        &hasher,
        NewClient {
            realm_id: realm.id,
            client_id: Some(client_id),
            name: "Example App",
            is_public,
            redirect_uris: &uris,
            grant_types: &[],
            scopes: &scopes,
            // Consent is exercised on its own below; most tests want the
            // straight path.
            require_consent: false,
        },
    )
    .await
    .unwrap();

    Fixture {
        secret: registered
            .client_secret
            .map(|secret| secret.expose().to_owned()),
    }
}

/// Sign in so the authorization endpoint has a user to authorise for.
async fn sign_in(server: &TestServer) {
    server
        .post("/api/sfn/login")
        .json(&json!({
            "request": { "realm": "master", "identifier": "ada", "password": password() }
        }))
        .expect_success()
        .await;
}

/// Drive `GET /auth` and return the `Location` it redirects to.
async fn authorize(server: &TestServer, query: &str) -> String {
    let response = server
        .get(&format!(
            "/realms/master/protocol/openid-connect/auth?{query}"
        ))
        .expect_failure()
        .await;

    assert_eq!(
        response.status_code(),
        StatusCode::SEE_OTHER,
        "expected a redirect, got: {}",
        response.text(),
    );

    response
        .headers()
        .get("location")
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_owned()
}

/// Pull one query parameter out of a redirect target.
fn param(location: &str, name: &str) -> Option<String> {
    let query = location.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| percent_decode(value))
    })
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn public_request() -> String {
    format!(
        "response_type=code&client_id=spa&redirect_uri={REDIRECT_URI}\
         &scope=openid+profile+email+offline_access&state=xyz\
         &nonce=n-0S6_WzA2Mj&code_challenge={}&code_challenge_method=S256",
        challenge(),
    )
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn discovery_is_served_at_the_path_the_specification_names(db: PgPool) {
    // The previous router registered `openid_configuration`, with an
    // underscore, which no conformant client ever looks for.
    seed(&db, "spa", true).await;
    let server = server(db);

    for path in [
        "/.well-known/openid-configuration",
        "/realms/master/.well-known/openid-configuration",
    ] {
        let response = server.get(path).await;
        response.assert_status_ok();

        let doc: serde_json::Value = response.json();
        assert_eq!(doc["issuer"], "http://localhost:3000/realms/master");
        assert_eq!(
            doc["authorization_endpoint"],
            "http://localhost:3000/realms/master/protocol/openid-connect/auth",
        );
        assert_eq!(doc["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(doc["response_types_supported"], json!(["code"]));
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_endpoint_discovery_advertises_actually_answers(db: PgPool) {
    // A discovery document that names a 404 is worse than none at all.
    seed(&db, "spa", true).await;
    let server = server(db);

    let doc: serde_json::Value = server
        .get("/realms/master/.well-known/openid-configuration")
        .await
        .json();

    // Establish what "not mounted" looks like, so the loop below is testing
    // something rather than asserting a tautology.
    let missing = server
        .post("/realms/master/protocol/openid-connect/no-such-endpoint")
        .expect_failure()
        .await;
    assert_eq!(
        missing.status_code(),
        StatusCode::NOT_FOUND,
        "an unmounted path must 404 for this check to mean anything",
    );

    for key in [
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "introspection_endpoint",
        "revocation_endpoint",
        "end_session_endpoint",
        "registration_endpoint",
    ] {
        let url = doc[key].as_str().unwrap_or_else(|| panic!("{key} missing"));
        let path = url.trim_start_matches("http://localhost:3000");

        // A 405 is fine — it means the path is mounted and this probe simply
        // used the wrong method. A 404 means discovery is advertising a lie.
        let response = server.post(path).expect_failure().await;
        assert_ne!(
            response.status_code(),
            StatusCode::NOT_FOUND,
            "{key} at {path} is advertised but not mounted",
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_key_set_is_published_and_holds_no_private_material(db: PgPool) {
    seed(&db, "spa", true).await;
    let response = server(db)
        .get("/realms/master/protocol/openid-connect/certs")
        .await;
    response.assert_status_ok();

    let doc: serde_json::Value = response.json();
    let keys = doc["keys"].as_array().expect("keys array");
    assert!(!keys.is_empty(), "a realm must publish a usable key");

    for key in keys {
        assert_eq!(key["kty"], "OKP");
        assert_eq!(key["alg"], "EdDSA");
        assert!(key.get("d").is_none(), "a private key reached JWKS: {key}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_realm_is_a_404_not_an_advertisement(db: PgPool) {
    seed(&db, "spa", true).await;
    server(db)
        .get("/realms/nowhere/.well-known/openid-configuration")
        .expect_failure()
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// The authorization-code flow, end to end
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_public_client_completes_the_whole_code_flow(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    // 1. Authorize. The browser comes back with a code and the state it sent.
    let location = authorize(&server, &public_request()).await;
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert_eq!(param(&location, "state").as_deref(), Some("xyz"));
    let code = param(&location, "code").expect("a code");

    // 2. Redeem it, with the PKCE verifier.
    let response = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
            "code_verifier": VERIFIER,
        }))
        .await;
    response.assert_status_ok();

    // A token response must never be cached: it is a credential.
    assert!(
        response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store"),
    );

    let tokens: serde_json::Value = response.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "openid profile email offline_access");
    let access_token = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_owned();
    assert!(tokens["id_token"].is_string(), "openid was granted");

    // 3. The access token reads claims at UserInfo.
    let response = server
        .get("/realms/master/protocol/openid-connect/userinfo")
        .add_header("authorization", format!("Bearer {access_token}"))
        .await;
    response.assert_status_ok();

    let claims: serde_json::Value = response.json();
    assert_eq!(claims["preferred_username"], "ada");
    assert_eq!(claims["email"], "ada@example.com");

    // 4. The refresh token buys a new pair, and is itself replaced.
    let response = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "spa",
        }))
        .await;
    response.assert_status_ok();

    let refreshed: serde_json::Value = response.json();
    let rotated = refreshed["refresh_token"].as_str().unwrap();
    assert_ne!(rotated, refresh_token, "the token must rotate on use");
    assert!(refreshed["access_token"].is_string());
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_confidential_client_authenticates_with_its_secret(db: PgPool) {
    let fixture = seed(&db, "web", false).await;
    let secret = fixture.secret.expect("a confidential client has a secret");
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=web&redirect_uri={REDIRECT_URI}&scope=openid&state=s"
        ),
    )
    .await;
    let code = param(&location, "code").expect("a code");

    let response = server
        .post("/realms/master/protocol/openid-connect/token")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }))
        .await;
    response.assert_status_ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_confidential_client_cannot_redeem_without_its_secret(db: PgPool) {
    seed(&db, "web", false).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=web&redirect_uri={REDIRECT_URI}&scope=openid&state=s"
        ),
    )
    .await;
    let code = param(&location, "code").expect("a code");

    let response = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "web",
        }))
        .expect_failure()
        .await;

    // RFC 6749 §5.2 singles this out as 401, not 400.
    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "invalid_client"
    );
    assert!(response.headers().contains_key("www-authenticate"));
}

// ---------------------------------------------------------------------------
// The authorization endpoint's refusals
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn an_unregistered_redirect_uri_is_never_redirected_to(db: PgPool) {
    // This is the open redirect the previous authorize endpoint had: it sent
    // the browser to whatever `redirect_uri` the caller supplied.
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let response = server
        .get(
            "/realms/master/protocol/openid-connect/auth\
             ?response_type=code&client_id=spa&redirect_uri=https://evil.test/steal&scope=openid",
        )
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "invalid_redirect_uri",
    );
    assert!(
        response.headers().get("location").is_none(),
        "the browser must not be sent anywhere",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_client_is_reported_here_rather_than_redirected(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let response = server
        .get(&format!(
            "/realms/master/protocol/openid-connect/auth\
             ?response_type=code&client_id=ghost&redirect_uri={REDIRECT_URI}&scope=openid"
        ))
        .expect_failure()
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "invalid_client"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_public_client_without_pkce_is_refused(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    // Registered redirect URI, so this one *is* reported by redirecting.
    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=spa&redirect_uri={REDIRECT_URI}&scope=openid&state=s"
        ),
    )
    .await;

    assert!(location.starts_with(REDIRECT_URI));
    assert_eq!(
        param(&location, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(param(&location, "state").as_deref(), Some("s"));
    assert!(param(&location, "code").is_none(), "{location}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_scope_the_client_is_not_registered_for_is_refused(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=spa&redirect_uri={REDIRECT_URI}\
             &scope=openid+admin&state=s&code_challenge={}&code_challenge_method=S256",
            challenge(),
        ),
    )
    .await;

    assert_eq!(param(&location, "error").as_deref(), Some("invalid_scope"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_anonymous_visitor_is_sent_to_sign_in_and_brought_back(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);

    let location = authorize(&server, &public_request()).await;

    assert!(location.starts_with("/login?next="), "{location}");
    let next = param(&location, "next").expect("a next parameter");
    assert!(
        next.contains("/realms/master/protocol/openid-connect/auth"),
        "the interrupted request must be preserved: {next}",
    );
    assert!(next.contains("code_challenge"), "{next}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn prompt_none_never_shows_a_screen(db: PgPool) {
    // A silent-renewal request must fail loudly rather than pop a login form
    // inside a hidden iframe.
    seed(&db, "spa", true).await;
    let server = server(db);

    let location = authorize(&server, &format!("{}&prompt=none", public_request())).await;

    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert_eq!(param(&location, "error").as_deref(), Some("login_required"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn only_the_code_flow_is_offered(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=token&client_id=spa&redirect_uri={REDIRECT_URI}&scope=openid&state=s"
        ),
    )
    .await;

    assert_eq!(
        param(&location, "error").as_deref(),
        Some("unsupported_response_type"),
    );
}

// ---------------------------------------------------------------------------
// The token endpoint's refusals
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_code_cannot_be_redeemed_twice_and_the_replay_kills_its_tokens(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let body = json!({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": "spa",
        "code_verifier": VERIFIER,
    });

    let first: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&body)
        .await
        .json();
    let refresh_token = first["refresh_token"].as_str().unwrap().to_owned();

    // The replay itself fails …
    let replay = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&body)
        .expect_failure()
        .await;
    replay.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(replay.json::<serde_json::Value>()["error"], "invalid_grant");

    // … and so does everything the first redemption produced, because a code
    // presented twice means it leaked.
    server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "spa",
        }))
        .expect_failure()
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_code_is_useless_without_the_pkce_verifier(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let response = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
        }))
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "invalid_grant"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_pkce_verifier_is_refused(db: PgPool) {
    // The unit tests prove `Challenge::verify` rejects it; this proves the
    // token endpoint actually calls it.
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let response = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
            // Well-formed, right length, wrong value.
            "code_verifier": "Xy9tOEcJvVXBpN5hqLmZrTfKdWgQsAuIeYoP1234567",
        }))
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "invalid_grant"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_redirect_uri_that_merely_extends_a_registered_one_is_refused(db: PgPool) {
    // The shape that survives a prefix check and is still an attack: the
    // registered URI is a prefix of the hostile one.
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    for hostile in [
        "https://app.example.com/callback/../../evil",
        "https://app.example.com/callbackevil",
        "https://app.example.com/callback.evil.test",
    ] {
        let response = server
            .get(&format!(
                "/realms/master/protocol/openid-connect/auth\
                 ?response_type=code&client_id=spa&redirect_uri={hostile}&scope=openid"
            ))
            .expect_failure()
            .await;

        assert_eq!(
            response.status_code(),
            StatusCode::BAD_REQUEST,
            "accepted: {hostile}",
        );
        assert_eq!(
            response.json::<serde_json::Value>()["error"],
            "invalid_redirect_uri",
            "accepted: {hostile}",
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn reusing_a_rotated_refresh_token_revokes_the_whole_family(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let first: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
            "code_verifier": VERIFIER,
        }))
        .await
        .json();
    let original = first["refresh_token"].as_str().unwrap().to_owned();

    let rotated: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": original,
            "client_id": "spa",
        }))
        .await
        .json();
    let successor = rotated["refresh_token"].as_str().unwrap().to_owned();

    // Someone presents the spent token. Either it leaked or the client lost a
    // response; from here the two are indistinguishable, so both parties lose
    // access rather than one of them being an undetected thief.
    server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": original,
            "client_id": "spa",
        }))
        .expect_failure()
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": successor,
            "client_id": "spa",
        }))
        .expect_failure()
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unsupported_grant_type_says_so(db: PgPool) {
    seed(&db, "spa", true).await;
    let response = server(db)
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({ "grant_type": "password", "client_id": "spa" }))
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "unsupported_grant_type",
    );
}

// ---------------------------------------------------------------------------
// UserInfo, introspection, revocation
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn userinfo_refuses_anything_that_is_not_a_live_token(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);

    for header in [None, Some("Bearer not-a-token"), Some("Bearer ")] {
        let mut request = server
            .get("/realms/master/protocol/openid-connect/userinfo")
            .expect_failure();
        if let Some(value) = header {
            request = request.add_header("authorization", value);
        }

        let response = request.await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        assert!(
            response
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("invalid_token"),
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn introspection_needs_client_credentials_not_a_bearer_token(db: PgPool) {
    // The previous implementation gated introspection on a bearer JWT, so any
    // token the server had ever issued could inspect any other.
    let fixture = seed(&db, "web", false).await;
    let secret = fixture.secret.unwrap();
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=web&redirect_uri={REDIRECT_URI}\
             &scope=openid+offline_access&state=s"
        ),
    )
    .await;
    let code = param(&location, "code").expect("a code");

    let tokens: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }))
        .await
        .json();
    let access_token = tokens["access_token"].as_str().unwrap().to_owned();

    // Without client credentials: refused outright.
    server
        .post("/realms/master/protocol/openid-connect/token/introspect")
        .add_header("authorization", format!("Bearer {access_token}"))
        .form(&json!({ "token": access_token }))
        .expect_failure()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // With them: a real answer.
    let response = server
        .post("/realms/master/protocol/openid-connect/token/introspect")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({ "token": access_token }))
        .await;
    response.assert_status_ok();

    let doc: serde_json::Value = response.json();
    assert_eq!(doc["active"], true);
    assert_eq!(doc["client_id"], "web");
    assert_eq!(doc["token_type"], "Bearer");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_token_is_inactive_rather_than_an_error(db: PgPool) {
    // RFC 7662 §2.2. An error here would let a caller tell "does not exist"
    // apart from "not yours".
    let fixture = seed(&db, "web", false).await;
    let secret = fixture.secret.unwrap();

    let response = server(db)
        .post("/realms/master/protocol/openid-connect/token/introspect")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({ "token": "no-such-token" }))
        .await;

    response.assert_status_ok();
    assert_eq!(response.json::<serde_json::Value>()["active"], false);
}

#[sqlx::test(migrations = "../../migrations")]
async fn revocation_reports_success_even_for_a_token_it_never_had(db: PgPool) {
    // RFC 7009 §2.2, for the same reason.
    let fixture = seed(&db, "web", false).await;
    let secret = fixture.secret.unwrap();

    server(db)
        .post("/realms/master/protocol/openid-connect/revoke")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({ "token": "never-existed" }))
        .await
        .assert_status_ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_revoked_refresh_token_stops_working(db: PgPool) {
    let fixture = seed(&db, "web", false).await;
    let secret = fixture.secret.unwrap();
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=web&redirect_uri={REDIRECT_URI}\
             &scope=openid+offline_access&state=s"
        ),
    )
    .await;
    let code = param(&location, "code").expect("a code");

    let tokens: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        }))
        .await
        .json();
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_owned();

    server
        .post("/realms/master/protocol/openid-connect/revoke")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({ "token": refresh_token }))
        .await
        .assert_status_ok();

    server
        .post("/realms/master/protocol/openid-connect/token")
        .add_header("authorization", basic("web", &secret))
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }))
        .expect_failure()
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Consent and registration
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn a_client_that_requires_consent_stops_at_the_consent_screen(db: PgPool) {
    let hasher = PasswordHasher::new();
    seed(&db, "spa", true).await;
    let realm = realm::by_name(&db, "master").await.unwrap();
    let uris = vec![REDIRECT_URI.to_owned()];
    let scopes = vec!["openid".to_owned(), "email".to_owned()];
    client::register(
        &db,
        &hasher,
        NewClient {
            realm_id: realm.id,
            client_id: Some("asks"),
            name: "Asks First",
            is_public: true,
            redirect_uris: &uris,
            grant_types: &[],
            scopes: &scopes,
            require_consent: true,
        },
    )
    .await
    .unwrap();

    let server = server(db);
    sign_in(&server).await;

    let location = authorize(
        &server,
        &format!(
            "response_type=code&client_id=asks&redirect_uri={REDIRECT_URI}\
             &scope=openid+email&state=s&code_challenge={}&code_challenge_method=S256",
            challenge(),
        ),
    )
    .await;

    assert!(location.starts_with("/consent?"), "{location}");
    assert_eq!(param(&location, "realm").as_deref(), Some("master"));
    assert!(param(&location, "code").is_none(), "no code before consent");
}

#[sqlx::test(migrations = "../../migrations")]
async fn approving_at_the_consent_screen_completes_the_request(db: PgPool) {
    let hasher = PasswordHasher::new();
    seed(&db, "spa", true).await;
    let realm = realm::by_name(&db, "master").await.unwrap();
    let uris = vec![REDIRECT_URI.to_owned()];
    let scopes = vec!["openid".to_owned(), "email".to_owned()];
    client::register(
        &db,
        &hasher,
        NewClient {
            realm_id: realm.id,
            client_id: Some("asks"),
            name: "Asks First",
            is_public: true,
            redirect_uris: &uris,
            grant_types: &[],
            scopes: &scopes,
            require_consent: true,
        },
    )
    .await
    .unwrap();

    let server = server(db);
    sign_in(&server).await;

    let csrf = server.get("/api/v1/csrf").await;
    csrf.assert_status_ok();
    let csrf_token = csrf.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    // What the consent form posts back, with the parameters carried through.
    let approval = json!({
        "response_type": "code",
        "client_id": "asks",
        "redirect_uri": REDIRECT_URI,
        "scope": "openid email",
        "state": "s",
        "code_challenge": challenge(),
        "code_challenge_method": "S256",
        "csrf_token": csrf_token,
        "approve": "true",
    });

    let response = server
        .post("/realms/master/protocol/openid-connect/auth")
        .form(&approval)
        .expect_failure()
        .await;
    assert_eq!(response.status_code(), StatusCode::SEE_OTHER);

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(location.starts_with(REDIRECT_URI), "{location}");
    assert!(param(&location, "code").is_some(), "{location}");

    // And the approval is remembered: the next authorization goes straight
    // through instead of asking again.
    let again = authorize(
        &server,
        &format!(
            "response_type=code&client_id=asks&redirect_uri={REDIRECT_URI}\
             &scope=openid+email&state=s2&code_challenge={}&code_challenge_method=S256",
            challenge(),
        ),
    )
    .await;
    assert!(again.starts_with(REDIRECT_URI), "{again}");
    assert!(param(&again, "code").is_some(), "{again}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn declining_at_the_consent_screen_reports_access_denied(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let csrf_token = server.get("/api/v1/csrf").await.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let response = server
        .post("/realms/master/protocol/openid-connect/auth")
        .form(&json!({
            "response_type": "code",
            "client_id": "spa",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "s",
            "code_challenge": challenge(),
            "code_challenge_method": "S256",
            "csrf_token": csrf_token,
            "approve": "false",
        }))
        .expect_failure()
        .await;

    let location = response
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(param(&location, "error").as_deref(), Some("access_denied"));
    assert_eq!(param(&location, "state").as_deref(), Some("s"));
    assert!(param(&location, "code").is_none(), "{location}");
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_approval_without_the_session_csrf_token_is_refused(db: PgPool) {
    // Otherwise a page on another origin could approve scopes on the user's
    // behalf simply by submitting this form for them.
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let response = server
        .post("/realms/master/protocol/openid-connect/auth")
        .form(&json!({
            "response_type": "code",
            "client_id": "spa",
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "approve": "true",
            "code_challenge": challenge(),
            "code_challenge_method": "S256",
        }))
        .expect_failure()
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "invalid_request",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn dynamic_registration_is_off_unless_it_is_switched_on(db: PgPool) {
    // Open registration lets anyone create a client with a redirect URI they
    // control — a phishing page wearing the operator's own domain.
    seed(&db, "spa", true).await;

    let response = server(db)
        .post("/realms/master/protocol/openid-connect/register")
        .json(&json!({
            "client_name": "Anything",
            "redirect_uris": ["https://evil.test/callback"],
        }))
        .expect_failure()
        .await;

    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<serde_json::Value>()["error"],
        "access_denied"
    );
}

// ---------------------------------------------------------------------------
// Cross-cutting
// ---------------------------------------------------------------------------

#[sqlx::test(migrations = "../../migrations")]
async fn there_are_no_unauthenticated_test_endpoints(db: PgPool) {
    // The previous router mounted all of these, unauthenticated, with a
    // hardcoded user id. The last one returned a signed token for `demo_user`
    // to any caller at all.
    seed(&db, "spa", true).await;
    let server = server(db);

    for path in [
        "/oauth2/authorize/test",
        "/oauth2/token/test",
        "/oauth2/consent/test",
        "/api/v1/auth/test-login",
        "/oidc/token",
    ] {
        let response = server.post(path).expect_failure().await;
        assert_eq!(
            response.status_code(),
            StatusCode::NOT_FOUND,
            "{path} exists; it must not",
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_token_from_one_realm_does_not_work_in_another(db: PgPool) {
    seed(&db, "spa", true).await;
    realm::create(&db, "other", "Other").await.unwrap();

    let server = server(db);
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let tokens: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
            "code_verifier": VERIFIER,
        }))
        .await
        .json();
    let access_token = tokens["access_token"].as_str().unwrap().to_owned();

    // The issuer is per realm, so a token minted for `master` fails the
    // issuer check at `other` even though the signature is genuine.
    server
        .get("/realms/other/protocol/openid-connect/userinfo")
        .add_header("authorization", format!("Bearer {access_token}"))
        .expect_failure()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "../../migrations")]
async fn disabling_an_account_stops_its_live_access_token(db: PgPool) {
    seed(&db, "spa", true).await;
    let server = server(db.clone());
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let tokens: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
            "code_verifier": VERIFIER,
        }))
        .await
        .json();
    let access_token = tokens["access_token"].as_str().unwrap().to_owned();
    let refresh_token = tokens["refresh_token"].as_str().unwrap().to_owned();

    server
        .get("/realms/master/protocol/openid-connect/userinfo")
        .add_header("authorization", format!("Bearer {access_token}"))
        .await
        .assert_status_ok();

    sqlx::query!("UPDATE users SET enabled = FALSE WHERE username = 'ada'")
        .execute(&db)
        .await
        .unwrap();

    // A signed token stays cryptographically valid until it expires; the
    // account check is what makes disabling take effect now rather than in
    // fifteen minutes.
    server
        .get("/realms/master/protocol/openid-connect/userinfo")
        .add_header("authorization", format!("Bearer {access_token}"))
        .expect_failure()
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "spa",
        }))
        .expect_failure()
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

/// Decode a JWT's payload without verifying it.
///
/// Fine here and nowhere else: these tests already prove the signature is
/// checked, and what is being asserted is what the payload *says*.
fn payload_of(jwt: &str) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let payload = jwt.split('.').nth(1).expect("a JWT has three parts");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[sqlx::test(migrations = "../../migrations")]
async fn amr_survives_the_whole_flow_including_a_refresh(db: PgPool) {
    // The property `amr` exists for, asserted where a relying party sees it.
    // A password-only sign-in must say so, and must still say so on an ID
    // token minted from a refresh days later — the value travels with the code
    // and then with the refresh family rather than being recomputed, because
    // by then the session may be gone and the account's enrolment may differ.
    seed(&db, "spa", true).await;
    let server = server(db);
    sign_in(&server).await;

    let location = authorize(&server, &public_request()).await;
    let code = param(&location, "code").expect("a code");

    let tokens: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": "spa",
            "code_verifier": VERIFIER,
        }))
        .await
        .json();

    let id_token = tokens["id_token"].as_str().expect("an id token");
    assert_eq!(
        payload_of(id_token)["amr"],
        json!(["pwd"]),
        "the ID token must describe how the user actually signed in",
    );

    // The access token describes an authorisation, not an authentication.
    let access = payload_of(tokens["access_token"].as_str().unwrap());
    assert!(access.get("amr").is_none(), "{access}");

    // And it survives rotation.
    let refreshed: serde_json::Value = server
        .post("/realms/master/protocol/openid-connect/token")
        .form(&json!({
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"].as_str().unwrap(),
            "client_id": "spa",
        }))
        .await
        .json();

    let refreshed_id = refreshed["id_token"]
        .as_str()
        .expect("a refreshed id token");
    assert_eq!(
        payload_of(refreshed_id)["amr"],
        json!(["pwd"]),
        "a refreshed ID token must still describe the original sign-in",
    );
}
