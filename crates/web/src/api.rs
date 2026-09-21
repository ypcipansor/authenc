//! Server functions.
//!
//! A `#[server]` function is one function that the browser calls and the server
//! runs. There is no DTO written twice, no hand-maintained fetch wrapper, and
//! no route string to get wrong — the argument and return types *are* the
//! contract, checked by the compiler on both sides.
//!
//! The previous console needed 60 lines of `authenticated_request` plumbing to
//! do this by hand, and that wrapper silently rejected `PATCH`, so renaming a
//! passkey failed without ever reaching the network.

// Types that appear in a `#[server]` *signature* are needed by both halves;
// these are the ones only its body mentions, and the body compiles only under
// `ssr`.
use authenc_contract::model::{
    LoginOutcome, LoginRequest, LoginResponse, MfaStatus, PasskeySummary, SecondFactor,
    TotpEnrolment,
};
#[cfg(feature = "ssr")]
use authenc_contract::{AppError, model::SecondFactorPrompt};
use leptos::prelude::*;
use leptos::server_fn::codec::Json;

#[cfg(feature = "ssr")]
use crate::server_ctx::CookiePolicy;
use serde::{Deserialize, Serialize};

/// What the server reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    /// Version from `CARGO_PKG_VERSION` of the server binary.
    pub version: String,
    /// Whether the database answered.
    pub database_ready: bool,
}

/// Ask the server how it is doing.
///
/// Deliberately the first server function in the tree: it exercises the whole
/// path — browser call, wire format, server execution, database access, typed
/// response — so that if hydration or the server-function plumbing is broken,
/// the home page says so instead of failing silently.
#[server(name = GetServerStatus, prefix = "/api/sfn", endpoint = "status")]
pub async fn server_status() -> Result<ServerStatus, ServerFnError> {
    use authenc_identity::Db;

    let db = expect_context::<Db>();
    let database_ready = authenc_identity::ping(&db).await.is_ok();

    Ok(ServerStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        database_ready,
    })
}

/// Authenticate and open a session.
///
/// On success the server sets an `HttpOnly` session cookie; nothing secret is
/// returned in the body, and there is no token for page script to hold.
///
/// The `request` argument carries the submitted credentials.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = LogIn, prefix = "/api/sfn", endpoint = "login", input = Json)]
pub async fn log_in(request: LoginRequest) -> Result<LoginOutcome, ServerFnError> {
    use authenc_identity::{
        Db, PasswordHasher,
        login::{self, Attempt, Outcome},
        mfa::Factor,
        session::Origin,
    };

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    let user_agent = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok());

    let outcome = login::authenticate(
        &db,
        &hasher,
        Attempt {
            realm: &request.realm,
            identifier: &request.identifier,
            password: &request.password,
            origin: Origin {
                user_agent,
                ip_address: server_ctx::client_ip(&parts),
            },
        },
    )
    .await
    .map_err(server_ctx::to_server_fn_error)?;

    match outcome {
        Outcome::Complete(authenticated) => {
            server_ctx::set_session_cookie(policy, &authenticated.session);
            // Only when one was actually presented. Clearing unconditionally
            // put a `Set-Cookie` deleting a challenge on every ordinary login,
            // which is noise on the wire and, because it came first, made the
            // response's first `Set-Cookie` header something other than the
            // session.
            if server_ctx::challenge_token(policy, &parts).is_some() {
                server_ctx::clear_challenge_cookie(policy);
            }
            Ok(LoginOutcome::Complete(
                describe_session(&db, authenticated.user).await?,
            ))
        }
        Outcome::SecondFactorRequired(challenged) => {
            server_ctx::set_challenge_cookie(policy, &challenged.issued);
            Ok(LoginOutcome::SecondFactorRequired(SecondFactorPrompt {
                username: challenged.user.username,
                totp: challenged.factors.contains(&Factor::Totp),
                passkey: challenged.factors.contains(&Factor::Passkey),
                recovery_code: challenged.factors.contains(&Factor::RecoveryCode),
            }))
        }
    }
}

/// Resolve the roles and permissions a signed-in user carries.
///
/// One place, so the two paths that produce a `LoginResponse` — with and
/// without a second factor — cannot answer differently.
#[cfg(feature = "ssr")]
async fn describe_session(
    db: &authenc_identity::Db,
    user: authenc_contract::model::User,
) -> Result<LoginResponse, ServerFnError> {
    use crate::server_ctx;

    let roles = authenc_identity::user::role_names(db, user.id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let permissions = authenc_identity::user::permissions(db, user.id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(LoginResponse {
        user,
        roles,
        permissions,
    })
}

/// Finish a login by presenting a second factor.
///
/// The challenge is identified by an `HttpOnly` cookie, not by an argument, so
/// a caller cannot aim this at somebody else's pending login by changing a
/// field.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = SubmitSecondFactor, prefix = "/api/sfn", endpoint = "mfa/verify", input = Json)]
pub async fn submit_second_factor(factor: SecondFactor) -> Result<LoginResponse, ServerFnError> {
    use authenc_identity::{
        Db, MasterKey,
        login::{self, Proof},
        session::Origin,
    };

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let master = expect_context::<std::sync::Arc<MasterKey>>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    let token = server_ctx::challenge_token(policy, &parts)
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;

    let proof = match &factor {
        SecondFactor::Totp { code } => Proof::Totp(code),
        SecondFactor::RecoveryCode { code } => Proof::RecoveryCode(code),
    };

    let user_agent = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok());

    let authenticated = login::second_factor(
        &db,
        &master,
        &token,
        proof,
        Origin {
            user_agent,
            ip_address: server_ctx::client_ip(&parts),
        },
    )
    .await
    .inspect_err(|_| {
        // A wrong code leaves the challenge usable, so the cookie stays. Only
        // an exhausted or expired one is cleared — which `login::second_factor`
        // reports the same way, so this errs toward keeping it and letting the
        // next attempt fail cleanly.
    })
    .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::clear_challenge_cookie(policy);
    server_ctx::set_session_cookie(policy, &authenticated.session);

    describe_session(&db, authenticated.user).await
}

/// Abandon a half-finished login.
///
/// Called when the user backs out of the second step, so the browser is not
/// left holding a challenge cookie it will send on every later request.
#[server(name = CancelSecondFactor, prefix = "/api/sfn", endpoint = "mfa/cancel")]
pub async fn cancel_second_factor() -> Result<(), ServerFnError> {
    use crate::server_ctx;

    server_ctx::clear_challenge_cookie(expect_context::<CookiePolicy>());
    Ok(())
}

/// End the current session.
///
/// Always succeeds: logging out of a session that is already gone is the
/// outcome the caller wanted.
#[server(name = LogOut, prefix = "/api/sfn", endpoint = "logout")]
pub async fn log_out() -> Result<(), ServerFnError> {
    use authenc_identity::{Db, session};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    if let Some(token) = server_ctx::session_token(policy, &parts) {
        session::revoke(&db, &token)
            .await
            .map_err(server_ctx::to_server_fn_error)?;
    }

    server_ctx::clear_session_cookie(policy);
    Ok(())
}

/// Who the current session belongs to, or `None` when nobody is signed in.
#[server(name = CurrentUser, prefix = "/api/sfn", endpoint = "me")]
pub async fn current_user() -> Result<Option<LoginResponse>, ServerFnError> {
    use authenc_identity::{Db, session, user};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    let Some(token) = server_ctx::session_token(policy, &parts) else {
        return Ok(None);
    };
    let Some(session) = session::lookup(&db, &token)
        .await
        .map_err(server_ctx::to_server_fn_error)?
    else {
        return Ok(None);
    };

    let user = user::by_id(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let roles = user::role_names(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let permissions = user::permissions(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(Some(LoginResponse {
        user,
        roles,
        permissions,
    }))
}

// ---------------------------------------------------------------------------
// Managing your own second factors
// ---------------------------------------------------------------------------
//
// Every function below acts on **the caller's own** account, resolved from the
// session. None of them takes a user id: an argument naming whose factors to
// change is an argument someone will eventually change.

/// The caller's second factors.
#[server(name = GetMfaStatus, prefix = "/api/sfn", endpoint = "mfa/status")]
pub async fn mfa_status() -> Result<MfaStatus, ServerFnError> {
    use authenc_identity::{Db, mfa};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db).await?;

    let enrolment = mfa::enrolment(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let passkeys = mfa::passkey::list(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(MfaStatus {
        totp: enrolment.totp,
        passkeys: passkeys.into_iter().map(into_summary).collect(),
        recovery_codes_remaining: enrolment.recovery_codes,
        enforced: enrolment.is_required(),
    })
}

#[cfg(feature = "ssr")]
fn into_summary(registered: authenc_identity::mfa::passkey::Registered) -> PasskeySummary {
    use time::format_description::well_known::Rfc3339;

    PasskeySummary {
        id: authenc_contract::PasskeyId(registered.id),
        label: registered.label,
        created_at: registered
            .created_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::new()),
        last_used_at: registered
            .last_used_at
            .and_then(|at| at.format(&Rfc3339).ok()),
    }
}

/// Begin enrolling an authenticator app.
///
/// The secret is returned once and never again — it exists in the database only
/// sealed under the master key.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = BeginTotpEnrolment, prefix = "/api/sfn", endpoint = "mfa/totp/begin", input = Json)]
pub async fn begin_totp_enrolment(label: String) -> Result<TotpEnrolment, ServerFnError> {
    use authenc_identity::{Db, MasterKey, mfa::totp, user};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let master = expect_context::<std::sync::Arc<MasterKey>>();
    let session = server_ctx::require_session(&db).await?;

    let user = user::by_id(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let realm = authenc_identity::realm::by_id(&db, session.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let enrolling = totp::begin_enrolment(&db, &master, session.user_id, &label)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(TotpEnrolment {
        secret: enrolling.secret.to_base32(),
        provisioning_uri: enrolling.provisioning_uri(&realm.display_name, &user.username),
    })
}

/// Confirm an enrolment, and receive the recovery codes that go with it.
///
/// The codes are generated here rather than on a separate button because this
/// is the moment they matter: turning on a second factor without a way past a
/// lost phone is how an account becomes unrecoverable.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = ConfirmTotpEnrolment, prefix = "/api/sfn", endpoint = "mfa/totp/confirm", input = Json)]
pub async fn confirm_totp_enrolment(code: String) -> Result<Vec<String>, ServerFnError> {
    use authenc_identity::{
        Db, MasterKey,
        mfa::{recovery, totp},
    };

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let master = expect_context::<std::sync::Arc<MasterKey>>();
    let session = server_ctx::require_session(&db).await?;

    let confirmed = totp::confirm(&db, &master, session.user_id, &code)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    if !confirmed {
        return Err(server_ctx::to_server_fn_error(AppError::validation(
            "that code did not match; check your authenticator and try again",
        )));
    }

    let codes = recovery::generate(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(codes.expose().to_vec())
}

/// Remove the authenticator.
///
/// Every session but this one is revoked: turning a factor off is exactly the
/// action an attacker who has borrowed a session would take, and the owner
/// should not be left sharing their account with whoever was already in it.
#[server(name = DisableTotp, prefix = "/api/sfn", endpoint = "mfa/totp/disable")]
pub async fn disable_totp() -> Result<(), ServerFnError> {
    use authenc_identity::{Db, mfa::totp};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db).await?;

    totp::disable(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(())
}

/// Replace the recovery codes with a fresh set.
#[server(name = RegenerateRecoveryCodes, prefix = "/api/sfn", endpoint = "mfa/recovery/regenerate")]
pub async fn regenerate_recovery_codes() -> Result<Vec<String>, ServerFnError> {
    use authenc_identity::{Db, mfa::recovery};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db).await?;

    let codes = recovery::generate(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(codes.expose().to_vec())
}

// ---------------------------------------------------------------------------
// Passkey ceremonies
// ---------------------------------------------------------------------------
//
// These four carry `serde_json::Value` rather than typed arguments, and that is
// a deliberate boundary rather than laziness. The WebAuthn types belong to
// `webauthn-rs`, which lives in `authenc-identity` and must never reach the
// browser bundle — `authenc-contract` is the only vocabulary shared with wasm,
// and it may not depend on `sqlx`, `axum`, or anything that pulls them.
//
// What crosses the wire is exactly what the browser's `navigator.credentials`
// API produces and consumes, which is JSON by definition. The typing that
// matters happens on the server, where the value is parsed into the library's
// own types and refused if it does not fit.

/// Begin registering a passkey for the caller.
#[server(name = BeginPasskeyRegistration, prefix = "/api/sfn", endpoint = "mfa/passkey/register/begin")]
pub async fn begin_passkey_registration() -> Result<serde_json::Value, ServerFnError> {
    use authenc_identity::{Db, mfa::passkey};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let rp = expect_context::<std::sync::Arc<passkey::RelyingParty>>();
    let session = server_ctx::require_session(&db).await?;

    let user = authenc_identity::user::by_id(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let (challenge, token) = passkey::begin_registration(&db, &rp, &user)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::set_ceremony_cookie(expect_context::<CookiePolicy>(), &token);

    serde_json::to_value(challenge).map_err(|e| {
        server_ctx::to_server_fn_error(AppError::internal_from("encoding a challenge", e))
    })
}

/// Finish registering a passkey.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = FinishPasskeyRegistration, prefix = "/api/sfn", endpoint = "mfa/passkey/register/finish", input = Json)]
pub async fn finish_passkey_registration(
    label: String,
    credential: serde_json::Value,
) -> Result<PasskeySummary, ServerFnError> {
    use authenc_identity::{Db, mfa::passkey};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let rp = expect_context::<std::sync::Arc<passkey::RelyingParty>>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();
    let session = server_ctx::require_session(&db).await?;

    let token = server_ctx::ceremony_token(policy, &parts)
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;

    let credential = serde_json::from_value(credential).map_err(|_| {
        server_ctx::to_server_fn_error(AppError::validation("that is not a WebAuthn credential"))
    })?;

    let registered =
        passkey::finish_registration(&db, &rp, session.user_id, &token, &label, &credential)
            .await
            .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::clear_ceremony_cookie(policy);
    Ok(into_summary(registered))
}

/// Begin signing in with a passkey, against the pending login.
#[server(name = BeginPasskeyLogin, prefix = "/api/sfn", endpoint = "mfa/passkey/login/begin")]
pub async fn begin_passkey_login() -> Result<serde_json::Value, ServerFnError> {
    use authenc_identity::{
        Db,
        mfa::{challenge, passkey},
    };

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let rp = expect_context::<std::sync::Arc<passkey::RelyingParty>>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    // The user is taken from the pending challenge, never from an argument:
    // otherwise this endpoint would hand out an authentication challenge for
    // any account a caller cared to name.
    let token = server_ctx::challenge_token(policy, &parts)
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;
    let pending = challenge::lookup(&db, &token)
        .await
        .map_err(server_ctx::to_server_fn_error)?
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;

    let (request, ceremony) = passkey::begin_authentication(&db, &rp, pending.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::set_ceremony_cookie(policy, &ceremony);

    serde_json::to_value(request).map_err(|e| {
        server_ctx::to_server_fn_error(AppError::internal_from("encoding a challenge", e))
    })
}

/// Finish signing in with a passkey.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = FinishPasskeyLogin, prefix = "/api/sfn", endpoint = "mfa/passkey/login/finish", input = Json)]
pub async fn finish_passkey_login(
    credential: serde_json::Value,
) -> Result<LoginResponse, ServerFnError> {
    use authenc_identity::{
        Db, login,
        mfa::{Factor, challenge, passkey},
        session::Origin,
    };

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let rp = expect_context::<std::sync::Arc<passkey::RelyingParty>>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    let challenge_token = server_ctx::challenge_token(policy, &parts)
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;
    let ceremony_token = server_ctx::ceremony_token(policy, &parts)
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;

    let pending = challenge::lookup(&db, &challenge_token)
        .await
        .map_err(server_ctx::to_server_fn_error)?
        .ok_or_else(|| server_ctx::to_server_fn_error(AppError::Unauthenticated))?;

    let credential = serde_json::from_value(credential).map_err(|_| {
        server_ctx::to_server_fn_error(AppError::validation("that is not a WebAuthn assertion"))
    })?;

    if let Err(error) =
        passkey::finish_authentication(&db, &rp, pending.user_id, &ceremony_token, &credential)
            .await
    {
        // A failed assertion costs an attempt, exactly as a wrong code does.
        // Without this, the passkey route would be the one way to try
        // indefinitely.
        challenge::record_failure(&db, pending.id)
            .await
            .map_err(server_ctx::to_server_fn_error)?;
        return Err(server_ctx::to_server_fn_error(error));
    }

    let user_agent = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok());

    let authenticated = login::open_session(
        &db,
        &pending,
        Factor::Passkey,
        Origin {
            user_agent,
            ip_address: server_ctx::client_ip(&parts),
        },
    )
    .await
    .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::clear_ceremony_cookie(policy);
    server_ctx::clear_challenge_cookie(policy);
    server_ctx::set_session_cookie(policy, &authenticated.session);

    describe_session(&db, authenticated.user).await
}

/// Rename one of the caller's passkeys.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = RenamePasskey, prefix = "/api/sfn", endpoint = "mfa/passkey/rename", input = Json)]
pub async fn rename_passkey(
    id: authenc_contract::PasskeyId,
    label: String,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, mfa::passkey};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db).await?;

    passkey::rename(&db, session.user_id, id.0, &label)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// Remove one of the caller's passkeys.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = RemovePasskey, prefix = "/api/sfn", endpoint = "mfa/passkey/remove", input = Json)]
pub async fn remove_passkey(id: authenc_contract::PasskeyId) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, mfa::passkey};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db).await?;

    passkey::remove(&db, session.user_id, id.0)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// One page of the realm's audit trail.
///
/// `action_prefix` is a namespace like `mfa.`, not a free-text search: the
/// stored names are namespaced precisely so a category can be selected without
/// enumerating it, and a `LIKE` on arbitrary user input would be a different
/// and worse thing.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = ListAuditEvents, prefix = "/api/sfn", endpoint = "audit", input = Json)]
pub async fn list_audit_events(
    action_prefix: Option<String>,
    outcome: Option<authenc_contract::event::Outcome>,
    limit: i64,
    offset: i64,
) -> Result<AuditPage, ServerFnError> {
    use authenc_identity::{Db, admin, audit};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let filter = audit::Filter {
        prefix: action_prefix.as_deref(),
        outcome,
        ..audit::Filter::default()
    };

    let total = admin::count_audit(&db, &actor, actor.realm_id, filter)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let events = admin::list_audit(&db, &actor, actor.realm_id, filter, limit, offset)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(AuditPage { events, total })
}

/// A page of audit events, with the total so the console can page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPage {
    /// The events, newest first.
    pub events: Vec<authenc_contract::AuditEvent>,
    /// How many match the filter in total.
    pub total: i64,
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// A group as the console shows it.
///
/// Defined here rather than reusing `authenc_identity::group::Group`, because
/// this type has to compile to wasm and that one carries `sqlx` with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupSummary {
    /// Stable identifier.
    pub id: authenc_contract::GroupId,
    /// Full path from the root, e.g. `/engineering/backend`.
    pub path: String,
    /// Name, unique among its siblings.
    pub name: String,
    /// How deep it sits, so the console can indent without parsing the path.
    pub depth: usize,
    /// Roles granted **directly** to it. Not the inherited ones: a child holds
    /// its ancestors' roles for authorisation, but listing them here would
    /// misreport what an administrator actually set.
    pub roles: Vec<String>,
    /// How many people are directly in it.
    pub members: usize,
}

/// The realm's group tree, ordered so it reads top-down.
#[server(name = ListGroups, prefix = "/api/sfn", endpoint = "groups")]
pub async fn list_groups() -> Result<Vec<GroupSummary>, ServerFnError> {
    use authenc_identity::{Db, admin, group};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let groups = admin::list_groups(&db, &actor, actor.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let mut summaries = Vec::with_capacity(groups.len());
    for found in groups {
        let roles = group::roles(&db, found.id)
            .await
            .map_err(server_ctx::to_server_fn_error)?;
        let members = group::members(&db, found.id)
            .await
            .map_err(server_ctx::to_server_fn_error)?;

        summaries.push(GroupSummary {
            // The path always starts with `/`, so one segment means depth 0.
            depth: found.path.matches('/').count().saturating_sub(1),
            id: found.id,
            path: found.path,
            name: found.name,
            roles: roles.into_iter().map(|role| role.name).collect(),
            members: members.len(),
        });
    }

    Ok(summaries)
}

/// Create a group.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = CreateGroup, prefix = "/api/sfn", endpoint = "groups/create", input = Json)]
pub async fn create_group(
    parent_id: Option<authenc_contract::GroupId>,
    name: String,
) -> Result<GroupSummary, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let created = admin::create_group(&db, &actor, parent_id, &name, None)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(GroupSummary {
        depth: created.path.matches('/').count().saturating_sub(1),
        id: created.id,
        path: created.path,
        name: created.name,
        roles: Vec::new(),
        members: 0,
    })
}

/// Delete a group and its subtree.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DeleteGroup, prefix = "/api/sfn", endpoint = "groups/delete", input = Json)]
pub async fn delete_group(id: authenc_contract::GroupId) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::delete_group(&db, &actor, id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

/// An organisation as the console shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationSummary {
    /// Stable identifier.
    pub id: authenc_contract::OrganizationId,
    /// URL-safe handle.
    pub slug: String,
    /// Human-facing name.
    pub name: String,
    /// Whether its members may sign in.
    pub enabled: bool,
    /// How many people belong to it.
    pub members: usize,
    /// How many invitations are outstanding.
    pub pending_invitations: usize,
}

/// Every organisation in the realm.
#[server(name = ListOrganizations, prefix = "/api/sfn", endpoint = "organizations")]
pub async fn list_organizations() -> Result<Vec<OrganizationSummary>, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let organizations = admin::list_organizations(&db, &actor)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let mut summaries = Vec::with_capacity(organizations.len());
    for organization in organizations {
        let members = admin::organization_members(&db, &actor, organization.id)
            .await
            .map_err(server_ctx::to_server_fn_error)?;
        let invitations = admin::organization_invitations(&db, &actor, organization.id)
            .await
            .map_err(server_ctx::to_server_fn_error)?;

        summaries.push(OrganizationSummary {
            id: organization.id,
            slug: organization.slug,
            name: organization.name,
            enabled: organization.enabled,
            members: members.len(),
            pending_invitations: invitations
                .iter()
                .filter(|invitation| !invitation.accepted)
                .count(),
        });
    }

    Ok(summaries)
}

/// Create an organisation.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = CreateOrganization, prefix = "/api/sfn", endpoint = "organizations/create", input = Json)]
pub async fn create_organization(
    slug: String,
    name: String,
) -> Result<OrganizationSummary, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let created = admin::create_organization(&db, &actor, &slug, &name)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(OrganizationSummary {
        id: created.id,
        slug: created.slug,
        name: created.name,
        enabled: created.enabled,
        members: 0,
        pending_invitations: 0,
    })
}

/// Suspend or restore an organisation.
///
/// Suspending stops every member signing in, unless they also belong to
/// another organisation that is still enabled.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = SetOrganizationEnabled, prefix = "/api/sfn", endpoint = "organizations/enabled", input = Json)]
pub async fn set_organization_enabled(
    id: authenc_contract::OrganizationId,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::set_organization_enabled(&db, &actor, id, enabled)
        .await
        .map(|_| ())
        .map_err(server_ctx::to_server_fn_error)
}

/// Delete an organisation. Its members remain as users.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DeleteOrganization, prefix = "/api/sfn", endpoint = "organizations/delete", input = Json)]
pub async fn delete_organization(
    id: authenc_contract::OrganizationId,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::delete_organization(&db, &actor, id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// A social-login provider, as the login page shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignInProvider {
    /// The alias, which is the path segment the button links to.
    pub alias: String,
    /// What the button says.
    pub display_name: String,
    /// Which provider it is, so the button can carry the right mark.
    pub kind: String,
}

/// The social-login providers a realm offers.
///
/// Deliberately unauthenticated: the login page is. An unknown realm returns
/// an empty list rather than an error, so this cannot be used to find out
/// which realms exist — the same reason `login::authenticate` answers 401 for
/// an unknown realm rather than 404.
///
/// Nothing secret is published. The alias and the display name are both
/// visible on the button anyway, and the client id — which is public, but has
/// no reason to be here — is not included.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = SignInProviders, prefix = "/api/sfn", endpoint = "sign-in-providers", input = Json)]
pub async fn sign_in_providers(realm: String) -> Result<Vec<SignInProvider>, ServerFnError> {
    use authenc_identity::{Db, federation, realm as realms};

    let db = expect_context::<Db>();

    let Ok(found) = realms::by_name(&db, &realm).await else {
        return Ok(Vec::new());
    };
    if !found.enabled {
        return Ok(Vec::new());
    }

    let providers = federation::list(&db, found.id)
        .await
        .map_err(crate::server_ctx::to_server_fn_error)?;

    Ok(providers
        .into_iter()
        .filter(|provider| provider.enabled)
        .map(|provider| SignInProvider {
            alias: provider.alias,
            display_name: provider.display_name,
            kind: provider.kind.to_string(),
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Social-login providers
// ---------------------------------------------------------------------------

/// A configured provider as the console shows it.
///
/// No client secret, because no read path decrypts one — `federation::Provider`
/// has no field for it either, so one cannot arrive here by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSummary {
    /// Stable identifier.
    pub id: authenc_contract::IdentityProviderId,
    /// URL-safe handle, appearing in the callback path.
    pub alias: String,
    /// Which claim mapping is used.
    pub kind: String,
    /// What the login page calls it.
    pub display_name: String,
    /// Whether it is offered on the login page.
    pub enabled: bool,
    /// Whether an unrecognised upstream account may create a local one.
    pub allow_provisioning: bool,
    /// Whether a verified upstream address may adopt an existing local account.
    pub link_by_verified_email: bool,
    /// How many accounts are signed in through it.
    pub links: i64,
}

/// Every provider configured in the realm.
#[server(name = ListProviders, prefix = "/api/sfn", endpoint = "providers")]
pub async fn list_providers() -> Result<Vec<ProviderSummary>, ServerFnError> {
    use authenc_identity::{Db, admin, federation};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let providers = admin::list_identity_providers(&db, &actor)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let mut summaries = Vec::with_capacity(providers.len());
    for provider in providers {
        let links = federation::link_count(&db, provider.id)
            .await
            .map_err(server_ctx::to_server_fn_error)?;

        summaries.push(ProviderSummary {
            id: provider.id,
            alias: provider.alias,
            kind: provider.kind.to_string(),
            display_name: provider.display_name,
            enabled: provider.enabled,
            allow_provisioning: provider.allow_provisioning,
            link_by_verified_email: provider.link_by_verified_email,
            links,
        });
    }

    Ok(summaries)
}

/// Offer a provider on the login page, or stop offering it.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = SetProviderEnabled, prefix = "/api/sfn", endpoint = "providers/enabled", input = Json)]
pub async fn set_provider_enabled(
    id: authenc_contract::IdentityProviderId,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::set_identity_provider_enabled(&db, &actor, id, enabled)
        .await
        .map(|_| ())
        .map_err(server_ctx::to_server_fn_error)
}

/// Delete a provider and every account link through it.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DeleteProvider, prefix = "/api/sfn", endpoint = "providers/delete", input = Json)]
pub async fn delete_provider(
    id: authenc_contract::IdentityProviderId,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::delete_identity_provider(&db, &actor, id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// Render a server-function failure as something a person can read.
///
/// One place to do this, so no page invents its own error string.
///
/// A `ServerError` carries the message the server chose, already stripped of
/// internal detail by `to_server_fn_error`. Displaying the whole
/// [`ServerFnError`] instead would prepend Leptos's own
/// `"error running server function: "` wrapper, so a wrong password read as
/// *"error running server function: authentication required"* — an internal
/// phrase shown to a person at the one moment they are already stuck.
#[must_use]
pub fn describe(error: &ServerFnError) -> String {
    match error {
        ServerFnError::ServerError(message) => message.clone(),
        other => other.to_string(),
    }
}

/// Begin a password reset.
///
/// Always succeeds, whether or not the address is registered. Reporting
/// otherwise would turn this endpoint into a way to enumerate accounts.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = RequestPasswordReset, prefix = "/api/sfn", endpoint = "password-reset", input = Json)]
pub async fn request_password_reset(realm: String, email: String) -> Result<(), ServerFnError> {
    use std::sync::Arc;

    use authenc_identity::{Db, mail::Mailer, recovery};

    use crate::{server_ctx, server_ctx::PublicUrls};

    let db = expect_context::<Db>();
    let mailer = expect_context::<Arc<dyn Mailer>>();
    let urls = expect_context::<PublicUrls>();

    // An unknown realm is also silent: the caller learns nothing either way.
    let Ok(realm) = authenc_identity::realm::by_name(&db, &realm).await else {
        return Ok(());
    };

    recovery::request_password_reset(&db, mailer.as_ref(), realm.id, &email, &urls.reset)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// Finish a password reset using the token from the emailed link.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = CompletePasswordReset, prefix = "/api/sfn", endpoint = "password-reset-complete", input = Json)]
pub async fn complete_password_reset(
    token: String,
    new_password: String,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, PasswordHasher, SecretToken, recovery};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();

    recovery::complete_password_reset(
        &db,
        &hasher,
        &SecretToken::from_client(token),
        &new_password,
    )
    .await
    .map(|_| ())
    .map_err(server_ctx::to_server_fn_error)
}

/// Confirm an email address using the token from the emailed link.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = VerifyEmail, prefix = "/api/sfn", endpoint = "verify-email", input = Json)]
pub async fn verify_email(token: String) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, SecretToken, recovery};

    use crate::server_ctx;

    let db = expect_context::<Db>();

    recovery::complete_email_verification(&db, &SecretToken::from_client(token))
        .await
        .map(|_| ())
        .map_err(server_ctx::to_server_fn_error)
}

/// A page of users, with the total so the console can page through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPage {
    /// The users on this page.
    pub items: Vec<authenc_contract::model::User>,
    /// How many exist in total.
    pub total: i64,
}

/// List users in the caller's realm.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = ListUsers, prefix = "/api/sfn", endpoint = "users", input = Json)]
pub async fn list_users(limit: i64, offset: i64) -> Result<UserPage, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let items = admin::list_users(&db, &actor, actor.realm_id, limit, offset)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let total = admin::count_users(&db, &actor, actor.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(UserPage { items, total })
}

/// Create a user in the caller's realm.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = CreateUser, prefix = "/api/sfn", endpoint = "users-create", input = Json)]
pub async fn create_user(
    username: String,
    email: String,
    password: String,
) -> Result<authenc_contract::model::User, ServerFnError> {
    use authenc_identity::{Db, PasswordHasher, admin, user::NewUser};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::create_user(
        &db,
        &actor,
        &hasher,
        NewUser {
            realm_id: actor.realm_id,
            username: &username,
            email: &email,
            password: &password,
            first_name: None,
            last_name: None,
        },
    )
    .await
    .map_err(server_ctx::to_server_fn_error)
}

/// Enable or disable a user.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = SetUserEnabled, prefix = "/api/sfn", endpoint = "users-enabled", input = Json)]
pub async fn set_user_enabled(
    user_id: authenc_contract::UserId,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::set_user_enabled(&db, &actor, user_id, enabled)
        .await
        .map(|_| ())
        .map_err(server_ctx::to_server_fn_error)
}

/// Delete a user.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DeleteUser, prefix = "/api/sfn", endpoint = "users-delete", input = Json)]
pub async fn delete_user(user_id: authenc_contract::UserId) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::delete_user(&db, &actor, user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// List roles in the caller's realm.
#[server(name = ListRoles, prefix = "/api/sfn", endpoint = "roles", input = Json)]
pub async fn list_roles() -> Result<Vec<authenc_contract::model::Role>, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    admin::list_roles(&db, &actor, actor.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

// ---------------------------------------------------------------------------
// OAuth consent
// ---------------------------------------------------------------------------

/// One scope, as the consent screen shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeInfo {
    /// The scope's protocol name, e.g. `email`.
    pub name: String,
    /// What granting it means, in a sentence.
    pub description: String,
}

/// What the consent screen needs in order to ask an honest question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentPrompt {
    /// The client's registered display name — not a name it supplied in the
    /// request, which is the difference between consent and a phishing form.
    pub client_name: String,
    /// The scopes that will actually be granted, already narrowed to what the
    /// client is registered for.
    pub scopes: Vec<ScopeInfo>,
    /// The signed-in user, so they can see whose account they are granting.
    pub username: String,
    /// The token the approval form must post back.
    pub csrf_token: String,
}

/// Describe a pending authorization request.
///
/// Everything shown is resolved server-side from the client's registration.
/// The query string is only used to *identify* the request; nothing in it is
/// echoed to the user, because a page that displays attacker-supplied text
/// under the operator's domain is a phishing page with extra steps.
///
/// The arguments are the realm, the client asking, and the scopes it wants.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DescribeConsent, prefix = "/api/sfn", endpoint = "consent")]
pub async fn consent_prompt(
    realm: String,
    client_id: String,
    scope: String,
) -> Result<ConsentPrompt, ServerFnError> {
    use authenc_identity::{Db, user};
    use authenc_oauth::{client, scope as scopes};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db).await?;

    let realm = authenc_identity::realm::by_name(&db, &realm)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let user = user::by_id(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    // A session in one realm must not be able to approve anything in another,
    // and a disabled account must not be able to approve at all.
    if !user.enabled || user.realm_id != realm.id {
        return Err(server_ctx::to_server_fn_error(AppError::Unauthenticated));
    }

    let client = client::by_client_id(&db, realm.id, &client_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let granted = scopes::resolve(&scopes::parse(&scope), &client.scopes)
        .map_err(|error| server_ctx::to_server_fn_error(AppError::validation(error.description)))?;

    Ok(ConsentPrompt {
        client_name: client.name,
        scopes: granted
            .iter()
            .map(|name| ScopeInfo {
                name: name.clone(),
                description: scopes::describe(name).to_owned(),
            })
            .collect(),
        username: user.username,
        csrf_token: session.csrf_token(),
    })
}

// ---------------------------------------------------------------------------
// OAuth clients
// ---------------------------------------------------------------------------

/// A registered client, as the console lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSummary {
    /// The `client_id` the client presents.
    pub client_id: String,
    /// Display name, shown on the consent screen.
    pub name: String,
    /// Whether it is a public client: no secret, PKCE required.
    pub is_public: bool,
    /// Exact redirect URIs it may be sent to.
    pub redirect_uris: Vec<String>,
    /// Scopes it may request.
    pub scopes: Vec<String>,
    /// Whether the user is asked before issuance.
    pub require_consent: bool,
}

#[cfg(feature = "ssr")]
impl From<authenc_oauth::Client> for ClientSummary {
    fn from(client: authenc_oauth::Client) -> Self {
        Self {
            client_id: client.client_id,
            name: client.name,
            is_public: client.is_public,
            redirect_uris: client.redirect_uris,
            scopes: client.scopes,
            require_consent: client.require_consent,
        }
    }
}

/// List the OAuth clients in the caller's realm.
#[server(name = ListClients, prefix = "/api/sfn", endpoint = "clients")]
pub async fn list_clients() -> Result<Vec<ClientSummary>, ServerFnError> {
    use authenc_identity::Db;

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    let clients = authenc_oauth::admin::list(&db, &actor, actor.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(clients.into_iter().map(ClientSummary::from).collect())
}

/// Register a client, returning its secret once.
///
/// The secret is shown to the administrator and never stored in a form the
/// server can read back — only its Argon2 hash reaches the database. If the
/// page is closed before it is copied, the remedy is to rotate it, not to
/// look it up.
///
/// The arguments are the client id, display name, whether it is public, its
/// redirect URIs, and its scopes.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = RegisterClient, prefix = "/api/sfn", endpoint = "clients/register", input = Json)]
pub async fn register_client(
    client_id: String,
    name: String,
    is_public: bool,
    redirect_uris: Vec<String>,
    scopes: Vec<String>,
) -> Result<Option<String>, ServerFnError> {
    use authenc_identity::{Db, PasswordHasher};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();
    let actor = server_ctx::require_actor(&db).await?;

    let registered = authenc_oauth::admin::register(
        &db,
        &actor,
        &hasher,
        authenc_oauth::admin::Registration {
            client_id: &client_id,
            name: &name,
            is_public,
            redirect_uris: &redirect_uris,
            scopes: &scopes,
            require_consent: true,
        },
    )
    .await
    .map_err(server_ctx::to_server_fn_error)?;

    Ok(registered
        .client_secret
        .map(|secret| secret.expose().to_owned()))
}

/// Replace a client's secret and return the new one.
///
/// The argument is the client id.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = RotateClientSecret, prefix = "/api/sfn", endpoint = "clients/secret")]
pub async fn rotate_client_secret(client_id: String) -> Result<String, ServerFnError> {
    use authenc_identity::{Db, PasswordHasher};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();
    let actor = server_ctx::require_actor(&db).await?;

    let secret = authenc_oauth::admin::rotate_secret(&db, &actor, &hasher, &client_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(secret.expose().to_owned())
}

/// Delete a client, and with it every code, token, and consent it holds.
///
/// The argument is the client id.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DeleteClient, prefix = "/api/sfn", endpoint = "clients/delete")]
pub async fn delete_client(client_id: String) -> Result<(), ServerFnError> {
    use authenc_identity::Db;

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db).await?;

    authenc_oauth::admin::delete(&db, &actor, &client_id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}
