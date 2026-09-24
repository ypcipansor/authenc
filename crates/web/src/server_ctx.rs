//! Server-side helpers shared by the server functions in [`crate::api`] and by
//! the HTTP surface in `authenc-server`.
//!
//! This lives here rather than in `authenc-server` for a structural reason:
//! `server` depends on `web`, so anything both need has to sit at or below
//! `web`. Compiled only under `ssr`; none of it reaches the browser bundle.

use std::net::{IpAddr, SocketAddr};

use authenc_contract::{AppError, model::Actor};
use authenc_identity::{SecretToken, session::Issued};
use axum::http::{StatusCode, header::SET_COOKIE, request::Parts};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use leptos::prelude::{ServerFnError, use_context};
use leptos_axum::ResponseOptions;

/// How the session cookie is named and flagged.
///
/// The `Secure` attribute is not a choice: every cookie built here carries it,
/// so a session token is never sent over a plaintext connection. On
/// `http://localhost` browsers treat the origin as trustworthy and store a
/// `Secure` cookie anyway, so development still works.
///
/// The `__Host-` prefix is what differs. It is the strictest form — bound to
/// exactly this origin, no `Domain`, `Path=/` — and production gets it. It is
/// tied to the HTTPS public URL that `Config::validate` demands the production
/// profile supply before it will start.
#[derive(Debug, Clone, Copy)]
pub struct CookiePolicy {
    /// Cookie name.
    pub name: &'static str,
    /// Whether the name carries the `__Host-` prefix. Orthogonal to the
    /// `Secure` attribute, which is always set.
    pub host_prefix: bool,
}

impl CookiePolicy {
    /// The development policy: a plain name, still `Secure`.
    #[must_use]
    pub const fn development() -> Self {
        Self {
            name: "authenc_session",
            host_prefix: false,
        }
    }

    /// The production policy.
    ///
    /// `__Host-` binds the cookie to exactly this origin — no `Domain`,
    /// `Path=/`, `Secure` — so a sibling subdomain cannot overwrite it.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            name: "__Host-authenc_session",
            host_prefix: true,
        }
    }

    /// Build the `Set-Cookie` value that establishes a session.
    #[must_use]
    pub fn issue(self, token: &SecretToken, max_age: time::Duration) -> Cookie<'static> {
        Cookie::build((self.name, token.expose().to_owned()))
            // Unreadable from JavaScript, so an injected script has nothing to
            // steal. The previous console kept a JWT in `localStorage`.
            .http_only(true)
            .secure(true)
            // `Lax` still sends the cookie on top-level navigation, so a link
            // into the console works, but withholds it on cross-site POSTs.
            .same_site(SameSite::Lax)
            .path("/")
            .max_age(max_age)
            .build()
    }

    /// Build the `Set-Cookie` value that clears a session.
    #[must_use]
    pub fn revoke(self) -> Cookie<'static> {
        Cookie::build((self.name, ""))
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Lax)
            .path("/")
            .max_age(time::Duration::ZERO)
            .build()
    }

    /// Read the session token a cookie jar carries, if any.
    #[must_use]
    pub fn read(self, jar: &CookieJar) -> Option<SecretToken> {
        jar.get(self.name)
            .map(|cookie| SecretToken::from_client(cookie.value()))
    }

    /// The policy for an in-flight WebAuthn ceremony.
    ///
    /// A third name for a third meaning. The ceremony handle is not a session
    /// and not a login challenge — it identifies one `navigator.credentials`
    /// call, and it is spent the moment that call comes back.
    #[must_use]
    pub const fn ceremony(self) -> Self {
        Self {
            name: if self.host_prefix {
                "__Host-authenc_ceremony"
            } else {
                "authenc_ceremony"
            },
            host_prefix: self.host_prefix,
        }
    }

    /// The policy for a social sign-in in flight.
    ///
    /// The `state` parameter goes to the provider *and* into this cookie, and
    /// the callback demands they match. Without that binding an attacker can
    /// start a sign-in with their own upstream account, hand the victim the
    /// resulting callback URL, and have the victim's browser finish it — after
    /// which the victim is working inside the attacker's account, and anything
    /// they save goes there. The server-side row alone does not prevent it:
    /// the attacker holds a perfectly valid, unspent state.
    ///
    /// `SameSite=Lax` is what makes the cookie survive the provider's
    /// top-level redirect back here, which is why the whole scheme works.
    #[must_use]
    pub const fn federation(self) -> Self {
        Self {
            name: if self.host_prefix {
                "__Host-authenc_federation"
            } else {
                "authenc_federation"
            },
            host_prefix: self.host_prefix,
        }
    }

    /// The policy for the half-finished login held between the two steps of an
    /// MFA sign-in.
    ///
    /// Same flags, deliberately a different name. A challenge is not a session,
    /// and if the two shared a cookie name then the second-step request would
    /// arrive carrying a value that every session lookup in the tree would try
    /// to resolve — which is the exact confusion the separate table exists to
    /// prevent, reintroduced at the transport.
    #[must_use]
    pub const fn challenge(self) -> Self {
        Self {
            name: if self.host_prefix {
                "__Host-authenc_mfa"
            } else {
                "authenc_mfa"
            },
            host_prefix: self.host_prefix,
        }
    }
}

/// Absolute base URLs for the links sent by mail.
///
/// Provided by the server from `server.public_url`, so a server function never
/// has to guess its own origin — the previous code hardcoded
/// `http://localhost:8080/v1` as the OIDC issuer and served that in its
/// discovery document wherever it was deployed.
#[derive(Debug, Clone)]
pub struct PublicUrls {
    /// Where a password-reset link points.
    pub reset: String,
    /// Where an email-verification link points.
    pub verify: String,
}

/// The session token presented by a request, if any.
#[must_use]
pub fn session_token(policy: CookiePolicy, parts: &Parts) -> Option<SecretToken> {
    policy.read(&CookieJar::from_headers(&parts.headers))
}

/// Attach a session cookie to the response a server function is building.
pub fn set_session_cookie(policy: CookiePolicy, issued: &Issued) {
    let max_age = issued.session.expires_at - time::OffsetDateTime::now_utc();
    append_cookie(&policy.issue(&issued.token, max_age));
}

/// Attach a cookie that clears the session.
pub fn clear_session_cookie(policy: CookiePolicy) {
    append_cookie(&policy.revoke());
}

/// The MFA challenge token presented by a request, if any.
#[must_use]
pub fn challenge_token(policy: CookiePolicy, parts: &Parts) -> Option<SecretToken> {
    policy
        .challenge()
        .read(&CookieJar::from_headers(&parts.headers))
}

/// Attach the cookie that carries a half-finished login.
///
/// Its lifetime matches the challenge's, so the browser drops it at the same
/// moment the server stops honouring it rather than sending a dead value on
/// every subsequent request.
pub fn set_challenge_cookie(
    policy: CookiePolicy,
    issued: &authenc_identity::mfa::challenge::Issued,
) {
    let max_age = issued.pending.expires_at - time::OffsetDateTime::now_utc();
    append_cookie(&policy.challenge().issue(&issued.token, max_age));
}

/// The WebAuthn ceremony handle presented by a request, if any.
#[must_use]
pub fn ceremony_token(policy: CookiePolicy, parts: &Parts) -> Option<SecretToken> {
    policy
        .ceremony()
        .read(&CookieJar::from_headers(&parts.headers))
}

/// Attach the cookie that identifies an in-flight WebAuthn ceremony.
pub fn set_ceremony_cookie(policy: CookiePolicy, token: &SecretToken) {
    append_cookie(
        &policy
            .ceremony()
            .issue(token, authenc_identity::mfa::passkey::CEREMONY_LIFETIME),
    );
}

/// Attach a cookie that clears any in-flight WebAuthn ceremony.
pub fn clear_ceremony_cookie(policy: CookiePolicy) {
    append_cookie(&policy.ceremony().revoke());
}

/// Attach a cookie that clears any half-finished login.
///
/// Called on completion **and** on failure: a spent or dead challenge left in
/// the browser produces a second step that cannot succeed and does not say why.
pub fn clear_challenge_cookie(policy: CookiePolicy) {
    append_cookie(&policy.challenge().revoke());
}

fn append_cookie(cookie: &Cookie<'static>) {
    let Some(response) = use_context::<ResponseOptions>() else {
        // Only possible if a server function is invoked outside a request,
        // which would be a wiring bug rather than a runtime condition.
        tracing::error!("no ResponseOptions in context; cookie not set");
        return;
    };
    if let Ok(value) = cookie.to_string().parse() {
        response.append_header(SET_COOKIE, value);
    }
}

/// The client's address, as far as it can be trusted.
///
/// Taken from the transport connection only. `X-Forwarded-For` is deliberately
/// **not** consulted: it is caller-supplied, and the previous code trusted it
/// unconditionally to drive its risk scoring, which meant any client could
/// choose the address it was judged by. Reinstating it requires an explicit
/// trusted-proxy configuration.
#[must_use]
pub fn client_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip())
}

/// Resolve the live session behind the current server-function call.
///
/// Almost every caller wants [`require_actor`] instead. This exists for the
/// one thing an `Actor` deliberately does not carry: the session-bound CSRF
/// token, which the consent form has to embed so its `POST` to the protocol
/// endpoint can be told apart from one another origin submitted.
///
/// # Errors
///
/// Returns a 401 failure when there is no live session, or a 500 if the lookup
/// fails.
///
/// The error type is [`ServerFnError`] rather than [`AppError`] on purpose.
/// Leptos reports every server-function failure as 500 unless something sets
/// the status, and `?` on an `AppError` goes through a blanket conversion that
/// does not — so a function written the obvious way answered an anonymous
/// caller with 500 instead of 401, and only a test that asserted the status
/// caught it. Returning the converted error makes the obvious way the correct
/// one.
pub async fn require_session(
    db: &authenc_identity::Db,
) -> Result<authenc_identity::session::Session, ServerFnError> {
    use authenc_identity::session;

    let policy = leptos::prelude::expect_context::<CookiePolicy>();
    let parts = leptos::prelude::expect_context::<Parts>();

    let resolve = async {
        let token = session_token(policy, &parts).ok_or(AppError::Unauthenticated)?;
        session::lookup(db, &token)
            .await?
            .ok_or(AppError::Unauthenticated)
    };

    resolve.await.map_err(to_server_fn_error)
}

/// Resolve the [`Actor`] behind the current server-function call.
///
/// Every administrative server function starts here. The actor's permissions
/// are read from the database on each call, so a role revoked a second ago is
/// already gone — nothing is cached in a token.
///
/// # Errors
///
/// Returns a 401 failure when there is no live session, or a 500 if a lookup
/// fails. The error is already a [`ServerFnError`] with its HTTP status set —
/// see [`require_session`] for why that matters.
pub async fn require_actor(db: &authenc_identity::Db) -> Result<Actor, ServerFnError> {
    use authenc_identity::user;

    let session = require_session(db).await?;

    let resolve = async {
        let user = user::by_id(db, session.user_id).await?;
        if !user.enabled {
            return Err(AppError::Unauthenticated);
        }

        Ok(Actor {
            roles: user::role_names(db, session.user_id).await?,
            permissions: user::permissions(db, session.user_id).await?,
            user_id: user.id,
            realm_id: user.realm_id,
            username: user.username,
        })
    };

    resolve.await.map_err(to_server_fn_error)
}

/// Convert a domain error into the failure a server function returns.
///
/// Two things happen here, and both matter:
///
/// * internal detail is dropped, because a server function's error travels to
///   the browser just as an HTTP body does;
/// * the HTTP status is set from the error, because Leptos otherwise reports
///   every server-function failure as 500 — which would make a wrong password
///   indistinguishable from a database outage to anything reading status
///   codes, including our own tests.
#[must_use]
pub fn to_server_fn_error(error: AppError) -> ServerFnError {
    if error.is_server_fault() {
        tracing::error!(?error, "server function failed");
    }

    if let Some(response) = use_context::<ResponseOptions>()
        && let Ok(status) = StatusCode::from_u16(error.status())
    {
        response.set_status(status);
    }

    ServerFnError::ServerError(error.public_detail())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_uses_a_plain_name_so_it_works_over_http() {
        let policy = CookiePolicy::development();
        assert_eq!(policy.name, "authenc_session");
        assert!(!policy.host_prefix);
    }

    #[test]
    fn production_uses_the_host_prefix() {
        let policy = CookiePolicy::production();
        assert_eq!(policy.name, "__Host-authenc_session");
        assert!(policy.host_prefix, "__Host- is the production spelling");
    }

    #[test]
    fn every_cookie_is_secure_whichever_profile_built_it() {
        // `Secure` is not a profile setting: a session token must never be
        // eligible for a plaintext request, in development or production.
        for policy in [CookiePolicy::development(), CookiePolicy::production()] {
            assert_eq!(
                policy
                    .issue(
                        &SecretToken::from_client("some-token"),
                        time::Duration::hours(1),
                    )
                    .secure(),
                Some(true)
            );
            assert_eq!(policy.revoke().secure(), Some(true));
        }
    }

    #[test]
    fn the_session_cookie_is_never_readable_from_javascript() {
        for policy in [CookiePolicy::development(), CookiePolicy::production()] {
            let cookie = policy.issue(
                &SecretToken::from_client("some-token"),
                time::Duration::hours(1),
            );
            assert_eq!(cookie.http_only(), Some(true));
            assert_eq!(cookie.same_site(), Some(SameSite::Lax));
            assert_eq!(cookie.path(), Some("/"));
        }
    }

    #[test]
    fn revoking_expires_the_cookie_immediately() {
        let cookie = CookiePolicy::development().revoke();
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
    }

    #[test]
    fn a_token_round_trips_through_the_jar() {
        let policy = CookiePolicy::development();
        let jar = CookieJar::new().add(policy.issue(
            &SecretToken::from_client("abc123"),
            time::Duration::hours(1),
        ));
        assert_eq!(policy.read(&jar).unwrap().expose(), "abc123");
    }

    #[test]
    fn no_cookie_means_no_token() {
        assert!(
            CookiePolicy::development()
                .read(&CookieJar::new())
                .is_none()
        );
    }

    #[test]
    fn internal_error_detail_does_not_reach_the_browser() {
        let error = to_server_fn_error(AppError::internal(
            "connecting to postgres://user:hunter2@db:5432",
        ));
        assert!(!error.to_string().contains("hunter2"), "leaked: {error}");
    }

    #[test]
    fn validation_detail_does_reach_the_browser() {
        let error = to_server_fn_error(AppError::field("email", "must contain @"));
        assert!(error.to_string().contains("must contain @"));
    }
}
