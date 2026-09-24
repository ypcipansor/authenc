//! Session cookies, request authentication, and CSRF.

use authenc_contract::{AppError, Result, model::Actor};
use authenc_identity::{
    Db,
    session::{self, Session},
    user,
};
use authenc_web::server_ctx::CookiePolicy;
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, Method, header, request::Parts},
};
use axum_extra::extract::cookie::CookieJar;

use crate::{config::Config, error::ApiError};

/// Header a client uses to present its CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Derive the cookie policy from configuration.
#[must_use]
pub fn cookie_policy(config: &Config) -> CookiePolicy {
    if config.profile.is_production() {
        CookiePolicy::production()
    } else {
        CookiePolicy::development()
    }
}

/// Resolve the session a request carries, if it carries a live one.
///
/// # Errors
///
/// Returns an internal error if the lookup fails. An absent or expired session
/// is `Ok(None)`, not an error — that is simply an anonymous request.
pub async fn session_for(
    db: &Db,
    policy: CookiePolicy,
    jar: &CookieJar,
) -> Result<Option<Session>> {
    let Some(token) = policy.read(jar) else {
        return Ok(None);
    };
    session::lookup(db, &token).await
}

/// Build the [`Actor`] for a session.
///
/// Roles are resolved here, at the point of use, from the database. They are
/// deliberately not carried in a token: the previous system minted tokens with
/// `roles: None` and then checked `roles.contains("admin")`, so no token it
/// issued could ever satisfy an admin check.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if the session points at a user that no
/// longer exists, or an internal error if a query fails.
pub async fn actor_for(db: &Db, session: &Session) -> Result<Actor> {
    let user = user::by_id(db, session.user_id).await?;

    // A disabled account must stop working immediately, even if its session
    // row still exists.
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
}

/// An authenticated caller: a session cookie, or an API token.
///
/// Used by the HTTP surface. Server functions get the same thing through
/// [`crate::http`]'s context rather than through an extractor.
///
/// # Why two credentials produce one type
///
/// Downstream code takes an [`Actor`] and checks it. It cannot tell whether a
/// person or a token is behind it, and that is the point: every rule already
/// written — realm isolation, disabled accounts, permission checks — applies
/// to a token without being restated for it. `authenticate` narrows a token's
/// authority to the intersection of its grant and what the bound account holds
/// now, so the `Actor` it produces is never more than a person's would be.
///
/// # Why a token skips CSRF
///
/// CSRF is a browser problem: it exists because a browser attaches a cookie to
/// a request the user did not intend. A token is attached by the client that
/// holds it, deliberately, and is never sent automatically — so there is
/// nothing to forge. Requiring a CSRF header from a Terraform provider would
/// be ceremony that protects nobody.
///
/// The cookie path keeps its CSRF check exactly as before, and a request
/// carrying *both* a token and a cookie is treated as a token request — the
/// `Authorization` header is the deliberate one.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub Actor);

/// The bearer token a request presents, if any.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
    Db: axum::extract::FromRef<S>,
    std::sync::Arc<Config>: axum::extract::FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        use axum::extract::FromRef;

        let db = Db::from_ref(state);
        let config = std::sync::Arc::<Config>::from_ref(state);
        let policy = cookie_policy(&config);
        let jar = CookieJar::from_headers(&parts.headers);

        // An API token first: it is the deliberate credential, and a client
        // that sends one means it even if a cookie happens to ride along.
        if let Some(presented) = bearer(&parts.headers) {
            let actor = authenc_identity::api_token::authenticate(&db, presented)
                .await
                .map_err(ApiError)?
                .ok_or(ApiError(AppError::Unauthenticated))?;
            return Ok(Self(actor));
        }

        let session = session_for(&db, policy, &jar)
            .await
            .map_err(ApiError)?
            .ok_or(ApiError(AppError::Unauthenticated))?;

        // A state-changing request must also carry a matching CSRF token.
        verify_csrf(&parts.method, &parts.headers, &session).map_err(ApiError)?;

        let actor = actor_for(&db, &session).await.map_err(ApiError)?;
        Ok(Self(actor))
    }
}

/// The caller's raw session, without the CSRF requirement.
///
/// Used only by the endpoint that hands out the CSRF token, which is a `GET`
/// and therefore changes nothing. Everything else takes [`CurrentUser`].
#[derive(Debug, Clone)]
pub struct CurrentSession(pub Session);

impl<S> FromRequestParts<S> for CurrentSession
where
    S: Send + Sync,
    Db: axum::extract::FromRef<S>,
    std::sync::Arc<Config>: axum::extract::FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        use axum::extract::FromRef;

        let db = Db::from_ref(state);
        let config = std::sync::Arc::<Config>::from_ref(state);
        let jar = CookieJar::from_headers(&parts.headers);

        session_for(&db, cookie_policy(&config), &jar)
            .await
            .map_err(ApiError)?
            .map(Self)
            .ok_or(ApiError(AppError::Unauthenticated))
    }
}

/// Reject a state-changing request that does not present this session's CSRF
/// token.
///
/// Safe methods are exempt because they must not change anything in the first
/// place. The token is bound to the session, so one minted elsewhere does not
/// validate here — the previous implementation accepted any string of 32
/// characters or more, with no server-side state at all.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] if the token is absent or does not match.
pub fn verify_csrf(method: &Method, headers: &HeaderMap, session: &Session) -> Result<()> {
    if matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return Ok(());
    }

    let presented = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;

    if session.csrf_token_matches(presented) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Whether a state-changing request came from our own origin.
///
/// `Sec-Fetch-Site` is set by the browser and cannot be forged by page script;
/// `Origin` is the fallback for browsers that do not send it, and is likewise
/// unforgeable. A request carrying neither is not a browser, so it cannot be a
/// forged one, and it passes through to whatever authenticates it.
///
/// This is the CSRF gate for `/api/sfn` — see `http::refuse_cross_origin`,
/// which is the only caller — and defence in depth for `/api/v1`, where the
/// session-bound token in `verify_csrf` is the gate. The two surfaces differ
/// because the Leptos client sends no header of ours, so a token requirement
/// on server functions would refuse the console itself.
#[must_use]
pub fn is_same_origin(headers: &HeaderMap, expected_origin: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return matches!(site, "same-origin" | "none");
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(origin) => origin == expected_origin,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    // Cookie-flag behaviour is tested where the policy lives, in
    // `authenc_web::server_ctx`. What belongs here is the mapping from
    // configuration to policy, and the origin check.

    #[test]
    fn only_production_gets_the_host_prefix() {
        for profile in [Profile::Development, Profile::Test] {
            let config = Config {
                profile,
                ..Config::default()
            };
            assert_eq!(cookie_policy(&config).name, "authenc_session");
            assert!(!cookie_policy(&config).host_prefix);
        }

        let config = Config {
            profile: Profile::Production,
            ..Config::default()
        };
        assert_eq!(cookie_policy(&config).name, "__Host-authenc_session");
        assert!(cookie_policy(&config).host_prefix);
    }

    #[test]
    fn same_origin_detection_trusts_sec_fetch_site_over_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        headers.insert(header::ORIGIN, "https://id.example.com".parse().unwrap());

        assert!(
            !is_same_origin(&headers, "https://id.example.com"),
            "Sec-Fetch-Site is set by the browser and page script cannot forge it",
        );
    }

    #[test]
    fn same_origin_falls_back_to_the_origin_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!is_same_origin(&headers, "https://id.example.com"));

        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://id.example.com".parse().unwrap());
        assert!(is_same_origin(&headers, "https://id.example.com"));
    }

    #[test]
    fn a_request_with_neither_header_is_left_to_the_token_check() {
        assert!(is_same_origin(&HeaderMap::new(), "https://id.example.com"));
    }
}
