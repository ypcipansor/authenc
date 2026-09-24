//! Turning an authorization into tokens.
//!
//! Everything the token endpoint returns is built here, so the
//! authorization-code path and the refresh path cannot drift apart in what
//! they issue or in which claims they attach.
//!
//! Claims follow the granted scopes, not the client's request: a client that
//! was granted `openid` alone gets an ID token with no email in it, even if it
//! asked. The scope set is the authority.

use authenc_contract::{RealmId, Result, UserId, model::User};
use authenc_identity::{Db, user};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    client::{Client, GRANT_REFRESH_TOKEN},
    error::OAuthError,
    keyring::{self, MasterKey},
    refresh,
    scope::{self, EMAIL, OFFLINE_ACCESS, OPENID, PROFILE},
    token::{self, ACCESS_TOKEN_LIFETIME, Claims, Grant, ID_TOKEN_LIFETIME},
};

/// The token endpoint's success response (RFC 6749 §5.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// Always `Bearer`.
    pub token_type: String,
    /// Seconds until the access token expires.
    pub expires_in: i64,
    /// Present when `offline_access` was granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Present when `openid` was granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// The scopes actually granted, which may be narrower than those asked
    /// for. RFC 6749 §5.1 requires this whenever they differ, and returning it
    /// always saves the client from having to notice.
    pub scope: String,
}

/// What to issue.
#[derive(Debug, Clone)]
pub struct Issue<'a> {
    /// The realm.
    pub realm_id: RealmId,
    /// The realm's issuer URL.
    pub issuer: &'a str,
    /// The client the tokens are for.
    pub client: &'a Client,
    /// The user they speak for.
    pub user_id: UserId,
    /// The granted scopes.
    pub scopes: &'a [String],
    /// The `nonce` from the authorization request, for the ID token.
    pub nonce: Option<&'a str>,
    /// How the session behind this authenticated, in RFC 8176 terms.
    pub authenticated_with: &'a [String],
    /// The refresh-token family. New authorizations pass the code's id;
    /// a rotation passes the family it is continuing.
    pub family_id: Uuid,
    /// Whether to mint a refresh token. A rotation has already minted its
    /// own successor and passes `None` here.
    pub refresh: Refresh,
}

/// Whether this issuance also mints a refresh token.
#[derive(Debug, Clone)]
pub enum Refresh {
    /// Mint one if `offline_access` was granted.
    IfGranted,
    /// Return this one, already minted by a rotation.
    Existing(String),
    /// Mint none.
    None,
}

/// Build the token response.
///
/// # Errors
///
/// Returns a protocol error if signing or a database write fails.
pub async fn issue(
    db: &Db,
    master: &MasterKey,
    request: Issue<'_>,
) -> std::result::Result<TokenResponse, OAuthError> {
    let key = keyring::active(db, master, request.realm_id).await?;

    let access_token = token::issue(
        &key,
        &Grant {
            issuer: request.issuer,
            subject: request.user_id,
            audience: &request.client.client_id,
            scopes: request.scopes,
            nonce: None,
            lifetime: ACCESS_TOKEN_LIFETIME,
        },
    )?;

    let id_token = if request.scopes.iter().any(|s| s == OPENID) {
        let user = user::by_id(db, request.user_id).await?;
        Some(token::sign(
            &key,
            &id_claims(&user, &request, ID_TOKEN_LIFETIME),
        )?)
    } else {
        None
    };

    let refresh_token = match request.refresh {
        Refresh::Existing(token) => Some(token),
        Refresh::None => None,
        Refresh::IfGranted if request.scopes.iter().any(|s| s == OFFLINE_ACCESS) => {
            if !request.client.allows_grant(GRANT_REFRESH_TOKEN) {
                None
            } else {
                let minted = refresh::mint(
                    db,
                    refresh::Mint {
                        authenticated_with: request.authenticated_with,
                        client: request.client.key,
                        realm_id: request.realm_id,
                        user_id: request.user_id,
                        scopes: request.scopes,
                        family_id: request.family_id,
                    },
                )
                .await?;
                Some(minted.token.expose().to_owned())
            }
        }
        Refresh::IfGranted => None,
    };

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".to_owned(),
        expires_in: ACCESS_TOKEN_LIFETIME.whole_seconds(),
        refresh_token,
        id_token,
        scope: scope::join(request.scopes),
    })
}

fn id_claims(user: &User, request: &Issue<'_>, lifetime: time::Duration) -> Claims {
    let now = time::OffsetDateTime::now_utc();
    let has = |wanted: &str| request.scopes.iter().any(|s| s == wanted);

    Claims {
        iss: request.issuer.to_owned(),
        sub: user.id.to_string(),
        aud: request.client.client_id.clone(),
        exp: (now + lifetime).unix_timestamp(),
        iat: now.unix_timestamp(),
        nbf: now.unix_timestamp(),
        jti: Uuid::new_v4().to_string(),
        // An ID token describes an authentication, not an authorisation, so
        // it deliberately carries no `scope`.
        scope: None,
        // Echoing the nonce is what binds the ID token to the authorization
        // request the client made, so a token replayed from elsewhere fails
        // the client's own check.
        nonce: request.nonce.map(ToOwned::to_owned),
        // Only on the ID token: an access token describes an authorisation,
        // and how the person proved who they were is not part of that.
        amr: (!request.authenticated_with.is_empty()).then(|| request.authenticated_with.to_vec()),
        preferred_username: has(PROFILE).then(|| user.username.clone()),
        email: has(EMAIL).then(|| user.email.clone()),
        email_verified: has(EMAIL).then_some(user.email_verified),
    }
}

/// The subset of a user's claims that UserInfo returns for a scope set.
///
/// `sub` is always present — OpenID Connect Core §5.3.2 requires it, and a
/// response without it is unusable.
///
/// # Errors
///
/// Returns an internal error if the lookup fails.
pub async fn userinfo(db: &Db, user_id: UserId, scopes: &[String]) -> Result<serde_json::Value> {
    let user = user::by_id(db, user_id).await?;
    let has = |wanted: &str| scopes.iter().any(|s| s == wanted);

    let mut claims = serde_json::Map::new();
    claims.insert("sub".to_owned(), user.id.to_string().into());

    if has(PROFILE) {
        claims.insert(
            "preferred_username".to_owned(),
            user.username.clone().into(),
        );
        claims.insert("name".to_owned(), user.display_name().into());
        if let Some(first) = &user.first_name {
            claims.insert("given_name".to_owned(), first.clone().into());
        }
        if let Some(last) = &user.last_name {
            claims.insert("family_name".to_owned(), last.clone().into());
        }
    }
    if has(EMAIL) {
        claims.insert("email".to_owned(), user.email.clone().into());
        claims.insert("email_verified".to_owned(), user.email_verified.into());
    }

    Ok(serde_json::Value::Object(claims))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed setup step should fail the test"
)]
mod tests {
    use super::*;
    use crate::test_support;

    /// The `amr` of an ordinary password login, which is what these fixtures
    /// stand in for. The MFA variants are exercised in `authenc-identity`.
    ///
    /// A `static` rather than a function: the structs below borrow it, and a
    /// freshly built `Vec` would not outlive the expression that borrows it.
    static PWD: std::sync::LazyLock<Vec<String>> =
        std::sync::LazyLock::new(|| vec!["pwd".to_owned()]);
    use crate::client::{self, NewClient};
    use authenc_identity::{PasswordHasher, realm, user::NewUser};

    const ISSUER: &str = "https://id.example.com/realms/master";

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    struct Fixture {
        realm_id: RealmId,
        user_id: UserId,
        client: Client,
        master: MasterKey,
    }

    async fn fixture(db: &Db) -> Fixture {
        let hasher = PasswordHasher::new();
        let realm = realm::create(db, "master", "Master").await.unwrap();
        let user = user::create(
            db,
            &hasher,
            NewUser {
                realm_id: realm.id,
                username: "ada",
                email: "ada@example.com",
                password: test_support::password(),
                first_name: Some("Ada"),
                last_name: Some("Lovelace"),
            },
        )
        .await
        .unwrap();

        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&[OPENID, PROFILE, EMAIL, OFFLINE_ACCESS]);
        let registered = client::register(
            db,
            &hasher,
            NewClient {
                realm_id: realm.id,
                client_id: Some("app"),
                name: "App",
                is_public: true,
                redirect_uris: &uris,
                grant_types: &[],
                scopes: &scopes,
                require_consent: false,
            },
        )
        .await
        .unwrap();

        Fixture {
            realm_id: realm.id,
            user_id: user.id,
            client: registered.client,
            master: MasterKey::generate().unwrap(),
        }
    }

    fn request<'a>(f: &'a Fixture, scopes: &'a [String]) -> Issue<'a> {
        Issue {
            authenticated_with: &PWD,
            realm_id: f.realm_id,
            issuer: ISSUER,
            client: &f.client,
            user_id: f.user_id,
            scopes,
            nonce: Some("n-0S6_WzA2Mj"),
            family_id: Uuid::new_v4(),
            refresh: Refresh::IfGranted,
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_access_token_verifies_against_the_published_key(db: Db) {
        let f = fixture(&db).await;
        let scopes = owned(&[OPENID]);
        let response = issue(&db, &f.master, request(&f, &scopes)).await.unwrap();

        let kid = token::kid_of(&response.access_token).unwrap();
        let public = keyring::verifying_key(&db, &kid).await.unwrap().unwrap();

        let claims = token::verify(
            &response.access_token,
            &public,
            token::Expected {
                issuer: ISSUER,
                audience: "app",
            },
        )
        .unwrap();

        assert_eq!(claims.sub, f.user_id.to_string());
        assert_eq!(claims.scope.as_deref(), Some("openid"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_id_token_echoes_the_nonce_it_was_asked_with(db: Db) {
        // Without this the client cannot tell its own authorization apart from
        // one replayed by someone else.
        let f = fixture(&db).await;
        let scopes = owned(&[OPENID]);
        let response = issue(&db, &f.master, request(&f, &scopes)).await.unwrap();

        let id_token = response.id_token.unwrap();
        let kid = token::kid_of(&id_token).unwrap();
        let public = keyring::verifying_key(&db, &kid).await.unwrap().unwrap();
        let claims = token::verify(
            &id_token,
            &public,
            token::Expected {
                issuer: ISSUER,
                audience: "app",
            },
        )
        .unwrap();

        assert_eq!(claims.nonce.as_deref(), Some("n-0S6_WzA2Mj"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn claims_follow_the_granted_scopes_and_not_the_request(db: Db) {
        let f = fixture(&db).await;

        let narrow = owned(&[OPENID]);
        let response = issue(&db, &f.master, request(&f, &narrow)).await.unwrap();
        let claims = decode(&db, &response.id_token.unwrap()).await;
        assert!(
            claims.email.is_none(),
            "email leaked without the email scope"
        );
        assert!(claims.preferred_username.is_none());

        let wide = owned(&[OPENID, PROFILE, EMAIL]);
        let response = issue(&db, &f.master, request(&f, &wide)).await.unwrap();
        let claims = decode(&db, &response.id_token.unwrap()).await;
        assert_eq!(claims.email.as_deref(), Some("ada@example.com"));
        assert_eq!(claims.preferred_username.as_deref(), Some("ada"));
    }

    async fn decode(db: &Db, jwt: &str) -> Claims {
        let kid = token::kid_of(jwt).unwrap();
        let public = keyring::verifying_key(db, &kid).await.unwrap().unwrap();
        token::verify(
            jwt,
            &public,
            token::Expected {
                issuer: ISSUER,
                audience: "app",
            },
        )
        .unwrap()
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn no_openid_scope_means_no_id_token(db: Db) {
        let f = fixture(&db).await;
        let scopes = owned(&[PROFILE]);
        let response = issue(&db, &f.master, request(&f, &scopes)).await.unwrap();
        assert!(response.id_token.is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_refresh_token_is_only_minted_when_offline_access_was_granted(db: Db) {
        let f = fixture(&db).await;

        let without = owned(&[OPENID]);
        assert!(
            issue(&db, &f.master, request(&f, &without))
                .await
                .unwrap()
                .refresh_token
                .is_none(),
        );

        let with = owned(&[OPENID, OFFLINE_ACCESS]);
        assert!(
            issue(&db, &f.master, request(&f, &with))
                .await
                .unwrap()
                .refresh_token
                .is_some(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_response_states_what_was_actually_granted(db: Db) {
        let f = fixture(&db).await;
        let scopes = owned(&[OPENID, EMAIL]);
        let response = issue(&db, &f.master, request(&f, &scopes)).await.unwrap();
        assert_eq!(response.scope, "openid email");
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, ACCESS_TOKEN_LIFETIME.whole_seconds());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn userinfo_always_carries_sub_and_nothing_the_scopes_did_not_allow(db: Db) {
        let f = fixture(&db).await;

        let bare = userinfo(&db, f.user_id, &owned(&[OPENID])).await.unwrap();
        assert_eq!(bare["sub"], f.user_id.to_string());
        assert!(bare.get("email").is_none());
        assert!(bare.get("preferred_username").is_none());

        let full = userinfo(&db, f.user_id, &owned(&[OPENID, PROFILE, EMAIL]))
            .await
            .unwrap();
        assert_eq!(full["preferred_username"], "ada");
        assert_eq!(full["name"], "Ada Lovelace");
        assert_eq!(full["email"], "ada@example.com");
        assert_eq!(full["email_verified"], false);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_client_not_registered_for_refresh_does_not_get_one(db: Db) {
        // Discovery says which grants exist; the client record says which this
        // client may use. Minting a token it can never redeem is worse than
        // useless — it is a long-lived credential nobody is watching.
        let mut f = fixture(&db).await;
        f.client.grant_types = owned(&[client::GRANT_AUTHORIZATION_CODE]);

        let scopes = owned(&[OPENID, OFFLINE_ACCESS]);
        let response = issue(&db, &f.master, request(&f, &scopes)).await.unwrap();
        assert!(response.refresh_token.is_none());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_id_token_says_how_the_user_authenticated(db: Db) {
        // The whole point of carrying `amr`: a relying party has to be able to
        // tell a password-only sign-in from one behind a second factor.
        let f = fixture(&db).await;
        let scopes = vec![OPENID.to_owned()];

        let mfa = vec!["pwd".to_owned(), "otp".to_owned(), "mfa".to_owned()];
        let issued = issue(
            &db,
            &f.master,
            Issue {
                authenticated_with: &mfa,
                ..request(&f, &scopes)
            },
        )
        .await
        .unwrap();

        let claims = decode(&db, issued.id_token.as_deref().unwrap()).await;
        assert_eq!(claims.amr, Some(mfa));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_access_token_carries_no_amr(db: Db) {
        // It describes what a client may do, not how the person proved who
        // they were. Putting `amr` there would invite a resource server to
        // make an authentication decision from an authorisation credential.
        let f = fixture(&db).await;
        let scopes = vec![OPENID.to_owned()];

        let issued = issue(&db, &f.master, request(&f, &scopes)).await.unwrap();
        let claims = decode(&db, &issued.access_token).await;

        assert_eq!(claims.amr, None);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_amr_is_absent_rather_than_empty(db: Db) {
        // An empty array asserts "no methods were used", which is a claim.
        // Silence is not, and silence is the honest answer.
        let f = fixture(&db).await;
        let scopes = vec![OPENID.to_owned()];

        let issued = issue(
            &db,
            &f.master,
            Issue {
                authenticated_with: &[],
                ..request(&f, &scopes)
            },
        )
        .await
        .unwrap();

        let claims = decode(&db, issued.id_token.as_deref().unwrap()).await;
        assert_eq!(claims.amr, None);

        let rendered = serde_json::to_string(&claims).unwrap();
        assert!(!rendered.contains("amr"), "{rendered}");
    }
}
