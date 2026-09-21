//! Sign-in page.

use authenc_contract::{
    model::{LoginOutcome, LoginRequest, SecondFactor, SecondFactorPrompt},
    validate,
};
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};

use crate::{
    api,
    ui::{Button, Card, ErrorBanner, Field},
};

/// Where to go after signing in.
///
/// Only a path on this origin is ever honoured. A `next` of
/// `https://evil.test/` — or the sneakier `//evil.test/`, which a browser
/// resolves as protocol-relative — would otherwise turn the login page into an
/// open redirect that arrives wearing this domain's name.
///
/// A backslash is refused for the same reason as a second slash: browsers
/// treat `/\evil.test` as protocol-relative too. So are control characters and
/// spaces, and that part is not decoration — a browser strips tab, newline,
/// and carriage return from a URL *before* parsing it, so `/<TAB>/evil.test`
/// passes any rule that only inspects the second character and then arrives at
/// the parser as `//evil.test`. This is the same rule the
/// `federation_login_states.return_to` constraint enforces in the database;
/// two copies of one rule, and a test on each, because the two paths are
/// reached separately.
fn safe_next(raw: Option<String>) -> String {
    raw.filter(|value| is_same_origin_path(value))
        .unwrap_or_else(|| "/".to_owned())
}

/// Whether this is a path on this site and nothing else.
fn is_same_origin_path(value: &str) -> bool {
    let mut characters = value.chars();
    if characters.next() != Some('/') {
        return false;
    }
    match characters.next() {
        None => true,
        Some('/' | '\\') => false,
        Some(first) if first.is_control() || first == ' ' => false,
        Some(_) => !value.chars().any(|c| c.is_control() || c == ' '),
    }
}

/// What to tell somebody whose sign-in was refused.
///
/// `AppError::Unauthenticated` reads "authentication required" on the wire,
/// which is the right thing for a client to branch on and the wrong thing to
/// show a person who has just typed a password: it names the failure without
/// naming the remedy. The same message covers an unknown user, a wrong
/// password, and a disabled account — deliberately, so the page cannot be used
/// to discover which usernames exist — so the wording must fit all three.
fn login_failure(failure: &ServerFnError) -> String {
    match api::describe(failure).as_str() {
        "authentication required" => {
            "That realm, username, or password did not match an account.".to_owned()
        }
        "too many requests" => {
            "Too many attempts. Wait a moment, then try again.".to_owned()
        }
        other => other.to_owned(),
    }
}

/// The sign-in page: a password, and then a second factor if one is enrolled.
///
/// Split into two components because the two steps are two different things.
/// The alternative — one component with a `show_code` flag — is how a page ends
/// up rendering the code field and the password field at once, and how "did the
/// server actually ask for a second factor?" turns into a boolean the page can
/// set for itself.
#[component]
pub fn Login() -> impl IntoView {
    // `None` until the server says which step we are on. Nothing here decides
    // whether a second factor is required; the server does, and this only
    // renders the answer.
    let prompt = RwSignal::new(None::<SecondFactorPrompt>);

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <Show
                when=move || prompt.get().is_some()
                fallback=move || view! { <PasswordStep prompt=prompt /> }
            >
                <SecondFactorStep prompt=prompt />
            </Show>
        </main>
    }
}

/// Step one: realm, identifier, password.
#[component]
fn PasswordStep(prompt: RwSignal<Option<SecondFactorPrompt>>) -> impl IntoView {
    let query = use_query_map();
    let next = Signal::derive(move || safe_next(query.get().get("next")));

    let realm = RwSignal::new("master".to_owned());
    let identifier = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());

    let submit = ServerAction::<api::LogIn>::new();

    // `RwSignal` rather than a split `(read, write)` pair: the previous console
    // declared 121 separate `create_signal`s, fifteen of them in one form.
    let error = RwSignal::new(None::<String>);

    // The same validation the server runs, from `authenc-contract`. One
    // implementation, so the button and the database cannot disagree.
    let can_submit = Signal::derive(move || {
        !identifier.get().trim().is_empty()
            && !password.get().is_empty()
            && validate::realm_name(&realm.get()).is_ok()
    });

    Effect::new(move |_| {
        let Some(result) = submit.value().get() else {
            return;
        };
        match result {
            Ok(LoginOutcome::Complete(_)) => {
                error.set(None);
                // A full navigation, so the server re-renders with the new
                // session cookie in place. `next` brings an interrupted OAuth
                // authorization request back to where it left off.
                use_navigate()(&next.get_untracked(), Default::default());
            }
            // Not signed in. The session cookie was not set, and the only thing
            // this page received is what to ask for next.
            Ok(LoginOutcome::SecondFactorRequired(asked)) => {
                error.set(None);
                prompt.set(Some(asked));
            }
            Err(failure) => error.set(Some(login_failure(&failure))),
        }
    });

    let pending = submit.pending();

    view! {
        <>
            <header class="text-center">
                <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                    "Sign in"
                </h1>
            </header>

            <Card>
                <form
                    class="flex flex-col gap-4"
                    on:submit=move |ev| {
                        ev.prevent_default();
                        submit
                            .dispatch(api::LogIn {
                                request: LoginRequest {
                                    realm: realm.get_untracked(),
                                    identifier: identifier.get_untracked(),
                                    password: password.get_untracked(),
                                },
                            });
                    }
                >
                    <ErrorBanner message=error />

                    <Field label="Realm" name="realm" value=realm autocomplete="organization" />
                    <Field
                        label="Username or email"
                        name="identifier"
                        value=identifier
                        autocomplete="username"
                    />
                    <Field
                        label="Password"
                        name="password"
                        value=password
                        kind="password"
                        autocomplete="current-password"
                    />

                    <Button kind="submit" disabled=Signal::derive(move || {
                        pending.get() || !can_submit.get()
                    })>
                        {move || if pending.get() { "Signing in…" } else { "Sign in" }}
                    </Button>
                </form>
            </Card>

            <SocialButtons realm=realm next=next />
        </>
    }
}

/// The "continue with …" buttons, one per provider the realm offers.
///
/// Plain links, not a `fetch`. A social sign-in is a *top-level navigation*,
/// which is what makes the `SameSite=Lax` state cookie survive the provider's
/// redirect back here — an XHR would not carry it, and the callback would
/// refuse every time.
#[component]
fn SocialButtons(
    /// The realm typed into the form above. Buttons follow it.
    realm: RwSignal<String>,
    /// Where to return after signing in.
    next: Signal<String>,
) -> impl IntoView {
    let providers = Resource::new(
        move || realm.get(),
        |realm| async move {
            // An unknown realm answers with an empty list rather than an
            // error, so a typo in the field shows no buttons rather than a
            // failure message that would confirm which realms exist.
            api::sign_in_providers(realm).await.unwrap_or_default()
        },
    );

    view! {
        <Transition fallback=|| ()>
            {move || Suspend::new(async move {
                let offered = providers.await;
                if offered.is_empty() {
                    return ().into_any();
                }

                let realm_name = realm.get_untracked();
                let return_to = next.get_untracked();

                view! {
                    <div class="flex flex-col gap-3">
                        <div class="flex items-center gap-3">
                            <hr class="flex-1 border-ink-200 dark:border-ink-800" />
                            <span class="text-xs uppercase tracking-wide text-ink-500">"or"</span>
                            <hr class="flex-1 border-ink-200 dark:border-ink-800" />
                        </div>
                        {offered
                            .into_iter()
                            .map(|provider| {
                                let href = start_url(&realm_name, &provider.alias, &return_to);
                                view! {
                                    <a
                                        class="flex items-center justify-center rounded-md px-3 py-2 \
                                               text-sm font-semibold text-ink-800 ring-1 ring-inset \
                                               ring-ink-300 hover:bg-surface-100 \
                                               dark:text-ink-100 dark:ring-ink-700 \
                                               dark:hover:bg-surface-800"
                                        href=href
                                    >
                                        {format!("Continue with {}", provider.display_name)}
                                    </a>
                                }
                            })
                            .collect_view()}
                    </div>
                }
                    .into_any()
            })}
        </Transition>
    }
}

/// Where a provider button points.
///
/// `return_to` is passed through, and the server refuses anything that is not
/// a path on this site — the check is the column's, so a caller that forgets
/// it cannot create an open redirect.
fn start_url(realm: &str, alias: &str, return_to: &str) -> String {
    let realm = urlencode(realm);
    let alias = urlencode(alias);
    let return_to = urlencode(return_to);
    format!("/realms/{realm}/federation/{alias}/start?return_to={return_to}")
}

/// Percent-encode one path or query segment.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// Step two: the second factor.
///
/// The pending login is identified by an `HttpOnly` cookie the server set, so
/// nothing on this page holds a credential and nothing it submits names whose
/// login to finish.
#[component]
fn SecondFactorStep(prompt: RwSignal<Option<SecondFactorPrompt>>) -> impl IntoView {
    let query = use_query_map();
    let next = Signal::derive(move || safe_next(query.get().get("next")));

    let code = RwSignal::new(String::new());
    let use_recovery = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    let submit = ServerAction::<api::SubmitSecondFactor>::new();
    let cancel = ServerAction::<api::CancelSecondFactor>::new();

    Effect::new(move |_| {
        let Some(result) = submit.value().get() else {
            return;
        };
        match result {
            Ok(_) => {
                error.set(None);
                use_navigate()(&next.get_untracked(), Default::default());
            }
            Err(failure) => {
                code.set(String::new());
                error.set(Some(api::describe(&failure)));
            }
        }
    });

    Effect::new(move |_| {
        if cancel.value().get().is_some() {
            prompt.set(None);
        }
    });

    let pending = submit.pending();
    let username = Signal::derive(move || prompt.get().map(|p| p.username).unwrap_or_default());
    let offers_recovery = Signal::derive(move || prompt.get().is_some_and(|p| p.recovery_code));
    let offers_totp = Signal::derive(move || prompt.get().is_some_and(|p| p.totp));

    view! {
        <>
            <header class="text-center">
                <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                    "Two-step verification"
                </h1>
                <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
                    "Signing in as " <span class="font-medium">{username}</span>
                </p>
            </header>

            <Card>
                <form
                    class="flex flex-col gap-4"
                    on:submit=move |ev| {
                        ev.prevent_default();
                        let entered = code.get_untracked();
                        let factor = if use_recovery.get_untracked() {
                            SecondFactor::RecoveryCode { code: entered }
                        } else {
                            SecondFactor::Totp { code: entered }
                        };
                        submit.dispatch(api::SubmitSecondFactor { factor });
                    }
                >
                    <ErrorBanner message=error />

                    <Show
                        when=move || use_recovery.get()
                        fallback=move || {
                            view! {
                                <Field
                                    label="Authenticator code"
                                    name="code"
                                    value=code
                                    autocomplete="one-time-code"
                                />
                            }
                        }
                    >
                        <Field
                            label="Recovery code"
                            name="recovery_code"
                            value=code
                            autocomplete="off"
                        />
                    </Show>

                    <Button kind="submit" disabled=Signal::derive(move || {
                        pending.get() || code.get().trim().is_empty()
                    })>
                        {move || if pending.get() { "Verifying…" } else { "Verify" }}
                    </Button>
                </form>

                <div class="mt-4 flex flex-col gap-2 text-sm">
                    <Show when=move || offers_recovery.get() && offers_totp.get()>
                        <button
                            type="button"
                            class="text-brand-600 hover:underline dark:text-brand-400"
                            on:click=move |_| {
                                code.set(String::new());
                                error.set(None);
                                use_recovery.update(|value| *value = !*value);
                            }
                        >
                            {move || {
                                if use_recovery.get() {
                                    "Use an authenticator code instead"
                                } else {
                                    "Use a recovery code instead"
                                }
                            }}
                        </button>
                    </Show>
                    <button
                        type="button"
                        class="text-ink-600 hover:underline dark:text-ink-400"
                        on:click=move |_| {
                            cancel.dispatch(api::CancelSecondFactor {});
                        }
                    >
                        "Start over"
                    </button>
                </div>
            </Card>
        </>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_path_on_this_origin_is_followed_after_signing_in() {
        assert_eq!(safe_next(Some("/admin/users".to_owned())), "/admin/users");
        assert_eq!(
            safe_next(Some(
                "/realms/master/protocol/openid-connect/auth?x=1".to_owned()
            )),
            "/realms/master/protocol/openid-connect/auth?x=1",
        );

        // A *percent-encoded* backslash stays a path: a URL parser does not
        // decode it before determining the origin, so refusing it would only
        // break legitimate links.
        assert_eq!(
            safe_next(Some("/files/%5Creport.pdf".to_owned())),
            "/files/%5Creport.pdf"
        );

        // Each of these would send the user somewhere else entirely, having
        // arrived at a link on this domain.
        for hostile in [
            "https://evil.test/",
            "//evil.test/",
            "http://evil.test",
            "javascript:alert(1)",
            "evil.test",
            // A backslash is protocol-relative to a browser too.
            "/\\evil.test",
            // And these are the ones a rule that only reads the second
            // character misses: a browser strips tab, newline, and carriage
            // return *before* parsing, so each of these reaches the parser as
            // `//evil.test`.
            "/\t/evil.test",
            "/\n/evil.test",
            "/\r/evil.test",
        ] {
            assert_eq!(
                safe_next(Some(hostile.to_owned())),
                "/",
                "followed: {hostile}",
            );
        }

        assert_eq!(safe_next(None), "/");
    }
}
