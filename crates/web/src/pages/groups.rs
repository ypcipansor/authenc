//! The group tree.
//!
//! Groups are shown flat and indented rather than as a collapsible tree. The
//! server already returns them ordered by path, so indentation reproduces the
//! hierarchy exactly, and a flat list is what makes the roles and member counts
//! comparable down a column — which is the question an administrator opens this
//! page to answer ("who gets what through nesting?").

use authenc_contract::{GroupId, Permission};
use leptos::prelude::*;

use crate::{
    api,
    pages::admin::Session,
    ui::{Badge, Button, Card, Cell, DataTable, ErrorBanner, Field, Select, Variant},
};

/// The value the parent selector carries for "no parent".
const ROOT: &str = "";

/// Group management.
#[component]
pub fn Groups() -> impl IntoView {
    let session = expect_context::<Session>().0;
    let error = RwSignal::new(None::<String>);

    let create = ServerAction::<api::CreateGroup>::new();
    let remove = ServerAction::<api::DeleteGroup>::new();

    let groups = Resource::new(
        move || (create.version().get(), remove.version().get()),
        |_| api::list_groups(),
    );

    Effect::new(move |_| {
        let failures = [
            create.value().get().map(|result| result.map(|_| ())),
            remove.value().get(),
        ];
        error.set(
            failures
                .into_iter()
                .flatten()
                .find_map(Result::err)
                .map(|failure| api::describe(&failure)),
        );
    });

    let can_write = Signal::derive(move || {
        session
            .get()
            .and_then(Result::ok)
            .flatten()
            .is_some_and(|me| me.can(Permission::GroupWrite))
    });

    // The parent selector offers every existing group, so a new one can be
    // nested at creation time rather than created at the root and then moved.
    let parents = Signal::derive(move || {
        let mut options = vec![(ROOT.to_owned(), "— top level —".to_owned())];
        options.extend(
            groups
                .get()
                .and_then(Result::ok)
                .unwrap_or_default()
                .into_iter()
                .map(|group| (group.id.to_string(), group.path)),
        );
        options
    });

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Groups"
            </h1>

            <p class="max-w-2xl text-sm text-ink-600 dark:text-ink-400">
                "A member of a group holds the roles granted to it and to every group above it. \
                 Nesting therefore widens what the child's members can do, never the parent's."
            </p>

            <ErrorBanner message=error />

            // The form and the table share one suspense boundary because both
            // read the same resource. The parent dropdown's options are built
            // from the loaded groups, so rendering the form outside the
            // boundary made the server emit one option and the hydrating
            // client render two — an SSR/hydration mismatch that aborts
            // hydration for the entire page, table included.
            <Transition fallback=|| {
                view! { <p class="text-sm text-ink-500">"Loading groups…"</p> }
            }>
                {move || Suspend::new(async move {
                    let list = match groups.await {
                        Ok(list) => list,
                        Err(failure) => {
                            let message = api::describe(&failure);
                            return view! { <ErrorBanner message=Some(message) /> }.into_any();
                        }
                    };

                    let rows = Signal::derive(move || list.clone());

                    view! {
                        <div class="flex flex-col gap-6">
                            <Show when=move || can_write.get()>
                                <CreateGroupForm create=create parents=parents />
                            </Show>

                            <DataTable
                                headers=vec!["Group", "Roles", "Members", ""]
                                rows=rows
                                key=|group: &api::GroupSummary| group.id
                                noun="groups"
                                row=move |group: api::GroupSummary| {
                                    view! {
                                        <GroupRow
                                            group=group
                                            can_write=can_write
                                            remove=remove
                                        />
                                    }
                                }
                            />
                        </div>
                    }
                        .into_any()
                })}
            </Transition>
        </div>
    }
}

/// One row of the group table.
#[component]
fn GroupRow(
    /// The group this row shows.
    group: api::GroupSummary,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// The delete action.
    remove: ServerAction<api::DeleteGroup>,
) -> impl IntoView {
    let id = group.id;
    let name = group.name.clone();
    let path = group.path.clone();
    let members = group.members;

    // `<Show>` calls its children on every re-evaluation, so both closures below
    // must be `Fn`. `StoredValue` is `Copy`; a moved `Vec` would be `FnOnce`.
    let roles = StoredValue::new(group.roles.clone());

    // Indent by nesting depth. Inline rather than a Tailwind `pl-*` class,
    // because that would have to be one of a fixed set and the tree has no
    // fixed maximum depth.
    let indent = format!("padding-left: {}rem", group.depth as f32 * 1.25);

    view! {
        <Cell>
            <div style=indent>
                <span class="font-medium text-ink-900 dark:text-ink-100">{name}</span>
                <span class="ml-2 text-xs text-ink-500">{path}</span>
            </div>
        </Cell>
        <Cell>
            <Show
                when=move || !roles.read_value().is_empty()
                fallback=|| view! { <span class="text-ink-500">"—"</span> }
            >
                <div class="flex flex-wrap gap-1">
                    {roles
                        .get_value()
                        .into_iter()
                        .map(|role| view! { <Badge ok=true label=role /> })
                        .collect_view()}
                </div>
            </Show>
        </Cell>
        <Cell>{members}</Cell>
        <Cell>
            <Show when=move || can_write.get()>
                <Button
                    variant=Variant::Danger
                    on_click=Callback::new(move |()| {
                        remove.dispatch(api::DeleteGroup { id });
                    })
                >
                    "Delete"
                </Button>
            </Show>
        </Cell>
    }
}

/// The form for adding a group.
#[component]
fn CreateGroupForm(
    /// The create action.
    create: ServerAction<api::CreateGroup>,
    /// Groups that may be chosen as the parent.
    parents: Signal<Vec<(String, String)>>,
) -> impl IntoView {
    let name = RwSignal::new(String::new());
    let parent = RwSignal::new(ROOT.to_owned());

    // The same two rules `identity::group::create` enforces, so a name it will
    // refuse cannot be submitted.
    let ready = Signal::derive(move || {
        let name = name.get();
        let trimmed = name.trim();
        !trimmed.is_empty() && !trimmed.contains('/')
    });

    let pending = create.pending();

    Effect::new(move |_| {
        if matches!(create.value().get(), Some(Ok(_))) {
            name.set(String::new());
        }
    });

    view! {
        <Card title="Add a group">
            <form
                class="grid gap-4 sm:grid-cols-3 sm:items-end"
                on:submit=move |ev| {
                    ev.prevent_default();
                    create
                        .dispatch(api::CreateGroup {
                            parent_id: parent.get_untracked().parse::<GroupId>().ok(),
                            name: name.get_untracked().trim().to_owned(),
                        });
                }
            >
                <Field label="Name" name="new-group-name" value=name />
                <Select label="Parent" name="new-group-parent" value=parent options=parents />
                <Button
                    kind="submit"
                    disabled=Signal::derive(move || pending.get() || !ready.get())
                >
                    "Create"
                </Button>
            </form>
        </Card>
    }
}
