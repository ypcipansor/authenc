-- Demo data for the screenshots in docs/screenshots/.
--
-- Everything here is invented. It exists so the console pages have something
-- to render: a few users, a role that is not the seeded administrator, a group
-- tree, an organisation, a social provider, and some audit history. Apply it
-- with `just demo-data`, which is idempotent — running it twice changes
-- nothing.
--
-- Passwords are NOT set here. Create the accounts through the CLI so that the
-- Argon2 parameters and the password policy are the ones the application uses;
-- this file only adds the rows that make the pages interesting.

BEGIN;

-- The seeded administrator, plus a handful of colleagues.
INSERT INTO users (realm_id, username, email, email_verified, first_name, last_name, enabled)
SELECT r.id, v.username, v.email, v.email_verified, v.first_name, v.last_name, v.enabled
FROM realms r
CROSS JOIN (VALUES
    ('admin',   'admin@example.com',   true,  'Ada',    'Administrator', true),
    ('alice',   'alice@example.com',   true,  'Alice',  'Nguyen',        true),
    ('bob',     'bob@example.com',     false, 'Bob',    'Okafor',        true),
    ('carol',   'carol@example.com',   true,  'Carol',  'Lindqvist',     true),
    ('dave',    'dave@example.com',    true,  'Dave',   'Marchetti',     false)
) AS v(username, email, email_verified, first_name, last_name, enabled)
WHERE r.name = 'master'
ON CONFLICT (realm_id, lower(username)) DO NOTHING;

-- A support role that is deliberately not the administrator role, so the role
-- page shows that a role *named* admin is not what grants anything.
INSERT INTO roles (realm_id, name, description)
SELECT r.id, v.name, v.description
FROM realms r
CROSS JOIN (VALUES
    ('support', 'Read-only access to users, groups, and the audit log'),
    ('auditor', 'Reads the audit log and nothing else')
) AS v(name, description)
WHERE r.name = 'master'
ON CONFLICT (realm_id, name) DO NOTHING;

-- Grant support the read permissions only. Write implies read inside the
-- application, so granting read alone is the honest way to express this.
INSERT INTO role_permissions (role_id, permission_id)
SELECT ro.id, p.id
FROM roles ro
JOIN permissions p ON p.realm_id = ro.realm_id
WHERE ro.realm_id = (SELECT id FROM realms WHERE name = 'master')
  AND ro.name = 'support'
  AND p.name IN ('user:read', 'group:read', 'audit:read')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT ro.id, p.id
FROM roles ro
JOIN permissions p ON p.realm_id = ro.realm_id
WHERE ro.realm_id = (SELECT id FROM realms WHERE name = 'master')
  AND ro.name = 'auditor'
  AND p.name = 'audit:read'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, ro.id
FROM users u
JOIN roles ro ON ro.realm_id = u.realm_id
WHERE u.realm_id = (SELECT id FROM realms WHERE name = 'master')
  AND (u.username, ro.name) IN (('alice', 'support'), ('carol', 'auditor'))
ON CONFLICT DO NOTHING;

-- A small group tree: /engineering with two children. Inheritance runs upward,
-- so a member of the child holds the parent's roles.
INSERT INTO groups (realm_id, parent_id, name, description)
SELECT r.id, NULL, 'engineering', 'Everyone who builds the product'
FROM realms r WHERE r.name = 'master'
ON CONFLICT DO NOTHING;

INSERT INTO groups (realm_id, parent_id, name, description)
SELECT r.id, parent.id, v.name, v.description
FROM realms r
JOIN groups parent ON parent.realm_id = r.id AND parent.name = 'engineering' AND parent.parent_id IS NULL
CROSS JOIN (VALUES
    ('backend',  'Services, data, and the API'),
    ('frontend', 'The Leptos console')
) AS v(name, description)
WHERE r.name = 'master'
ON CONFLICT DO NOTHING;

INSERT INTO group_members (group_id, user_id)
SELECT g.id, u.id
FROM groups g
JOIN users u ON u.realm_id = g.realm_id
WHERE g.realm_id = (SELECT id FROM realms WHERE name = 'master')
  AND (g.name, u.username) IN (
      ('engineering', 'alice'),
      ('backend',     'bob'),
      ('frontend',    'carol')
  )
ON CONFLICT DO NOTHING;

INSERT INTO group_roles (group_id, role_id)
SELECT g.id, ro.id
FROM groups g
JOIN roles ro ON ro.realm_id = g.realm_id AND ro.name = 'support'
WHERE g.realm_id = (SELECT id FROM realms WHERE name = 'master')
  AND g.name = 'engineering'
ON CONFLICT DO NOTHING;

-- One organisation, with Alice as its owner.
INSERT INTO organizations (realm_id, slug, name, enabled)
SELECT r.id, 'acme', 'Acme Corporation', true
FROM realms r WHERE r.name = 'master'
ON CONFLICT DO NOTHING;

INSERT INTO organization_members (organization_id, user_id, role)
SELECT o.id, u.id, 'owner'
FROM organizations o
JOIN users u ON u.realm_id = o.realm_id
WHERE o.realm_id = (SELECT id FROM realms WHERE name = 'master')
  AND o.slug = 'acme'
  AND u.username = 'alice'
ON CONFLICT DO NOTHING;

-- A GitHub provider. The sealed secret is a placeholder ciphertext: it is not
-- a usable credential, and the provider cannot complete a sign-in with it.
INSERT INTO identity_providers (
    realm_id, alias, kind, display_name, client_id,
    client_secret_ciphertext, client_secret_nonce,
    authorization_endpoint, token_endpoint, userinfo_endpoint, issuer,
    scopes, enabled, allow_provisioning, link_by_verified_email
)
SELECT r.id, 'github', 'github', 'GitHub', 'demo-client-id',
       decode('00', 'hex'), decode(repeat('00', 12), 'hex'),
       'https://github.com/login/oauth/authorize',
       'https://github.com/login/oauth/access_token',
       'https://api.github.com/user',
       NULL,
       ARRAY['read:user', 'user:email'], true, true, false
FROM realms r WHERE r.name = 'master'
ON CONFLICT (realm_id, alias) DO NOTHING;

-- An OAuth client, so the clients page and the consent screen have a subject.
-- Public, so no secret has to be invented here.
INSERT INTO oauth_clients (
    realm_id, client_id, client_secret_phc, name, is_public,
    redirect_uris, grant_types, scopes, require_consent
)
SELECT r.id, 'web-console', NULL, 'Web Console', true,
       ARRAY['http://localhost:3000/callback'],
       ARRAY['authorization_code', 'refresh_token'],
       ARRAY['openid', 'profile', 'email'], true
FROM realms r WHERE r.name = 'master'
ON CONFLICT (realm_id, client_id) DO NOTHING;

-- Audit history, so the audit page is not empty and its filters have
-- something to filter.
INSERT INTO audit_events (realm_id, action, outcome, actor_id, actor_name, target_type, target, ip_address, user_agent)
SELECT r.id, v.action, v.outcome, u.id, u.username, v.target_type, v.target,
       v.ip::inet, 'Mozilla/5.0 (demo data)'
FROM realms r
JOIN (VALUES
    ('login.succeeded',              'success', 'admin',  'user',         'admin@example.com',   '203.0.113.10'),
    ('login.succeeded',              'success', 'alice',  'user',         'alice@example.com',   '203.0.113.24'),
    ('login.failed',                 'failure', 'bob',    'user',         'bob@example.com',     '198.51.100.7'),
    ('login.failed',                 'failure', 'bob',    'user',         'bob@example.com',     '198.51.100.7'),
    ('login.locked_out',             'failure', 'bob',    'user',         'bob@example.com',     '198.51.100.7'),
    ('user.created',                 'success', 'admin',  'user',         'carol@example.com',   '203.0.113.10'),
    ('user.updated',                 'success', 'admin',  'user',         'dave@example.com',    '203.0.113.10'),
    ('role.created',                 'success', 'admin',  'role',         'support',             '203.0.113.10'),
    ('role.granted',                 'success', 'admin',  'role',         'support',             '203.0.113.10'),
    ('group.created',                'success', 'admin',  'group',        'engineering',         '203.0.113.10'),
    ('group.member_added',           'success', 'admin',  'group',        'engineering',         '203.0.113.10'),
    ('organization.created',         'success', 'admin',  'organization', 'acme',                '203.0.113.10'),
    ('organization.invited',         'success', 'alice',  'organization', 'acme',                '203.0.113.24'),
    ('client.registered',            'success', 'admin',  'client',       'web-console',         '203.0.113.10'),
    ('recovery.reset_completed',     'success', 'alice',  'user',         'alice@example.com',   '203.0.113.24'),
    ('recovery.email_verified',      'success', 'alice',  'user',         'alice@example.com',   '203.0.113.24'),
    ('mfa.totp_enrolled',            'success', 'alice',  'user',         'alice@example.com',   '203.0.113.24'),
    ('mfa.succeeded',                'success', 'alice',  'user',         'alice@example.com',   '203.0.113.24'),
    ('mfa.failed',                   'failure', 'bob',    'user',         'bob@example.com',     '198.51.100.7'),
    ('session.logged_out',           'success', 'carol',  'user',         'carol@example.com',   '203.0.113.24'),
    ('token.refresh_reuse_detected', 'failure', 'carol',  'client',       'web-console',         '198.51.100.91')
) AS v(action, outcome, username, target_type, target, ip)
  ON true
JOIN users u ON u.realm_id = r.id AND u.username = v.username
WHERE r.name = 'master'
  AND NOT EXISTS (
      SELECT 1 FROM audit_events e
      WHERE e.realm_id = r.id AND e.action = v.action AND e.target = v.target
  );

COMMIT;
