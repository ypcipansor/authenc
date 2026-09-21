-- Token fixture for the screenshot run.
--
-- One page can only be captured with a real token: the confirmed-email page.
-- Verification tokens are single-use by design, so visiting the page spends
-- them and a second run would capture an error page. This file re-arms it,
-- which is why the screenshot job is repeatable.
--
-- The password-reset token is deliberately *not* here. It is minted by making
-- a real reset request in the screenshot wrapper, so that capture exercises
-- the request path rather than a row a script inserted.

-- The refused sign-in in the capture uses an identifier under this prefix, one
-- per run. Five failures against a single identifier lock it for fifteen
-- minutes, so a reused name would make the second run render "Too many
-- attempts" instead of the anti-enumeration message the capture checks. The
-- failures also count against a per-address budget shared by every account, so
-- deleting them here keeps a capture run from consuming the budget of the
-- machine it runs on.
DELETE FROM login_attempts
WHERE identifier LIKE 'capture-nonexistent-%';

INSERT INTO email_verification_tokens (user_id, email, token_hash, expires_at)
SELECT id, email, sha256('verifytoken123'::bytea), now() + interval '1 hour'
FROM users
WHERE username = 'bob'
ON CONFLICT (token_hash) DO UPDATE
    SET used_at = NULL, expires_at = now() + interval '1 hour';
