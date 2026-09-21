// Captures every frontend page into docs/screenshots/.
//
// Run through `just screenshots`, which mints the two single-use tokens this
// needs. Every page that a visitor can reach is captured, including the
// signed-out pages, the error states, and the 404 — a screenshot set that only
// shows the happy path hides the pages most likely to break.
//
// Each capture is validated before it is written: a page with no text, a page
// that logged a JavaScript error, and an image too small to contain a layout
// are all reported as failures. A blank or white screenshot is the failure
// this exists to catch, and it is the one that looks fine in a directory
// listing.
//
// Output is written to a temporary directory and swapped into place only after
// every page succeeds, so a failed run never leaves a half-updated set behind
// for `check-screenshots.py` to mistake for this run's.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(process.env.OUT_DIR ?? path.join(here, '../../docs/screenshots'));
const BASE = process.env.BASE_URL ?? 'http://127.0.0.1:3000';
const REALM = process.env.DEMO_REALM ?? 'master';
const USER = process.env.DEMO_USER ?? 'admin';
// The refused sign-in deliberately does not name the administrator. A wrong
// password for a real account consumes that account's failure budget, and
// repeated captures would eventually lock it out — including the successful
// sign-in this same run needs. An identifier that cannot exist spends the
// administrator's budget not at all, and the page answers it with exactly the
// message a wrong password gets, which is the anti-enumeration property being
// checked here.
//
// The suffix is fresh on every run for the same reason: five failures against
// one identifier lock it for fifteen minutes, so reusing a fixed name would
// turn the second capture run's refused sign-in into "Too many attempts" and
// the run would fail on a message that is not the one under test. The capture
// script deletes the failures this pattern produced before it starts (see
// `e2e/token-fixtures.sql`), so the per-address budget the run contributes to
// does not accumulate across runs either.
const FAIL_USER_PREFIX = 'capture-nonexistent-';
const FAIL_USER =
  process.env.DEMO_FAIL_USER ?? FAIL_USER_PREFIX + Math.random().toString(36).slice(2, 10);
const FAIL_PASSWORD = process.env.DEMO_FAIL_PASSWORD ?? 'not the right password at all';
// What a refused sign-in must say. The wrong-password and unknown-account
// branches share this one message deliberately, so a capture that renders
// anything else is a regression toward enumeration.
const REFUSED_MESSAGE = 'That realm, username, or password did not match an account.';

// The demo administrator's password. Required, with no compiled-in default: a
// default here would be a published administrator password for any instance
// somebody stood up with the README's steps. `AUTHENC_SEED_PASSWORD` is accepted
// as the same secret the seed used, so one exported value drives both and there
// is no second copy to keep in sync.
const PASSWORD = process.env.DEMO_PASSWORD ?? process.env.AUTHENC_SEED_PASSWORD;
if (!PASSWORD) {
  console.error(
    'DEMO_PASSWORD is not set. The capture signs in with it, so it is required;\n' +
      'there is deliberately no default an outsider could guess. Export it, or\n' +
      'read it without echoing it:\n\n' +
      '  read -r -s DEMO_PASSWORD && export DEMO_PASSWORD\n' +
      '  just screenshots\n\n' +
      '`AUTHENC_SEED_PASSWORD` is accepted too, if you would rather export the\n' +
      'password just once and use the same value for `just seed`.\n',
  );
  process.exit(1);
}

const RESET_TOKEN = process.env.RESET_TOKEN ?? '';
const VERIFY_TOKEN = process.env.VERIFY_TOKEN ?? '';

// A token in a URL is a live credential for as long as it has not been spent.
// The report is committed, so the query is redacted before it is written; the
// screenshot still shows the real page.
function redact(url) {
  return url.replace(/([?&]token=)[^&]*/gi, '$1[REDACTED]');
}

// Write beside the destination so the rename below stays on one filesystem.
const TMP = fs.mkdtempSync(path.join(path.dirname(OUT), '.screenshots-'));
// A run that failed left its output behind for inspection; the next run should
// not accumulate those forever. Only directories older than an hour go: a
// second capture started a moment ago would otherwise have its output — or a
// concurrent one its working directory — deleted from under it. `OUT` itself is
// never touched, because a failed run must leave the known-good set in place.
const STALE_AFTER_MS = 60 * 60 * 1000;
const parent = path.dirname(OUT);
for (const entry of fs.readdirSync(parent)) {
  const candidate = path.join(parent, entry);
  if (!entry.startsWith('.screenshots-') || candidate === TMP) continue;
  if (Date.now() - fs.statSync(candidate).mtimeMs > STALE_AFTER_MS) {
    fs.rmSync(candidate, { recursive: true, force: true });
  }
}

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width: 1280, height: 900 },
  deviceScaleFactor: 2,
  colorScheme: 'light',
});
const page = await context.newPage();

let consoleErrors = [];
page.on('console', (m) => {
  if (m.type() === 'error') consoleErrors.push(m.text().split('\n')[0]);
});
page.on('pageerror', (e) => consoleErrors.push('pageerror: ' + e.message.split('\n')[0]));

const report = [];

async function shoot(
  name,
  url,
  {
    wait = 1500,
    settle = null,
    expectStatus = 200,
    allowConsoleErrors = [],
    allowErrorCopy = false,
    expectText = null,
  } = {},
) {
  consoleErrors = [];
  let resp = null;
  let settleError = null;
  try {
    resp = await page.goto(BASE + url, { waitUntil: 'networkidle' });
    if (settle) await settle();
    await page.waitForTimeout(wait);
  } catch (error) {
    // A settle step that times out means the state this capture wanted was
    // never reached. Recording it is the point; the page may still be worth
    // looking at, so the screenshot below is taken regardless.
    settleError = error.message.split('\n')[0];
  }

  const file = path.join(TMP, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });

  const info = await page.evaluate(() => {
    const text = (document.body.innerText || '').trim();
    const doc = document.documentElement;
    // A page that rendered an error banner is a failure even though it has
    // plenty of text and a healthy-looking image. Phrase-matching the app's
    // own error copy is the cheap way to catch it; a page that legitimately
    // displays one opts out with `allowErrorCopy`.
    const errorCopy = [
      'internal error occurred',
      'error running server function',
    ].filter((phrase) => text.toLowerCase().includes(phrase));

    // Elements pushed past the right edge, or taller than their own content
    // box with `overflow: hidden`, are the two ways a tidy page renders as a
    // broken one: text off-screen, or a control sliced in half.
    const vw = doc.clientWidth;
    const overflowing = [];
    const clipped = [];
    for (const el of document.querySelectorAll('body *')) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      if (r.right > vw + 2) overflowing.push(describe(el, r));
      const style = getComputedStyle(el);
      if (
        (style.overflow === 'hidden' || style.overflowY === 'hidden') &&
        el.scrollHeight > el.clientHeight + 4 &&
        r.height > 40
      ) {
        clipped.push(describe(el, r));
      }
    }

    function describe(el, r) {
      return `${el.tagName.toLowerCase()}.${(el.className || '').toString().split(' ')[0]}@${Math.round(r.right)}x${Math.round(r.height)}`;
    }

    return {
      textLen: text.length,
      sample: text.slice(0, 120).replace(/\s+/g, ' '),
      errorCopy,
      overflowing: overflowing.slice(0, 5),
      clipped: clipped.slice(0, 5),
      tables: document.querySelectorAll('table').length,
      rows: document.querySelectorAll('tbody tr').length,
      inputs: document.querySelectorAll('input,select').length,
      buttons: document.querySelectorAll('button').length,
      bg: getComputedStyle(document.body).backgroundColor,
      overflowX: doc.scrollWidth - doc.clientWidth,
      height: doc.scrollHeight,
    };
  });

  const bytes = fs.statSync(file).size;
  const status = resp ? resp.status() : null;
  const errors = consoleErrors.filter(
    (e) => !allowConsoleErrors.some((allowed) => e.includes(allowed)),
  );
  const problems = [];
  if (errors.length) problems.push('JS-ERRORS');
  if (settleError) problems.push('STATE-NOT-REACHED');
  // The status is asserted, not merely recorded: a 500 that still painted a
  // friendly body, or a 404 served as 200, is the failure this catches. That
  // is separate from the console-error exemption above, which says nothing
  // about which status a page should have answered with.
  if (status !== expectStatus) {
    problems.push(`UNEXPECTED-STATUS(${status}, wanted ${expectStatus})`);
  }
  if (info.errorCopy.length && !allowErrorCopy) problems.push('RENDERED-AN-ERROR');
  if (expectText) {
    const full = await page.evaluate(() => (document.body.innerText || '').trim());
    if (!full.includes(expectText)) problems.push('MISSING-EXPECTED-TEXT');
  }
  if (info.overflowing.length) problems.push('ELEMENT-OFF-SCREEN');
  if (info.clipped.length) problems.push('CLIPPED');
  if (info.textLen < 30) problems.push('NEARLY-EMPTY');
  if (bytes < 12000) problems.push('TINY-IMAGE');
  if (info.overflowX > 2) problems.push('OVERFLOWS-X');
  if (info.bg === 'rgba(0, 0, 0, 0)' || info.bg === 'rgb(255, 255, 255)') {
    problems.push('NO-BACKGROUND-COLOUR');
  }

  report.push({
    name,
    url: redact(url),
    status,
    expectedStatus: expectStatus,
    bytes,
    settleError,
    problems,
    ...info,
  });
  console.log(`${problems.length ? 'FAIL' : 'ok  '} ${name.padEnd(26)} ${JSON.stringify(report.at(-1))}`);
  return report.at(-1);
}

// Sign in through the real form, so the session cookie is the one the
// application issues rather than one this script fabricates. Repeatable: a
// successful sign-in clears the failure budget for the identifier it names.
async function signIn() {
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('#realm', REALM);
  await page.fill('#identifier', USER);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL((u) => !u.pathname.includes('/login'), { timeout: 30000 });
}

try {
  if (RESET_TOKEN) {
    await shoot('reset-password-form', `/reset-password?token=${RESET_TOKEN}`);
  }
  if (VERIFY_TOKEN) {
    await shoot('verify-email-confirmed', `/verify-email?token=${VERIFY_TOKEN}`);
  }

  await shoot('home', '/');
  await shoot('login', '/login');
  await shoot('login-error', '/login', {
    allowConsoleErrors: ['401'],
    expectText: REFUSED_MESSAGE,
    settle: async () => {
      await page.fill('#realm', REALM);
      // An identifier that is not an account. Nothing real is locked out by
      // repeating this capture.
      await page.fill('#identifier', FAIL_USER);
      await page.fill('#password', FAIL_PASSWORD);
      await page.click('button[type=submit]');
      await page.waitForTimeout(3000);
    },
  });
  await shoot('forgot-password', '/forgot-password');
  await shoot('forgot-password-sent', '/forgot-password', {
    settle: async () => {
      await page.fill('#realm', REALM);
      await page.fill('#email', 'admin@example.com');
      await page.click('button[type=submit]');
      await page.waitForTimeout(2500);
    },
  });
  await shoot('reset-password', '/reset-password');
  await shoot('verify-email', '/verify-email');
  await shoot('not-found', '/this-page-does-not-exist', {
    expectStatus: 404,
    allowConsoleErrors: ['404'],
  });

  await signIn();
  console.log(`signed in, now at ${page.url()}`);

  await shoot('admin-overview', '/admin');
  await shoot('admin-users', '/admin/users');
  await shoot('admin-roles', '/admin/roles');
  await shoot('admin-groups', '/admin/groups');
  await shoot('admin-organizations', '/admin/organizations');
  await shoot('admin-providers', '/admin/providers');
  await shoot('admin-clients', '/admin/clients');
  await shoot('admin-audit', '/admin/audit', {
    // The trail is a client-side resource behind a <Transition>, so the table
    // arrives after load. Waiting for a row is what makes this capture the
    // table rather than the "Loading…" placeholder. The wait is not caught:
    // a trail that never renders is a failure to report, not an empty page to
    // accept, so a timeout here becomes STATE-NOT-REACHED.
    wait: 4000,
    settle: async () => {
      await page.waitForSelector('table tbody tr', { timeout: 15000 });
    },
  });

  // The two mid-interaction states: a half-filled creation form, and the
  // enrolment panel a second factor opens. Both are real states a person
  // reaches and neither appears on a page load.
  await shoot('admin-users-filled', '/admin/users', {
    settle: async () => {
      await page.fill('#new-username', 'erin');
      await page.fill('#new-email', 'erin@example.com');
      await page.fill('#new-password', 'a long passphrase for erin');
    },
  });
  await shoot('security', '/security');
  await shoot('security-enrol', '/security', {
    settle: async () => {
      await page.click('button:has-text("Set up an authenticator")');
      await page.waitForTimeout(2500);
    },
  });
  await shoot('consent', `/consent?realm=${REALM}&client_id=web-console&scope=openid%20profile%20email`);
} catch (error) {
  // A navigation or sign-in that threw before a capture ran still has to be a
  // reported failure, not an unhandled rejection with no report written.
  report.push({
    name: 'capture-run',
    url: redact(page.url()),
    status: null,
    expectedStatus: null,
    bytes: null,
    settleError: error.message.split('\n')[0],
    problems: ['RUN-ABORTED'],
  });
}

const failed = report.filter((r) => r.problems.length);
console.log(`\n${report.length} pages captured, ${failed.length} with problems`);
if (failed.length) {
  for (const f of failed) console.log(' -', f.name, f.problems.join(','));
}

fs.writeFileSync(path.join(TMP, 'report.json'), JSON.stringify(report, null, 2));

await browser.close();

// Swap the whole set in only when every page passed. A refused capture leaves
// the previous, known-good set untouched and this run's output on disk to look
// at; a green one replaces it whole, so a page that no longer exists cannot
// leave a stale PNG behind for the checker to accept as current.
if (failed.length) {
  console.error(`capture failed; previous set left in place, this run is in ${TMP}`);
  process.exit(1);
}

const previous = `${OUT}.previous-${process.pid}`;
try {
  if (fs.existsSync(OUT)) fs.renameSync(OUT, previous);
  fs.renameSync(TMP, OUT);
  fs.rmSync(previous, { recursive: true, force: true });
} catch (error) {
  // Never leave the destination missing: if the swap half-failed, put the
  // previous set back rather than reporting success over an empty directory.
  if (fs.existsSync(previous) && !fs.existsSync(OUT)) fs.renameSync(previous, OUT);
  console.error(`could not replace ${OUT}: ${error.message}; this run is in ${TMP}`);
  process.exit(1);
}
process.exit(0);
