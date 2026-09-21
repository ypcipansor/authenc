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

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = process.env.OUT_DIR ?? path.resolve(here, '../../docs/screenshots');
const BASE = process.env.BASE_URL ?? 'http://127.0.0.1:3000';
const REALM = process.env.DEMO_REALM ?? 'master';
const USER = process.env.DEMO_USER ?? 'admin';
const PASSWORD = process.env.DEMO_PASSWORD ?? 'correct horse battery staple';
const RESET_TOKEN = process.env.RESET_TOKEN ?? '';
const VERIFY_TOKEN = process.env.VERIFY_TOKEN ?? '';

fs.mkdirSync(OUT, { recursive: true });

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

async function shoot(name, url, { wait = 1500, settle = null, expectError = null } = {}) {
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

  const file = path.join(OUT, `${name}.png`);
  await page.screenshot({ path: file, fullPage: true });

  const info = await page.evaluate(() => {
    const text = (document.body.innerText || '').trim();
    const doc = document.documentElement;
    // A page that rendered an error banner is a failure even though it has
    // plenty of text and a healthy-looking image. Phrase-matching the app's
    // own error copy is the cheap way to catch it; a page that legitimately
    // displays one opts out with `expectError`.
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
  const errors = consoleErrors.filter((e) => !(expectError && e.includes(expectError)));
  const problems = [];
  if (errors.length) problems.push('JS-ERRORS');
  if (settleError) problems.push('STATE-NOT-REACHED');
  if (info.errorCopy.length && !expectError) problems.push('RENDERED-AN-ERROR');
  if (info.overflowing.length) problems.push('ELEMENT-OFF-SCREEN');
  if (info.clipped.length) problems.push('CLIPPED');
  if (info.textLen < 30) problems.push('NEARLY-EMPTY');
  if (bytes < 12000) problems.push('TINY-IMAGE');
  if (info.overflowX > 2) problems.push('OVERFLOWS-X');
  if (info.bg === 'rgba(0, 0, 0, 0)' || info.bg === 'rgb(255, 255, 255)') {
    problems.push('NO-BACKGROUND-COLOUR');
  }

  report.push({ name, url, status: resp ? resp.status() : null, bytes, settleError, problems, ...info });
  console.log(`${problems.length ? 'FAIL' : 'ok  '} ${name.padEnd(26)} ${JSON.stringify(report.at(-1))}`);
  return report.at(-1);
}

// Sign in through the real form, so the session cookie is the one the
// application issues rather than one this script fabricates.
async function signIn() {
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle' });
  await page.fill('#realm', REALM);
  await page.fill('#identifier', USER);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL((u) => !u.pathname.includes('/login'), { timeout: 30000 });
}

if (RESET_TOKEN) {
  await shoot('reset-password-form', `/reset-password?token=${RESET_TOKEN}`);
}
if (VERIFY_TOKEN) {
  await shoot('verify-email-confirmed', `/verify-email?token=${VERIFY_TOKEN}`);
}

await shoot('home', '/');
await shoot('login', '/login');
await shoot('login-error', '/login', {
  expectError: '401',
  settle: async () => {
    await page.fill('#realm', REALM);
    await page.fill('#identifier', USER);
    await page.fill('#password', 'not the right password at all');
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
await shoot('not-found', '/this-page-does-not-exist', { expectError: '404' });

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
  // table rather than the "Loading…" placeholder.
  wait: 4000,
  settle: async () => {
    await page.waitForSelector('table tbody tr', { timeout: 15000 }).catch(() => {});
  },
});

// The two mid-interaction states: a half-filled creation form, and the
// enrolment panel a second factor opens. Both are real states a person reaches
// and neither appears on a page load.
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

const failed = report.filter((r) => r.problems.length);
console.log(`\n${report.length} pages captured, ${failed.length} with problems`);
if (failed.length) {
  for (const f of failed) console.log(' -', f.name, f.problems.join(','));
}

fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 2));

await browser.close();
process.exit(failed.length ? 1 : 0);
