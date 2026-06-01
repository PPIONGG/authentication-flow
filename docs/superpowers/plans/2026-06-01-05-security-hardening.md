I now have full context. Writing the plan.

# Security Hardening Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Consolidate and prove the authentication-flow security baseline by tuning helmet (CSP/HSTS), express-rate-limit thresholds, and cookie attributes, then locking the behaviour in with a dedicated regression test suite and a `docs/SECURITY.md` write-up plus a pre-prod checklist.

**Architecture:** This plan adds **no new endpoints**. It hardens existing middleware (`security.ts`, `rateLimit.ts`, `session.ts`, `csrf.ts`) and adds one integration-test file (`tests/security/hardening.test.ts`) that asserts the cross-cutting guarantees: rate-limit 429-after-N, CSRF 403, enumeration parity, cookie attribute correctness, session-id rotation on login (fixation defence), and single-use tokens. Documentation captures what is protected and a manual go-live checklist.

**Tech Stack:** Express 5 + TypeScript (ESM, strict); helmet@8, express-rate-limit@8 + rate-limit-redis@5, csrf-csrf@4, express-session@1.19 + connect-redis@9, argon2; vitest@4 + supertest@7 driving a test Postgres + test Redis + Mailpit; Prisma 7 (`prisma-client` generator, driver adapter).

---

## Files overview

| Action | Path | Why |
| --- | --- | --- |
| Modify | `apps/api/src/middleware/security.ts` | Tune helmet CSP for the SPA + explicit HSTS; lock CORS to single origin. |
| Modify | `apps/api/src/middleware/rateLimit.ts` | Define exact thresholds (global + auth limiters), `draft-8` headers, Redis store, `limit` not `max`. |
| Modify | `apps/api/src/config/env.ts` | Add zod-validated tunables (`RATE_LIMIT_*`) so thresholds are config, not magic numbers. |
| Modify | `apps/api/.env.example` | Document the new rate-limit env vars. |
| Create | `apps/api/tests/security/helpers.ts` | Shared test helpers: fetch CSRF token + cookie, parse `Set-Cookie`, Mailpit token extraction. |
| Create | `apps/api/tests/security/hardening.test.ts` | The regression suite proving every baseline guarantee. |
| Create | `docs/SECURITY.md` | What is protected + how, and a manual pre-prod checklist. |
| Modify | `docs/ROADMAP.md` | Tick the "baseline proven by tests" item under §10. |

Assume Plans 00–04 are fully implemented: the full Prisma schema + migration exist, `sessionStore.ts` and `audit.ts` exist, all endpoints from the FOUNDATION contract are live, and the app is wired in `apps/api/src/app.ts` with middleware order `helmet → cors → cookie-parser → session → csrf → rate-limit → routes → errorHandler`.

Before starting, read these existing files so you know the exact current shapes you are modifying: `apps/api/src/app.ts`, `apps/api/src/config/env.ts`, `apps/api/src/middleware/security.ts`, `apps/api/src/middleware/rateLimit.ts`, `apps/api/src/middleware/csrf.ts`, `apps/api/src/middleware/session.ts`, `apps/api/src/redis/client.ts`, `apps/api/src/db/prisma.ts`, `apps/api/src/lib/tokens.ts`, `apps/api/vitest.config.ts`, and one existing integration test (e.g. `apps/api/tests/auth/login.test.ts`) to copy its setup/teardown idiom.

All commands below assume you run them **inside the api container** (the test Postgres/Redis/Mailpit hostnames `db`/`redis`/`mailpit` only resolve there). Enter it with:

```bash
docker compose exec api sh
```

Then `cd /app` (the api workdir) before running any `npm`/`npx` command. All `git` commands run from the repo root on the host.

---

## Task 1: Make rate-limit thresholds configuration, not magic numbers

We want the regression test to drive a *low* `limit` so a test can trip the limiter in a handful of requests without 100 real calls. That means thresholds must be env-driven and zod-validated.

**Files**
- Modify: `apps/api/src/config/env.ts`
- Modify: `apps/api/.env.example`
- Test: (validated indirectly by Task 5; this task is config plumbing)

- [ ] **Step 1: Read the current env schema so you match its exact style.**
  Open `apps/api/src/config/env.ts`. It is a zod object validating `process.env` (FOUNDATION lists `DATABASE_URL, REDIS_URL, SESSION_SECRET, CSRF_SECRET, SMTP_HOST, SMTP_PORT, MAIL_FROM, APP_URL, NODE_ENV`). Note whether it exports `env` (the parsed object) and the inferred type. Do not change existing fields.

- [ ] **Step 2: Add four rate-limit tunables to the zod schema.**
  In `apps/api/src/config/env.ts`, inside the `z.object({ ... })` passed to validate `process.env`, add these fields (use `z.coerce.number()` because env values are strings). Place them after the existing fields:

  ```ts
  // --- Rate-limit tunables (Security Hardening Pass) ---
  // Global limiter: requests per window across the whole API.
  RATE_LIMIT_GLOBAL_MAX: z.coerce.number().int().positive().default(300),
  RATE_LIMIT_GLOBAL_WINDOW_MS: z.coerce.number().int().positive().default(15 * 60 * 1000),
  // Auth limiter: requests per window for sensitive /auth endpoints.
  RATE_LIMIT_AUTH_MAX: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_AUTH_WINDOW_MS: z.coerce.number().int().positive().default(15 * 60 * 1000),
  ```

  Because zod `.default()` is used, existing `.env` files keep working with no edits — defaults apply when the var is absent.

- [ ] **Step 3: Document the new vars in `.env.example`.**
  Open `apps/api/.env.example` and append (keep the file's existing comment style):

  ```bash
  # --- Rate limiting (Security Hardening Pass) ---
  # Global API limiter
  RATE_LIMIT_GLOBAL_MAX=300
  RATE_LIMIT_GLOBAL_WINDOW_MS=900000
  # Tighter limiter on sensitive /auth endpoints (login, forgot/reset, register, resend)
  RATE_LIMIT_AUTH_MAX=10
  RATE_LIMIT_AUTH_WINDOW_MS=900000
  ```

- [ ] **Step 4: Type-check to prove the schema still compiles.**
  Run inside the api container:

  ```bash
  npx tsc --noEmit
  ```

  Expected output: no errors (exit code 0). If `tsc` reports a duplicate-key or comma error, fix the object syntax before continuing.

- [ ] **Step 5: Commit.**
  From the repo root:

  ```bash
  git add apps/api/src/config/env.ts apps/api/.env.example
  git commit -m "feat: make rate-limit thresholds zod-validated env tunables"
  ```

---

## Task 2: Tune the rate limiters (global + auth) with exact thresholds and Redis store

The auth limiter must be tight enough to constitute a lockout-style brake on credential stuffing, must return **429** when tripped, must use the `limit` option (not the deprecated `max`), must emit IETF `draft-8` headers and drop legacy `X-RateLimit-*`, and must be backed by the shared connected node-redis client so it works across api instances.

**Files**
- Modify: `apps/api/src/middleware/rateLimit.ts`
- Test: covered by Task 5 (`tests/security/hardening.test.ts`)

- [ ] **Step 1: Read the current limiter file.**
  Open `apps/api/src/middleware/rateLimit.ts`. Identify how it imports the connected redis client (FOUNDATION: `apps/api/src/redis/client.ts` exports a singleton node-redis client) and what it currently exports. You will replace the limiter definitions; keep the redis import.

- [ ] **Step 2: Replace the limiter definitions with config-driven, 429-returning limiters.**
  Overwrite `apps/api/src/middleware/rateLimit.ts` with the following. The canonical export from `redis/client.ts` is `redis` (NOT `redisClient`); keep that import name:

  ```ts
  import { rateLimit } from 'express-rate-limit'
  import { RedisStore } from 'rate-limit-redis'
  import { redis } from '../redis/client.js'
  import { env } from '../config/env.js'

  // node-redis form: args are passed as a single array to sendCommand.
  // (ioredis would be (command, ...args) => client.call(command, ...args) — we use node-redis.)
  const store = (prefix: string) =>
    new RedisStore({
      prefix,
      sendCommand: (...args: string[]) => redis.sendCommand(args),
    })

  // Global brake across the whole API. Generous; catches runaway clients.
  export const globalLimiter = rateLimit({
    windowMs: env.RATE_LIMIT_GLOBAL_WINDOW_MS,
    limit: env.RATE_LIMIT_GLOBAL_MAX, // `limit`, NOT the deprecated `max`
    standardHeaders: 'draft-8', // combined IETF `RateLimit` header
    legacyHeaders: false, // drop X-RateLimit-*
    ipv6Subnet: 56,
    store: store('rl:global:'),
    message: { error: 'Too many requests, please try again later.' },
  })

  // Tight limiter on sensitive auth endpoints — credential-stuffing brake.
  // Returns 429 once the per-IP budget for the window is exhausted.
  export const authLimiter = rateLimit({
    windowMs: env.RATE_LIMIT_AUTH_WINDOW_MS,
    limit: env.RATE_LIMIT_AUTH_MAX,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    ipv6Subnet: 56,
    store: store('rl:auth:'),
    message: { error: 'Too many attempts, please try again later.' },
  })
  ```

  `express-rate-limit` returns HTTP **429** by default when `limit` is exceeded, so no `statusCode` override is needed.

- [ ] **Step 3: Confirm the limiters are mounted in `app.ts` in the right places.**
  Open `apps/api/src/app.ts`. Verify `globalLimiter` is applied app-wide (e.g. `app.use(globalLimiter)`) and `authLimiter` is mounted on the auth router (`app.use('/api/auth', authLimiter, authRoutes)` or equivalent). If either is missing, add it now. The `authLimiter` must sit **before** the auth route handlers so it runs first. Health (`GET /api/health`) and `GET /api/csrf` must remain reachable — if `globalLimiter` is mounted before them, the generous global default keeps them usable; do not put `authLimiter` on those paths.

- [ ] **Step 4: Type-check.**
  Inside the api container:

  ```bash
  npx tsc --noEmit
  ```

  Expected: no errors. The canonical export from `redis/client.ts` is `redis` — if the import does not match that name, fix it.

- [ ] **Step 5: Commit.**

  ```bash
  git add apps/api/src/middleware/rateLimit.ts apps/api/src/app.ts
  git commit -m "feat: tighten rate limiters with config thresholds, redis store, draft-8 headers"
  ```

---

## Task 3: Tune helmet CSP for the SPA and set explicit HSTS

helmet's default CSP can break a Vite SPA. We set an explicit, SPA-appropriate CSP that merges with helmet's secure defaults, and an explicit HSTS (1 year + includeSubDomains). We also confirm CORS is locked to the single origin with credentials.

**Files**
- Modify: `apps/api/src/middleware/security.ts`
- Test: CSP/HSTS header presence asserted in Task 5

- [ ] **Step 1: Read the current security middleware.**
  Open `apps/api/src/middleware/security.ts`. FOUNDATION says it sets up helmet + cors. Note how `env.APP_URL` is used for the CORS origin. You will replace the helmet call and confirm the cors call.

- [ ] **Step 2: Replace helmet config with an SPA-tuned CSP + explicit HSTS, and lock CORS.**
  Overwrite `apps/api/src/middleware/security.ts` with:

  ```ts
  import helmet from 'helmet'
  import cors from 'cors'
  import type { RequestHandler } from 'express'
  import { env } from '../config/env.js'

  // Single-origin deployment (Caddy reverse proxy): the SPA and API share one
  // origin (env.APP_URL). CSP is therefore strict 'self' for scripts/connect.
  export const helmetMiddleware: RequestHandler = helmet({
    contentSecurityPolicy: {
      useDefaults: true, // merge with helmet's secure defaults
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"], // no inline scripts; Vite build emits external JS
        // Styled components / Vite-injected critical CSS need inline styles.
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        // Same-origin XHR/fetch only; the API is same-origin behind Caddy.
        'connect-src': ["'self'"],
        'font-src': ["'self'", 'data:'],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
        'frame-ancestors': ["'self'"],
        'form-action': ["'self'"],
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: false, // do NOT preload until the prod domain is committed
    },
  })

  // CORS locked to the single origin with credentials. Even though same-origin
  // makes CORS largely moot, we lock it explicitly: never '*', always credentials.
  export const corsMiddleware: RequestHandler = cors({
    origin: env.APP_URL,
    credentials: true,
  })
  ```

  If your existing file exported the middleware under different names (e.g. a single `securityMiddleware`), keep the original export names so `app.ts` does not break — rename the consts above to match, or update `app.ts` imports. Do not change middleware *order* in `app.ts`: helmet first, then cors.

- [ ] **Step 3: Type-check.**
  Inside the api container:

  ```bash
  npx tsc --noEmit
  ```

  Expected: no errors.

- [ ] **Step 4: Commit.**

  ```bash
  git add apps/api/src/middleware/security.ts apps/api/src/app.ts
  git commit -m "feat: tune helmet CSP for the SPA and set explicit HSTS"
  ```

---

## Task 4: Add shared security-test helpers

The regression suite repeatedly needs to: bootstrap a CSRF token + its cookie, send authenticated/mutating requests carrying both cookies and the `x-csrf-token` header, parse `Set-Cookie` attributes, and extract a token from Mailpit. Centralise these so each test stays readable.

**Files**
- Create: `apps/api/tests/security/helpers.ts`
- Test: this file *is* test infrastructure; it is exercised by Task 5

- [ ] **Step 1: Confirm the supertest + app import idiom used by existing tests.**
  Open an existing test such as `apps/api/tests/auth/login.test.ts`. Note the exact import path of the app (`import { app } from '../../src/app.js'` or similar with `.js` ESM suffix) and how it imports `prisma`/`redis` for teardown (the canonical redis export is `redis`, not `redisClient`). Mirror those paths exactly in the helper.

- [ ] **Step 2: Create the helpers file.**
  Create `apps/api/tests/security/helpers.ts`. Adjust the import paths (`app`, and `prisma`/`redis` for any teardown the helper needs — the canonical redis export is `redis`) to match what you saw in Step 1:

  ```ts
  import request from 'supertest'
  import type { Response } from 'supertest'
  import { app } from '../../src/app.js'

  const MAILPIT = process.env.MAILPIT_URL ?? 'http://mailpit:8025'

  /** Parse the array of Set-Cookie strings into a name -> raw-cookie-string map. */
  export function parseSetCookie(res: Response): Record<string, string> {
    const raw = res.headers['set-cookie'] as unknown as string[] | undefined
    const list = Array.isArray(raw) ? raw : raw ? [raw] : []
    const out: Record<string, string> = {}
    for (const c of list) {
      const name = c.split('=')[0]
      out[name] = c
    }
    return out
  }

  /** Extract just the "name=value" pair (no attributes) for echoing back as a Cookie header. */
  export function cookiePair(rawCookie: string): string {
    return rawCookie.split(';')[0]
  }

  /**
   * Bootstrap the double-submit CSRF token from GET /api/csrf.
   * Returns the token plus the raw csrf cookie so callers can echo both back.
   */
  export async function getCsrf(): Promise<{ token: string; cookie: string }> {
    const res = await request(app).get('/api/csrf').expect(200)
    const token = res.body.csrfToken as string
    const cookies = parseSetCookie(res)
    // csrf-csrf is configured with cookieName 'x-csrf-token' (NOT the library
    // default '__Host-psifi.x-csrf-token'); find it by the 'csrf' substring.
    const csrfRaw = Object.entries(cookies).find(([n]) =>
      n.includes('csrf'),
    )?.[1]
    if (!csrfRaw) throw new Error('No CSRF cookie set by GET /api/csrf')
    return { token, cookie: cookiePair(csrfRaw) }
  }

  /** Clear all Mailpit messages so per-test email assertions are isolated. */
  export async function clearMailpit(): Promise<void> {
    await fetch(`${MAILPIT}/api/v1/messages`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
  }

  /** Return the full latest Mailpit message addressed to `addr`, or null. */
  export async function latestMessageTo(
    addr: string,
  ): Promise<{ HTML: string; Text: string; Subject: string } | null> {
    const res = await fetch(
      `${MAILPIT}/api/v1/search?query=${encodeURIComponent('to:' + addr)}&limit=1`,
    )
    const { messages } = (await res.json()) as { messages?: { ID: string }[] }
    if (!messages?.length) return null
    const full = await fetch(`${MAILPIT}/api/v1/message/${messages[0].ID}`)
    return full.json()
  }

  /**
   * Pull the first 24+ char token-looking string from a message body.
   * Verification/reset links carry the raw token in the URL or body.
   */
  export function extractToken(body: string): string {
    const m = body.match(/[A-Za-z0-9_-]{24,}/)
    if (!m) throw new Error('No token found in email body')
    return m[0]
  }
  ```

- [ ] **Step 3: Type-check the helper compiles against the real app types.**
  Inside the api container:

  ```bash
  npx tsc --noEmit
  ```

  Expected: no errors. If `app` is a default export in your codebase, change the import to `import app from '../../src/app.js'`.

- [ ] **Step 4: Commit.**

  ```bash
  git add apps/api/tests/security/helpers.ts
  git commit -m "test: add shared security regression test helpers"
  ```

---

## Task 5: Write the security regression suite

This is the core of the plan. We follow TDD per assertion-group: write the test, run it, watch it pass against the now-hardened code (the implementation already exists from Tasks 1–3 and Plans 00–04). Each group below is its own `describe` block; build the file incrementally and run after each block so a failure is localised.

To make the suite deterministic, the test run sets a **low** auth limit. Add to `apps/api/vitest.config.ts` a `test.env` block (or rely on the test compose env) so the api process under test sees `RATE_LIMIT_AUTH_MAX=3`. The cleanest place is the vitest config:

```ts
// inside defineConfig({ test: { ... } }) in apps/api/vitest.config.ts
env: {
  RATE_LIMIT_AUTH_MAX: '3',
  RATE_LIMIT_AUTH_WINDOW_MS: '900000',
},
```

Add that first (Step 0 below), since `env.ts` reads `process.env` at import time.

**Files**
- Modify: `apps/api/vitest.config.ts` (add `test.env`)
- Create: `apps/api/tests/security/hardening.test.ts`
- Modify: covered files from Tasks 1–4 (no further source changes expected)

- [ ] **Step 0: Pin the test-time auth limit in vitest config.**
  Open `apps/api/vitest.config.ts`. Inside the `test: { ... }` object, add the `env` block shown above. Keep `fileParallelism: false` / single-fork settings already present (FOUNDATION test strategy uses one throwaway DB; do not enable parallel files). Save. Commit this small change now:

  ```bash
  git add apps/api/vitest.config.ts
  git commit -m "test: pin low auth rate-limit for the security suite"
  ```

- [ ] **Step 1: Scaffold the test file with setup/teardown.**
  Create `apps/api/tests/security/hardening.test.ts`. Match the truncation/flush idiom from an existing test (Step 1 of Task 4 told you the exact `prisma`/`redis` import paths — reuse them here). Start with:

  ```ts
  import { beforeEach, describe, expect, test } from 'vitest'
  import request from 'supertest'
  import argon2 from 'argon2'
  import { app } from '../../src/app.js'
  import { prisma } from '../../src/db/prisma.js'
  import { redis } from '../../src/redis/client.js'
  import {
    clearMailpit,
    cookiePair,
    extractToken,
    getCsrf,
    latestMessageTo,
    parseSetCookie,
  } from './helpers.js'

  const PW = 'CorrectHorse9!'

  async function seedVerifiedUser(email: string) {
    return prisma.user.create({
      data: {
        email,
        passwordHash: await argon2.hash(PW),
        emailVerifiedAt: new Date(), // verified so login is allowed (Plan 02 rule)
      },
    })
  }

  beforeEach(async () => {
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
    )
    await redis.flushDb()
    await clearMailpit()
  })
  ```

- [ ] **Step 2: Add the rate-limit 429 assertion group, then run it.**
  Append to the file:

  ```ts
  describe('rate limiting', () => {
    test('auth endpoint returns 429 after the configured number of attempts', async () => {
      const email = 'rl@example.com'
      // RATE_LIMIT_AUTH_MAX is pinned to 3 in vitest.config.ts.
      // csrfProtection runs BEFORE the limiter, so a CSRF-less POST returns 403
      // and never reaches the limiter. Bootstrap a fresh CSRF token + cookie per
      // attempt and send both on every login attempt so each request reaches the
      // limiter and counts against the per-IP budget.
      const attempt = async () => {
        const { token, cookie } = await getCsrf()
        return request(app)
          .post('/api/auth/login')
          .set('Cookie', cookie)
          .set('x-csrf-token', token)
          .send({ email, password: 'wrong-password' })
      }

      // First 3 attempts are processed (401 for bad creds), not rate-limited.
      const r1 = await attempt()
      const r2 = await attempt()
      const r3 = await attempt()
      expect(r1.status).toBe(401)
      expect(r2.status).toBe(401)
      expect(r3.status).toBe(401)

      // The 4th attempt exceeds the budget -> 429.
      const r4 = await attempt()
      expect(r4.status).toBe(429)
      // draft-8 combined header is present; legacy X-RateLimit-* are gone.
      expect(r4.headers['ratelimit']).toBeDefined()
      expect(r4.headers['x-ratelimit-limit']).toBeUndefined()
    })
  })
  ```

  Run only this group:

  ```bash
  npx vitest run tests/security/hardening.test.ts -t "rate limiting"
  ```

  Expected: **1 passed**. If you instead see 403 on every attempt, the requests are not carrying a valid CSRF token/cookie and `csrfProtection` is rejecting them before the limiter — confirm `getCsrf()` returns a usable token+cookie and that both are set on each attempt. If you instead see all four return 401, the `authLimiter` is not mounted on `/api/auth` (revisit Task 2 Step 3) or `redis.flushDb()` is not resetting the `rl:auth:` counters (confirm the limiter and the flushed client are the same instance).

- [ ] **Step 3: Add the CSRF 403 assertion group, then run it.**
  Append:

  ```ts
  describe('CSRF double-submit protection', () => {
    test('mutating request with NO x-csrf-token is rejected 403', async () => {
      await request(app)
        .post('/api/auth/register')
        .send({ email: 'csrf-none@example.com', password: PW })
        .expect(403)
    })

    test('mutating request with WRONG x-csrf-token is rejected 403', async () => {
      const { cookie } = await getCsrf()
      await request(app)
        .post('/api/auth/register')
        .set('Cookie', cookie)
        .set('x-csrf-token', 'not-the-real-token')
        .send({ email: 'csrf-wrong@example.com', password: PW })
        .expect(403)
    })

    test('mutating request with matching token + cookie succeeds (201)', async () => {
      const { token, cookie } = await getCsrf()
      await request(app)
        .post('/api/auth/register')
        .set('Cookie', cookie)
        .set('x-csrf-token', token)
        .send({ email: 'csrf-ok@example.com', password: PW })
        .expect(201)
    })
  })
  ```

  Run:

  ```bash
  npx vitest run tests/security/hardening.test.ts -t "CSRF"
  ```

  Expected: **3 passed**. If the "matching token" test 403s, the csrf cookie name detection in `helpers.getCsrf()` is wrong — log `parseSetCookie(res)` from `GET /api/csrf` and adjust the `n.includes('csrf')` match to the actual cookie name (csrf-csrf is configured with `cookieName: 'x-csrf-token'`, not the library default `__Host-psifi.x-csrf-token`).

- [ ] **Step 4: Add the enumeration-parity assertion group, then run it.**
  Append:

  ```ts
  describe('account enumeration parity', () => {
    test('login gives identical generic response for unknown vs known email', async () => {
      await seedVerifiedUser('known-login@example.com')

      const csrfA = await getCsrf()
      const known = await request(app)
        .post('/api/auth/login')
        .set('Cookie', csrfA.cookie)
        .set('x-csrf-token', csrfA.token)
        .send({ email: 'known-login@example.com', password: 'wrong-password' })

      const csrfB = await getCsrf()
      const unknown = await request(app)
        .post('/api/auth/login')
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send({ email: 'nobody-login@example.com', password: 'wrong-password' })

      // Same status and same body shape — no signal that the email exists.
      expect(known.status).toBe(401)
      expect(unknown.status).toBe(401)
      expect(unknown.body).toEqual(known.body)
    })

    test('forgot-password always returns 200 for unknown and known email', async () => {
      await seedVerifiedUser('known-forgot@example.com')

      const csrfA = await getCsrf()
      const known = await request(app)
        .post('/api/auth/forgot-password')
        .set('Cookie', csrfA.cookie)
        .set('x-csrf-token', csrfA.token)
        .send({ email: 'known-forgot@example.com' })

      const csrfB = await getCsrf()
      const unknown = await request(app)
        .post('/api/auth/forgot-password')
        .set('Cookie', csrfB.cookie)
        .set('x-csrf-token', csrfB.token)
        .send({ email: 'nobody-forgot@example.com' })

      expect(known.status).toBe(200)
      expect(unknown.status).toBe(200)
      expect(unknown.body).toEqual(known.body)

      // Side-effect differs (mail only for the known user) but the RESPONSE does not.
      const knownMail = await latestMessageTo('known-forgot@example.com')
      const unknownMail = await latestMessageTo('nobody-forgot@example.com')
      expect(knownMail).not.toBeNull()
      expect(unknownMail).toBeNull()
    })
  })
  ```

  Run:

  ```bash
  npx vitest run tests/security/hardening.test.ts -t "enumeration"
  ```

  Expected: **2 passed**. If `unknown.body` differs from `known.body`, the service is leaking existence — that is a real bug to fix in `auth.service.ts` (return the identical generic error), not a test to weaken.

  > **Timing note (document only, do not test):** identical *bodies* defeat naive enumeration, but a known email path that runs `argon2.verify` while an unknown path returns early is a *timing* oracle. The service should verify against a dummy argon2 hash even when the user is absent so both paths spend comparable CPU. Record this in `docs/SECURITY.md` (Task 6); a wall-clock assertion in CI is too flaky to gate on.

- [ ] **Step 5: Add the cookie-attribute + session-fixation assertion group, then run it.**
  Append:

  ```ts
  describe('session cookie hardening and fixation defence', () => {
    test('__Host-sid cookie is httpOnly, Secure, SameSite and Path=/', async () => {
      await seedVerifiedUser('cookie@example.com')
      const { token, cookie } = await getCsrf()

      const res = await request(app)
        .post('/api/auth/login')
        .set('Cookie', cookie)
        .set('x-csrf-token', token)
        .send({ email: 'cookie@example.com', password: PW })
        .expect(200)

      const sid = parseSetCookie(res)['__Host-sid']
      expect(sid).toBeDefined()
      expect(sid).toMatch(/HttpOnly/i)
      expect(sid).toMatch(/Secure/i)
      expect(sid).toMatch(/SameSite=Lax/i)
      expect(sid).toMatch(/Path=\//i)
      // __Host- prefix forbids a Domain attribute.
      expect(sid).not.toMatch(/Domain=/i)
    })

    test('session id is regenerated on login (anti-fixation)', async () => {
      await seedVerifiedUser('fix@example.com')

      // 1) Acquire a pre-auth session id via the csrf bootstrap (which touches the session).
      const pre = await request(app).get('/api/csrf').expect(200)
      const preSid = parseSetCookie(pre)['__Host-sid']

      // 2) Log in, carrying any pre-auth cookies + csrf token.
      const csrf = await getCsrf()
      const login = await request(app)
        .post('/api/auth/login')
        .set('Cookie', [csrf.cookie, preSid ? cookiePair(preSid) : ''].filter(Boolean))
        .set('x-csrf-token', csrf.token)
        .send({ email: 'fix@example.com', password: PW })
        .expect(200)

      const postSid = parseSetCookie(login)['__Host-sid']
      expect(postSid).toBeDefined()
      // A fresh Set-Cookie for the session id proves regeneration occurred.
      // The signed value must differ from any pre-auth id.
      if (preSid) {
        expect(cookiePair(postSid)).not.toEqual(cookiePair(preSid))
      }
    })
  })
  ```

  Run:

  ```bash
  npx vitest run tests/security/hardening.test.ts -t "fixation"
  ```

  Expected: **2 passed**. If `Secure` is missing from the cookie, the app under test is not seeing HTTPS — confirm `app.set('trust proxy', 1)` is set in `app.ts` (FOUNDATION/library ref: required for express-session to emit the Secure cookie behind a proxy). Supertest connects over plain http, so for the test to see `Secure` the session cookie config must set `secure: true` unconditionally (the `__Host-` prefix requires it); if your code conditions `secure` on `NODE_ENV`, ensure the test env keeps it `true`.

- [ ] **Step 6: Add the single-use-token assertion group, then run it.**
  Append:

  ```ts
  describe('verification / reset token single-use', () => {
    test('a password-reset token cannot be consumed twice', async () => {
      await seedVerifiedUser('single@example.com')

      // Trigger a PASSWORD_RESET email.
      const f = await getCsrf()
      await request(app)
        .post('/api/auth/forgot-password')
        .set('Cookie', f.cookie)
        .set('x-csrf-token', f.token)
        .send({ email: 'single@example.com' })
        .expect(200)

      const mail = await latestMessageTo('single@example.com')
      expect(mail).not.toBeNull()
      const rawToken = extractToken((mail!.Text || mail!.HTML) ?? '')

      // First reset: succeeds and consumes the token.
      const r1csrf = await getCsrf()
      await request(app)
        .post('/api/auth/reset-password')
        .set('Cookie', r1csrf.cookie)
        .set('x-csrf-token', r1csrf.token)
        .send({ token: rawToken, password: 'BrandNewPw1!' })
        .expect(200)

      // Second reset with the SAME token: rejected (consumedAt is set).
      const r2csrf = await getCsrf()
      const second = await request(app)
        .post('/api/auth/reset-password')
        .set('Cookie', r2csrf.cookie)
        .set('x-csrf-token', r2csrf.token)
        .send({ token: rawToken, password: 'AnotherPw2!' })
      expect(second.status).toBe(400)

      // The DB row is marked consumed (token stored only as a hash, never plaintext).
      const tokens = await prisma.verificationToken.findMany({
        where: { type: 'PASSWORD_RESET' },
      })
      expect(tokens).toHaveLength(1)
      expect(tokens[0].consumedAt).not.toBeNull()
      expect(tokens[0].tokenHash).not.toContain(rawToken) // stored as sha256, not raw
    })
  })
  ```

  Run:

  ```bash
  npx vitest run tests/security/hardening.test.ts -t "single-use"
  ```

  Expected: **1 passed**. If the second reset returns 200, the consume-check in `auth.service.ts` is missing or the `consumedAt` filter is wrong — that is a real bug. If `extractToken` throws, inspect the mail body (`console.log(mail)`) and widen the regex or read the token from the link query string.

- [ ] **Step 7: Run the WHOLE security suite to confirm no cross-test bleed.**

  ```bash
  npx vitest run tests/security/hardening.test.ts
  ```

  Expected: **all tests passed** (rate-limit 1 + CSRF 3 + enumeration 2 + cookie/fixation 2 + single-use 1 = 9). Because `beforeEach` truncates Postgres + flushes Redis + clears Mailpit, the rate-limit counters reset between tests, so ordering does not matter. If a later test 429s unexpectedly, the Redis flush is not hitting the limiter's client — confirm `rateLimit.ts` and the test import the same `redis` singleton.

- [ ] **Step 8: Run the FULL api test suite to confirm hardening broke nothing upstream.**

  ```bash
  npx vitest run
  ```

  Expected: every pre-existing suite (auth, account, admin, csrf, health) still passes. The tightened CSP and limiters must not regress the existing flows. If an existing test now 429s, it is hammering an auth endpoint more than 3 times under the pinned test limit — either raise `RATE_LIMIT_AUTH_MAX` in `vitest.config.ts` to a value that satisfies both that test and the 429 test (e.g. set the 429 test to use a per-test override) or add a `redis.flushDb()` in that suite's `beforeEach`.

- [ ] **Step 9: Commit.**

  ```bash
  git add apps/api/tests/security/hardening.test.ts apps/api/vitest.config.ts
  git commit -m "test: add security regression suite (429, csrf 403, enumeration parity, cookie attrs, fixation, single-use tokens)"
  ```

---

## Task 6: Write `docs/SECURITY.md` (what is protected + how) and the pre-prod checklist

Capture the proven guarantees so a reader understands the threat model and the go-live gate. This file is the human-readable counterpart to the regression suite.

**Files**
- Create: `docs/SECURITY.md`
- Modify: `docs/ROADMAP.md`

- [ ] **Step 1: Create `docs/SECURITY.md`.**
  Write the file with this exact content (it references only mechanisms that exist in this codebase):

  ```markdown
  # Security model

  This document states what the authentication-flow API protects against and how.
  Each guarantee is enforced by code and locked by `apps/api/tests/security/hardening.test.ts`.

  ## Threat model (in scope)

  - Session theft via XSS — sessions are opaque IDs in an `httpOnly` cookie; JS cannot read them.
  - Cross-site request forgery on mutating endpoints.
  - Credential stuffing / brute force on auth endpoints.
  - Account enumeration (probing which emails are registered).
  - Session fixation (reusing a pre-auth session id after login).
  - Token replay (reusing an email verification / password-reset token).
  - Common header-based attacks (clickjacking, MIME sniffing, mixed content).

  Out of scope for now (see `ROADMAP.md` §10): breached-password checks, CAPTCHA/bot
  protection, new-device login alerts, 2FA/TOTP, pentest.

  ## Controls and how they are enforced

  ### Sessions and cookies
  - Server-side opaque sessions: `express-session` + `connect-redis` (Redis store). No JWT.
  - Cookie `__Host-sid`: `httpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, no `Domain`.
    The `__Host-` prefix requires Secure + Path=/ + no Domain — browsers reject it otherwise.
  - `app.set('trust proxy', 1)` so the Secure cookie is emitted behind the Caddy proxy.
  - Session id is regenerated (`req.session.regenerate`) on successful login (anti-fixation).
  - A per-user Redis set (`user_sessions:<userId>`, via `lib/sessionStore.ts`) lets
    logout-all and password-reset destroy every session for a user immediately.

  ### CSRF
  - Double-submit token via `csrf-csrf` (the maintained replacement for the archived `csurf`).
  - A non-`httpOnly` cookie carries the token; the SPA echoes it in the `x-csrf-token` header
    on every mutating request; the middleware compares them (HMAC, bound to the session id).
  - `GET /api/csrf` issues the token. GET/HEAD/OPTIONS are exempt; POST/PUT/PATCH/DELETE are protected.
  - Verified: a mutating request with no token, or a wrong token, returns 403.

  ### Rate limiting
  - `express-rate-limit` with a `rate-limit-redis` store (shared across api instances).
  - Global limiter (default 300 / 15 min) plus a tight auth limiter (default 10 / 15 min)
    on login, register, resend-verification, forgot-password, reset-password.
  - Exceeding the budget returns HTTP 429. Thresholds are env-tunable
    (`RATE_LIMIT_*` in `.env`); headers use IETF `draft-8` (`RateLimit`), legacy `X-RateLimit-*` off.

  ### Password hashing
  - `argon2id` with node-argon2 defaults (64 MiB, t=3, p=4) — exceeds OWASP 2026 minimums.
  - Passwords are never stored; only the PHC-encoded hash in `User.passwordHash`.

  ### Anti-enumeration
  - Login returns an identical generic 401 body for unknown vs known emails.
  - `forgot-password` always returns 200; mail is sent only when the user exists, but the
    HTTP response is identical either way.
  - **Timing:** the login path verifies against a dummy (decoy) argon2 hash when the user is
    absent so both branches spend comparable CPU, removing a timing oracle. This decoy
    `argon2.verify` is implemented in Plan 01's `verifyCredentials` (`auth.service.ts`).
    (Behavioural, not asserted by a wall-clock test — that would be flaky in CI.)

  ### Token hygiene (email verify / password reset / email change)
  - Tokens are stored only as a `sha256` hash (`VerificationToken.tokenHash`), never plaintext.
  - Single-use: `consumedAt` is set on first use; a second use is rejected (400).
  - Short expiry (`expiresAt`) and timing-safe comparison on lookup.

  ### Transport and headers (helmet)
  - HTTPS everywhere (Caddy `tls internal` in dev so Secure cookies work on `https://localhost`).
  - HSTS: `max-age=31536000; includeSubDomains` (preload deliberately off until the prod domain is fixed).
  - Content-Security-Policy tuned for the SPA: `default-src 'self'`, `script-src 'self'`,
    `connect-src 'self'`, `object-src 'none'`, `frame-ancestors 'self'`, `base-uri 'self'`.
  - CORS locked to the single origin (`APP_URL`) with `credentials: true` — never `*`.

  ### Input validation
  - Every request body is validated with Zod (`*.schema.ts`); invalid input returns 400 before
    any side effect (e.g. before hashing).

  ## Manual pre-prod checklist

  Run through this before any production deploy. Nothing here is automated.

  - [ ] `SESSION_SECRET` and `CSRF_SECRET` are freshly generated (>= 32 bytes), unique per env,
        and stored as real secrets (not committed, not in the image).
  - [ ] `NODE_ENV=production`.
  - [ ] `APP_URL` is the real HTTPS origin; CORS origin matches it exactly.
  - [ ] TLS is real (public CA), not `tls internal`; HSTS is acceptable for the domain.
  - [ ] Decide on HSTS `preload`: only enable after committing to HTTPS-forever for the domain.
  - [ ] Cookie is confirmed `__Host-sid` with Secure + HttpOnly + SameSite=Lax in the browser.
  - [ ] `RATE_LIMIT_AUTH_MAX` / windows set to production values (not the test value of 3).
  - [ ] Redis is reachable, persistent enough for sessions, and not publicly exposed.
  - [ ] Postgres credentials are production-grade; DB not publicly exposed; backups configured.
  - [ ] Mailpit is replaced by a real SMTP provider; `MAIL_FROM` is a real address.
  - [ ] `prisma migrate deploy` (never `migrate dev`) runs at container start.
  - [ ] `npx vitest run` is green in CI, including `tests/security/hardening.test.ts`.
  - [ ] Server error responses do not leak stack traces or whether an email exists.
  - [ ] Dependency audit (`npm audit`) reviewed; no known-critical advisories shipped.
  ```

- [ ] **Step 2: Tick the ROADMAP item.**
  Open `docs/ROADMAP.md`, find the §10 line that reads `✅ **Baseline (ใส่ทุกข้อ)**: ...` and append `; พิสูจน์ด้วย regression test suite (`tests/security/hardening.test.ts`) + `docs/SECURITY.md`` to the end of that bullet so the roadmap records that the baseline is now proven, not just present. Make the edit as a single appended clause; do not restructure the file.

- [ ] **Step 3: Sanity-check the markdown renders (no broken fences).**

  ```bash
  npx --yes markdownlint-cli docs/SECURITY.md || true
  ```

  Expected: either clean output or only minor style warnings (line length). This is advisory; do not block on style-only warnings. If `markdownlint-cli` is unavailable offline, skip — just visually confirm every code fence is closed.

- [ ] **Step 4: Commit.**

  ```bash
  git add docs/SECURITY.md docs/ROADMAP.md
  git commit -m "docs: add SECURITY.md threat model + pre-prod checklist; mark baseline proven"
  ```

---

## Task 7: Final verification of the whole slice

- [ ] **Step 1: Type-check the entire api package.**
  Inside the api container:

  ```bash
  npx tsc --noEmit
  ```

  Expected: exit code 0, no errors.

- [ ] **Step 2: Run the entire api test suite one final time.**

  ```bash
  npx vitest run
  ```

  Expected: all suites pass, including the new `tests/security/hardening.test.ts` (9 tests). This is the green-bar gate for the slice.

- [ ] **Step 3: Confirm the working tree is clean and the commits are present.**
  From the repo root:

  ```bash
  git status --short
  git log --oneline -8
  ```

  Expected: `git status --short` prints nothing (everything committed); `git log` shows the seven commits from Tasks 1–6 (config tunables, limiters, helmet, helpers, vitest pin, regression suite, docs) in order. The slice is complete: no new endpoints, hardened config, a proving regression suite, and security documentation with a go-live checklist.
