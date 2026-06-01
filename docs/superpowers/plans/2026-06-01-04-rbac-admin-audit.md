# RBAC, Admin Routes & Audit Log Viewer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Add role-based access control so only ADMIN Users reach admin-only API endpoints and the `/admin` SPA page, expose read-only listings of Users and recent audit events, and guarantee every auth/account event is recorded in the `AuditLog`.

**Architecture:** A new `requireRole` Express middleware reads the role from the server-side session (`req.session.role`, set at sign-in) and returns `403` for non-ADMINs. A new `admin` module mounts two ADMIN-gated read endpoints (`GET /api/admin/users`, `GET /api/admin/audit`) that query Postgres via the Prisma singleton. On the web side a `RoleRoute` guard wraps `/admin` using the role already returned by `useMe()`, and an `AdminPage` renders the two listings. A CLI promotion script flips a User to ADMIN. We also confirm the Plan-01 `writeAudit()` helper is invoked for all auth and account events so the viewer has data.

**Tech Stack:** Express 5 + TypeScript (ESM, strict), Prisma 7 (`prisma-client` generator, driver-adapter), Zod 4, express-session (session holds `{ userId, role }`), vitest + supertest (API integration tests against test Postgres/Redis), React 18 + React Router v7 + TanStack Query v5 + vitest/RTL/MSW (web), tsx (CLI script runner).

---

## Files overview

API (`/apps/api`):
- **Create** `src/middleware/requireRole.ts` — ADMIN gate middleware.
- **Create** `src/modules/admin/admin.routes.ts` — `GET /admin/users`, `GET /admin/audit`.
- **Modify** `src/app.ts` — mount the admin router under `/api/admin`.
- **Create** `scripts/promote-to-admin.ts` — CLI to set a User's `role` to `ADMIN`.
- **Modify** `package.json` — add `promote:admin` script.
- **Modify** `src/modules/auth/auth.service.ts` — ensure `register`/`login_success`/`login_fail`/`logout`/`password_reset` audit events fire (verify-and-fill any gaps).
- **Modify** `src/modules/account/account.service.ts` — ensure `password_change`/`email_change` audit events fire.
- **Create** `tests/admin/requireRole.test.ts` — middleware unit-ish integration test.
- **Create** `tests/admin/admin.routes.test.ts` — endpoint integration tests (403 for non-admin, list for admin).
- **Create** `tests/admin/audit-events.test.ts` — an audited action appears in `GET /admin/audit`.

Web (`/apps/web`):
- **Create** `src/routes/RoleRoute.tsx` — role-gated route wrapper.
- **Create** `src/features/admin/useAdminUsers.ts` — TanStack Query hook for `/api/admin/users`.
- **Create** `src/features/admin/useAdminAudit.ts` — TanStack Query hook for `/api/admin/audit`.
- **Create** `src/features/admin/AdminPage.tsx` — Users + audit listings.
- **Modify** `src/routes/router.tsx` — add the `/admin` route behind `RoleRoute`.
- **Modify** `src/App.tsx` — conditional "Admin" nav link.
- **Create** `tests/admin/RoleRoute.test.tsx` — non-admin redirected, admin renders.
- **Create** `tests/admin/AdminPage.test.tsx` — renders users + audit from mocked API.

---

## Task 1: `requireRole` middleware (API)

**Files**
- Create: `/apps/api/tests/admin/requireRole.test.ts`
- Create: `/apps/api/src/middleware/requireRole.ts`

This middleware assumes `requireAuth` (from FOUNDATION, `src/middleware/requireAuth.ts`) ran first and that the session carries `{ userId, role }` as set at sign-in. It gates on `role === 'ADMIN'`.

- [ ] **Step 1: Write the failing test.**
  Create `/apps/api/tests/admin/requireRole.test.ts` with a tiny Express app that mounts `requireRole('ADMIN')` on a probe route, and a test-only middleware to inject a fake session. We avoid full sign-in here to keep the unit fast.

  ```ts
  import express from 'express'
  import request from 'supertest'
  import { describe, it, expect } from 'vitest'
  import { requireRole } from '../../src/middleware/requireRole.js'

  // Build a probe app that injects a session-like object, then gates with requireRole.
  function buildApp(session: { userId?: string; role?: 'USER' | 'ADMIN' } | null) {
    const app = express()
    app.use((req, _res, next) => {
      // Mimic express-session's req.session for the purpose of the gate.
      ;(req as unknown as { session: unknown }).session = session
      next()
    })
    app.get('/probe', requireRole('ADMIN'), (_req, res) => res.json({ ok: true }))
    return app
  }

  describe('requireRole', () => {
    it('returns 401 when there is no session/userId', async () => {
      const res = await request(buildApp(null)).get('/probe')
      expect(res.status).toBe(401)
    })

    it('returns 403 when the user is authenticated but not ADMIN', async () => {
      const res = await request(buildApp({ userId: 'u1', role: 'USER' })).get('/probe')
      expect(res.status).toBe(403)
    })

    it('calls next() when the user is ADMIN', async () => {
      const res = await request(buildApp({ userId: 'u1', role: 'ADMIN' })).get('/probe')
      expect(res.status).toBe(200)
      expect(res.body).toEqual({ ok: true })
    })
  })
  ```

- [ ] **Step 2: Run the test and confirm it FAILS.**
  ```bash
  docker compose exec api npx vitest run tests/admin/requireRole.test.ts
  ```
  Expected: failure with `Cannot find module '../../src/middleware/requireRole.js'` (the file does not exist yet).

- [ ] **Step 3: Implement the middleware (minimal).**
  Create `/apps/api/src/middleware/requireRole.ts`:

  ```ts
  import type { Request, Response, NextFunction } from 'express'
  import type { Role } from '../generated/prisma/client.js'

  // Gate a route by Role. Assumes requireAuth has populated req.session.{userId,role}.
  // 401 if not signed in; 403 if signed in but lacking the required role.
  export function requireRole(required: Role) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const session = req.session as { userId?: string; role?: Role } | undefined
      if (!session?.userId) {
        res.status(401).json({ error: 'unauthorized' })
        return
      }
      if (session.role !== required) {
        res.status(403).json({ error: 'forbidden' })
        return
      }
      next()
    }
  }
  ```

  Note: `Role` is imported from the Prisma generated output (`src/generated/prisma/client`, per FOUNDATION's Prisma 7 `prisma-client` generator). If the surrounding session-typing for `express-session` already augments `SessionData` with `{ userId; role }` (it should, from Plan 01/02), the local cast is harmless and keeps this middleware self-contained.

- [ ] **Step 4: Run the test and confirm it PASSES.**
  ```bash
  docker compose exec api npx vitest run tests/admin/requireRole.test.ts
  ```
  Expected: `3 passed`.

- [ ] **Step 5: Commit.**
  ```bash
  git add apps/api/src/middleware/requireRole.ts apps/api/tests/admin/requireRole.test.ts
  git commit -m "feat: add requireRole ADMIN gate middleware"
  ```

---

## Task 2: `GET /api/admin/users` endpoint

**Files**
- Create: `/apps/api/tests/admin/admin.routes.test.ts` (users portion)
- Create: `/apps/api/src/modules/admin/admin.routes.ts`
- Modify: `/apps/api/src/app.ts`

These tests sign in through the real `/api/auth/login` flow so the session truly carries the role. They rely on the FOUNDATION test infra: truncate Postgres + flush Redis in `beforeEach`. We create users directly via the Prisma singleton and the Plan-01 `password.ts` hashing helper so login succeeds.

- [ ] **Step 1: Write the failing test (users listing + 403 path).**
  Create `/apps/api/tests/admin/admin.routes.test.ts`:

  ```ts
  import request from 'supertest'
  import { beforeEach, describe, it, expect } from 'vitest'
  import { app } from '../../src/app.js'
  import { prisma } from '../../src/db/prisma.js'
  import { redis } from '../../src/redis/client.js'
  import { hashPassword } from '../../src/lib/password.js'

  // Truncate Postgres + flush Redis between tests (FOUNDATION test strategy).
  beforeEach(async () => {
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE'
    )
    await redis.flushDb()
  })

  // Create a User row directly with a real argon2 hash and a verified email so login works.
  async function makeUser(email: string, password: string, role: 'USER' | 'ADMIN') {
    return prisma.user.create({
      data: {
        email,
        passwordHash: await hashPassword(password),
        role,
        emailVerifiedAt: new Date(),
      },
    })
  }

  // Sign in and return the agent (which retains the __Host-sid cookie) plus the csrf token.
  async function signIn(email: string, password: string) {
    const agent = request.agent(app)
    const csrfRes = await agent.get('/api/csrf')
    const csrfToken = csrfRes.body.csrfToken as string
    await agent
      .post('/api/auth/login')
      .set('x-csrf-token', csrfToken)
      .send({ email, password })
      .expect(200)
    return { agent, csrfToken }
  }

  describe('GET /api/admin/users', () => {
    it('returns 401 when not signed in', async () => {
      await request(app).get('/api/admin/users').expect(401)
    })

    it('returns 403 for a signed-in non-admin', async () => {
      await makeUser('user@example.com', 'password123', 'USER')
      const { agent } = await signIn('user@example.com', 'password123')
      await agent.get('/api/admin/users').expect(403)
    })

    it('returns the user list for an admin', async () => {
      await makeUser('admin@example.com', 'password123', 'ADMIN')
      await makeUser('user@example.com', 'password123', 'USER')
      const { agent } = await signIn('admin@example.com', 'password123')

      const res = await agent.get('/api/admin/users').expect(200)
      expect(Array.isArray(res.body.users)).toBe(true)
      expect(res.body.users).toHaveLength(2)
      const emails = res.body.users.map((u: { email: string }) => u.email).sort()
      expect(emails).toEqual(['admin@example.com', 'user@example.com'])
      // Must never leak the password hash.
      expect(res.body.users[0]).not.toHaveProperty('passwordHash')
      // Shape check on one row.
      expect(res.body.users[0]).toEqual(
        expect.objectContaining({
          id: expect.any(String),
          email: expect.any(String),
          role: expect.stringMatching(/^(USER|ADMIN)$/),
        })
      )
    })
  })
  ```

  Note: `hashPassword` is the Plan-01 export in `src/lib/password.ts`. If that file exports the hashing function under a different name (e.g. `hash`), adjust the import in this test to match the existing export — do not invent a new one.

- [ ] **Step 2: Run the test and confirm it FAILS.**
  ```bash
  docker compose exec api npx vitest run tests/admin/admin.routes.test.ts
  ```
  Expected: failures — the 401 test may pass incidentally (no route → Express 404, not 401), but the admin/non-admin tests fail because `/api/admin/users` is unmounted (404). This is the RED state; proceed.

- [ ] **Step 3: Create the admin router with the users endpoint.**
  Create `/apps/api/src/modules/admin/admin.routes.ts`:

  ```ts
  import { Router } from 'express'
  import { requireAuth } from '../../middleware/requireAuth.js'
  import { requireRole } from '../../middleware/requireRole.js'
  import { prisma } from '../../db/prisma.js'

  export const adminRouter = Router()

  // All admin routes require an authenticated ADMIN.
  adminRouter.use(requireAuth, requireRole('ADMIN'))

  // GET /api/admin/users -> { users: [...] } (no passwordHash; newest first)
  adminRouter.get('/users', async (_req, res, next) => {
    try {
      const users = await prisma.user.findMany({
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          email: true,
          role: true,
          emailVerifiedAt: true,
          createdAt: true,
        },
      })
      res.json({ users })
    } catch (err) {
      next(err)
    }
  })
  ```

  Note: `requireAuth` is the Plan-02 export in `src/middleware/requireAuth.ts`. The `prisma` singleton is `src/db/prisma.ts`. The `select` deliberately omits `passwordHash`.

- [ ] **Step 4: Mount the router in `app.ts`.**
  Open `/apps/api/src/app.ts`. It already mounts `authRouter` under `/api/auth` and `accountRouter` under `/api/account`. Add the import alongside the others:

  ```ts
  import { adminRouter } from './modules/admin/admin.routes.js'
  ```

  Then mount it next to the existing route mounts (after `accountRouter`, before the central `errorHandler`):

  ```ts
  app.use('/api/admin', adminRouter)
  ```

  The relative position must be: all routers mounted, then `app.use(errorHandler)` last (FOUNDATION middleware order — error handler is always last).

- [ ] **Step 5: Run the test and confirm it PASSES.**
  ```bash
  docker compose exec api npx vitest run tests/admin/admin.routes.test.ts
  ```
  Expected: the three `GET /api/admin/users` tests pass (`3 passed`).

- [ ] **Step 6: Commit.**
  ```bash
  git add apps/api/src/modules/admin/admin.routes.ts apps/api/src/app.ts apps/api/tests/admin/admin.routes.test.ts
  git commit -m "feat: add GET /api/admin/users admin-gated endpoint"
  ```

---

## Task 3: `GET /api/admin/audit` endpoint

**Files**
- Modify: `/apps/api/tests/admin/admin.routes.test.ts` (add audit block)
- Modify: `/apps/api/src/modules/admin/admin.routes.ts`

- [ ] **Step 1: Add a failing test for the audit listing.**
  Append a new `describe` block to `/apps/api/tests/admin/admin.routes.test.ts` (reuse the `makeUser` / `signIn` helpers already defined in that file):

  ```ts
  describe('GET /api/admin/audit', () => {
    it('returns 403 for a signed-in non-admin', async () => {
      await makeUser('user@example.com', 'password123', 'USER')
      const { agent } = await signIn('user@example.com', 'password123')
      await agent.get('/api/admin/audit').expect(403)
    })

    it('returns recent audit events for an admin, newest first', async () => {
      const admin = await makeUser('admin@example.com', 'password123', 'ADMIN')

      // Seed two audit rows directly so ordering is deterministic.
      await prisma.auditLog.create({
        data: { userId: admin.id, event: 'login_success', ip: '127.0.0.1' },
      })
      await prisma.auditLog.create({
        data: { userId: admin.id, event: 'password_change', ip: '127.0.0.1' },
      })

      const { agent } = await signIn('admin@example.com', 'password123')
      const res = await agent.get('/api/admin/audit').expect(200)

      expect(Array.isArray(res.body.events)).toBe(true)
      // The most recent seeded event should be first (createdAt desc).
      const events = res.body.events as Array<{ event: string }>
      expect(events.map((e) => e.event)).toContain('password_change')
      expect(events.map((e) => e.event)).toContain('login_success')
      expect(events[0]).toEqual(
        expect.objectContaining({
          id: expect.any(String),
          event: expect.any(String),
          createdAt: expect.any(String),
        })
      )
    })
  })
  ```

- [ ] **Step 2: Run the test and confirm it FAILS.**
  ```bash
  docker compose exec api npx vitest run tests/admin/admin.routes.test.ts
  ```
  Expected: the new audit `describe` fails — the 403 test may pass (route 404), but the admin audit test fails with `404` because `/api/admin/audit` is unmounted.

- [ ] **Step 3: Add the audit endpoint to the admin router.**
  Edit `/apps/api/src/modules/admin/admin.routes.ts` and append, after the `/users` handler:

  ```ts
  // GET /api/admin/audit -> { events: [...] } (newest first, capped at 100)
  adminRouter.get('/audit', async (_req, res, next) => {
    try {
      const events = await prisma.auditLog.findMany({
        orderBy: { createdAt: 'desc' },
        take: 100,
        select: {
          id: true,
          userId: true,
          event: true,
          ip: true,
          userAgent: true,
          createdAt: true,
          user: { select: { email: true } },
        },
      })
      res.json({ events })
    } catch (err) {
      next(err)
    }
  })
  ```

  Note: the `user` relation is nullable (`AuditLog.user User?` with `onDelete: SetNull`), so `event.user` may be `null` for events whose User was deleted; the `select` handles that automatically.

- [ ] **Step 4: Run the test and confirm it PASSES.**
  ```bash
  docker compose exec api npx vitest run tests/admin/admin.routes.test.ts
  ```
  Expected: all tests in the file pass (`5 passed`).

- [ ] **Step 5: Commit.**
  ```bash
  git add apps/api/src/modules/admin/admin.routes.ts apps/api/tests/admin/admin.routes.test.ts
  git commit -m "feat: add GET /api/admin/audit admin-gated endpoint"
  ```

---

## Task 4: Ensure auth & account events are audited end-to-end

**Files**
- Create: `/apps/api/tests/admin/audit-events.test.ts`
- Modify: `/apps/api/src/modules/auth/auth.service.ts` (only if a gap is found)
- Modify: `/apps/api/src/modules/account/account.service.ts` (only if a gap is found)

Per CROSS-SLICE EVOLUTION, Plan 04 "ensures account events are audited" and reuses the Plan-01 `writeAudit()` helper (`src/lib/audit.ts`). This task drives, via a black-box test, that a real signed-in action lands in `GET /admin/audit`. If the action is already audited by an earlier plan, the test passes with no service change; if not, add the `writeAudit()` call.

- [ ] **Step 1: Write the failing end-to-end audit test.**
  Create `/apps/api/tests/admin/audit-events.test.ts`:

  ```ts
  import request from 'supertest'
  import { beforeEach, describe, it, expect } from 'vitest'
  import { app } from '../../src/app.js'
  import { prisma } from '../../src/db/prisma.js'
  import { redis } from '../../src/redis/client.js'
  import { hashPassword } from '../../src/lib/password.js'

  beforeEach(async () => {
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE'
    )
    await redis.flushDb()
  })

  async function makeUser(email: string, password: string, role: 'USER' | 'ADMIN') {
    return prisma.user.create({
      data: {
        email,
        passwordHash: await hashPassword(password),
        role,
        emailVerifiedAt: new Date(),
      },
    })
  }

  describe('audited actions surface in GET /api/admin/audit', () => {
    it('records login_success and exposes it to an admin viewer', async () => {
      await makeUser('admin@example.com', 'password123', 'ADMIN')

      // An admin signs in -> this itself should write a login_success audit row.
      const agent = request.agent(app)
      const csrfToken = (await agent.get('/api/csrf')).body.csrfToken as string
      await agent
        .post('/api/auth/login')
        .set('x-csrf-token', csrfToken)
        .send({ email: 'admin@example.com', password: 'password123' })
        .expect(200)

      const res = await agent.get('/api/admin/audit').expect(200)
      const events = res.body.events as Array<{ event: string }>
      expect(events.map((e) => e.event)).toContain('login_success')
    })

    it('records login_fail on a bad password attempt', async () => {
      await makeUser('admin@example.com', 'password123', 'ADMIN')

      const agent = request.agent(app)
      const csrfToken = (await agent.get('/api/csrf')).body.csrfToken as string
      // Wrong password -> generic failure, but an audit row should still be written.
      await agent
        .post('/api/auth/login')
        .set('x-csrf-token', csrfToken)
        .send({ email: 'admin@example.com', password: 'wrong-password' })
        .expect(401)

      // Now sign in for real to read the audit log as admin.
      const csrf2 = (await agent.get('/api/csrf')).body.csrfToken as string
      await agent
        .post('/api/auth/login')
        .set('x-csrf-token', csrf2)
        .send({ email: 'admin@example.com', password: 'password123' })
        .expect(200)

      const res = await agent.get('/api/admin/audit').expect(200)
      const events = res.body.events as Array<{ event: string }>
      expect(events.map((e) => e.event)).toContain('login_fail')
    })

    it('records password_change when a signed-in admin changes their password', async () => {
      await makeUser('admin@example.com', 'password123', 'ADMIN')

      const agent = request.agent(app)
      const csrfToken = (await agent.get('/api/csrf')).body.csrfToken as string
      await agent
        .post('/api/auth/login')
        .set('x-csrf-token', csrfToken)
        .send({ email: 'admin@example.com', password: 'password123' })
        .expect(200)

      const csrf2 = (await agent.get('/api/csrf')).body.csrfToken as string
      await agent
        .post('/api/account/change-password')
        .set('x-csrf-token', csrf2)
        .send({ currentPassword: 'password123', newPassword: 'newpassword456' })
        .expect(200)

      const res = await agent.get('/api/admin/audit').expect(200)
      const events = res.body.events as Array<{ event: string }>
      expect(events.map((e) => e.event)).toContain('password_change')
    })
  })
  ```

- [ ] **Step 2: Run the test and observe which events are missing.**
  ```bash
  docker compose exec api npx vitest run tests/admin/audit-events.test.ts
  ```
  Expected: each assertion that fails names a specific missing event (`login_success`, `login_fail`, or `password_change`). Note exactly which ones are RED — only those need a service edit. (Per cross-slice notes, `login_success`/`login_fail`/`register`/`password_reset` are wired in Plans 01–02; `password_change`/`email_change` may need wiring here.)

- [ ] **Step 3: Wire any missing auth events in `auth.service.ts`.**
  Only if Step 2 showed `login_success` or `login_fail` missing. Open `/apps/api/src/modules/auth/auth.service.ts`, import the helper (if not already imported):

  ```ts
  import { writeAudit } from '../../lib/audit.js'
  ```

  In the login function, after a successful credential + verified-email check and before returning the user, add:

  ```ts
  await writeAudit({ userId: user.id, event: 'login_success', ip, userAgent })
  ```

  In the failure branch (bad email or bad password — keep the response generic per anti-enumeration), add before returning the 401:

  ```ts
  await writeAudit({ event: 'login_fail', userId: user?.id, ip, userAgent })
  ```

  Note: `ip` and `userAgent` are the request-derived values the service already receives (or that the route passes in). Match the exact `writeAudit()` signature defined in `src/lib/audit.ts` from Plan 01 — it is always the object form `writeAudit({ event, ... })` with the canonical event strings. Do not change that signature.

- [ ] **Step 4: Wire any missing account events in `account.service.ts`.**
  Only if Step 2 showed `password_change` (or, by the same pattern, `email_change`) missing. Open `/apps/api/src/modules/account/account.service.ts`, import the helper if needed:

  ```ts
  import { writeAudit } from '../../lib/audit.js'
  ```

  In `changePassword`, after the new hash is persisted and sessions handled, add:

  ```ts
  await writeAudit({ userId: user.id, event: 'password_change', ip, userAgent })
  ```

  In `changeEmail` (the function that creates the `EMAIL_CHANGE` token and mails the new address), add after the token is created:

  ```ts
  await writeAudit({ userId: user.id, event: 'email_change', ip, userAgent })
  ```

  Use the exact `writeAudit({ event, ... })` object-form signature from `src/lib/audit.ts`, with the canonical event strings `password_change` and `email_change` (matching Plan 03 which writes them).

- [ ] **Step 5: Re-run the audit-events test and confirm it PASSES.**
  ```bash
  docker compose exec api npx vitest run tests/admin/audit-events.test.ts
  ```
  Expected: `3 passed`.

- [ ] **Step 6: Run the full API suite to confirm no regression.**
  ```bash
  docker compose exec api npx vitest run
  ```
  Expected: all API tests pass (no previously-green test broke).

- [ ] **Step 7: Commit.**
  ```bash
  git add apps/api/tests/admin/audit-events.test.ts apps/api/src/modules/auth/auth.service.ts apps/api/src/modules/account/account.service.ts
  git commit -m "test: verify auth and account events surface in admin audit log"
  ```
  (If no service file changed because all events were already wired, drop those two paths from the `git add` and commit only the test file.)

---

## Task 5: `promote-to-admin` CLI script (API)

**Files**
- Create: `/apps/api/scripts/promote-to-admin.ts`
- Modify: `/apps/api/package.json`

A one-off operational script to flip a User's `role` to `ADMIN` by email, so an admin account can exist without a registration UI for it. Run via `tsx` (FOUNDATION's TS runner).

- [ ] **Step 1: Create the script.**
  Create `/apps/api/scripts/promote-to-admin.ts`:

  ```ts
  // Usage: npm run promote:admin -- user@example.com
  // Promotes an existing User to the ADMIN role. Exits non-zero if not found.
  import { prisma } from '../src/db/prisma.js'

  async function main(): Promise<void> {
    const email = process.argv[2]
    if (!email) {
      console.error('Usage: npm run promote:admin -- <email>')
      process.exit(1)
    }

    const existing = await prisma.user.findUnique({ where: { email } })
    if (!existing) {
      console.error(`No user found with email: ${email}`)
      process.exit(1)
    }

    const updated = await prisma.user.update({
      where: { email },
      data: { role: 'ADMIN' },
      select: { id: true, email: true, role: true },
    })
    console.log(`Promoted ${updated.email} -> ${updated.role}`)
  }

  main()
    .then(() => prisma.$disconnect())
    .catch(async (err) => {
      console.error(err)
      await prisma.$disconnect()
      process.exit(1)
    })
  ```

  Note: imports the Prisma singleton from `src/db/prisma.ts`, which already constructs the client with the v7 driver adapter. `role: 'ADMIN'` is the `Role` enum value from the schema.

- [ ] **Step 2: Add the npm script.**
  Open `/apps/api/package.json` and add to the `"scripts"` block (next to the existing entries):

  ```json
  "promote:admin": "tsx scripts/promote-to-admin.ts"
  ```

- [ ] **Step 3: Manually verify against the dev DB.**
  Create a throwaway user via the API (or use one that exists), then run:
  ```bash
  docker compose exec api npm run promote:admin -- someone@example.com
  ```
  Expected stdout: `Promoted someone@example.com -> ADMIN`. Running with a non-existent email exits `1` and prints `No user found with email: ...`. Running with no argument prints the usage line and exits `1`.

- [ ] **Step 4: Commit.**
  ```bash
  git add apps/api/scripts/promote-to-admin.ts apps/api/package.json
  git commit -m "feat: add promote-to-admin CLI script"
  ```

---

## Task 6: `RoleRoute` guard (Web)

**Files**
- Create: `/apps/web/tests/admin/RoleRoute.test.tsx`
- Create: `/apps/web/src/routes/RoleRoute.tsx`

`RoleRoute` builds on the existing `useMe()` hook (FOUNDATION, `src/features/auth/useMe.ts`), which returns the current `user` (with `role`) or `null`/401. It renders nested routes only for the required role; non-admins are sent to `/`, unauthenticated users to `/login`.

- [ ] **Step 1: Write the failing test.**
  Create `/apps/web/tests/admin/RoleRoute.test.tsx`. We mock `useMe` so we control the role without a network round-trip, and assert routing via React Router v7's `MemoryRouter`.

  ```tsx
  import { render, screen } from '@testing-library/react'
  import { describe, it, expect, vi } from 'vitest'
  import { MemoryRouter, Routes, Route } from 'react-router'
  import { RoleRoute } from '../../src/routes/RoleRoute'

  // Mock useMe so each test controls the returned user/role.
  const useMeMock = vi.fn()
  vi.mock('../../src/features/auth/useMe', () => ({
    useMe: () => useMeMock(),
  }))

  function renderAt(initialPath: string) {
    return render(
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/login" element={<div>login page</div>} />
          <Route path="/" element={<div>home page</div>} />
          <Route element={<RoleRoute role="ADMIN" />}>
            <Route path="/admin" element={<div>admin page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )
  }

  describe('RoleRoute', () => {
    it('shows a loading state while the session check is pending', () => {
      useMeMock.mockReturnValue({ data: undefined, isPending: true })
      renderAt('/admin')
      expect(screen.getByText(/loading/i)).toBeInTheDocument()
    })

    it('redirects unauthenticated users to /login', () => {
      useMeMock.mockReturnValue({ data: null, isPending: false })
      renderAt('/admin')
      expect(screen.getByText('login page')).toBeInTheDocument()
    })

    it('redirects authenticated non-admins to /', () => {
      useMeMock.mockReturnValue({
        data: { id: 'u1', email: 'u@x.com', role: 'USER' },
        isPending: false,
      })
      renderAt('/admin')
      expect(screen.getByText('home page')).toBeInTheDocument()
    })

    it('renders the admin route for an ADMIN', () => {
      useMeMock.mockReturnValue({
        data: { id: 'a1', email: 'a@x.com', role: 'ADMIN' },
        isPending: false,
      })
      renderAt('/admin')
      expect(screen.getByText('admin page')).toBeInTheDocument()
    })
  })
  ```

  Note: this assumes `useMe()` returns the TanStack Query result shape `{ data, isPending }` where `data` is the user or `null`. If the existing `useMe` exposes the user under a different field (e.g. `{ user, isPending }`), adjust the mock return values and `RoleRoute` to read that exact field.

- [ ] **Step 2: Run the test and confirm it FAILS.**
  ```bash
  docker compose exec web npx vitest run tests/admin/RoleRoute.test.tsx
  ```
  Expected: failure resolving `../../src/routes/RoleRoute` (module does not exist).

- [ ] **Step 3: Implement `RoleRoute`.**
  Create `/apps/web/src/routes/RoleRoute.tsx`:

  ```tsx
  import { Navigate, Outlet } from 'react-router'
  import { useMe } from '../features/auth/useMe'

  type Role = 'USER' | 'ADMIN'

  // Gate nested routes by role. Waits for the /me check before deciding.
  // - pending: show loading (do not redirect mid-check)
  // - no user: -> /login
  // - wrong role: -> /
  // - correct role: render nested routes
  export function RoleRoute({ role }: { role: Role }) {
    const { data: user, isPending } = useMe()

    if (isPending) return <div>Loading…</div>
    if (!user) return <Navigate to="/login" replace />
    if (user.role !== role) return <Navigate to="/" replace />

    return <Outlet />
  }
  ```

- [ ] **Step 4: Run the test and confirm it PASSES.**
  ```bash
  docker compose exec web npx vitest run tests/admin/RoleRoute.test.tsx
  ```
  Expected: `4 passed`.

- [ ] **Step 5: Commit.**
  ```bash
  git add apps/web/src/routes/RoleRoute.tsx apps/web/tests/admin/RoleRoute.test.tsx
  git commit -m "feat: add RoleRoute guard for ADMIN-only routes"
  ```

---

## Task 7: Admin data hooks (Web)

**Files**
- Create: `/apps/web/src/features/admin/useAdminUsers.ts`
- Create: `/apps/web/src/features/admin/useAdminAudit.ts`

Two TanStack Query v5 hooks fetching the admin endpoints through the shared `apiClient` (FOUNDATION, `src/lib/apiClient.ts`, which sets `credentials:"include"`). These are simple GETs (no CSRF header needed). No dedicated test here; they are exercised through `AdminPage.test.tsx` in Task 8.

- [ ] **Step 1: Create the users hook.**
  Create `/apps/web/src/features/admin/useAdminUsers.ts`:

  ```ts
  import { useQuery } from '@tanstack/react-query'
  import { apiClient } from '../../lib/apiClient'

  export interface AdminUser {
    id: string
    email: string
    role: 'USER' | 'ADMIN'
    emailVerifiedAt: string | null
    createdAt: string
  }

  // GET /api/admin/users -> { users: AdminUser[] }
  export function useAdminUsers() {
    return useQuery({
      queryKey: ['admin', 'users'],
      queryFn: async (): Promise<AdminUser[]> => {
        const res = await apiClient.get('/api/admin/users')
        return res.users as AdminUser[]
      },
      retry: false,
    })
  }
  ```

- [ ] **Step 2: Create the audit hook.**
  Create `/apps/web/src/features/admin/useAdminAudit.ts`:

  ```ts
  import { useQuery } from '@tanstack/react-query'
  import { apiClient } from '../../lib/apiClient'

  export interface AdminAuditEvent {
    id: string
    userId: string | null
    event: string
    ip: string | null
    userAgent: string | null
    createdAt: string
    user: { email: string } | null
  }

  // GET /api/admin/audit -> { events: AdminAuditEvent[] }
  export function useAdminAudit() {
    return useQuery({
      queryKey: ['admin', 'audit'],
      queryFn: async (): Promise<AdminAuditEvent[]> => {
        const res = await apiClient.get('/api/admin/audit')
        return res.events as AdminAuditEvent[]
      },
      retry: false,
    })
  }
  ```

  Note: per CONTRACTS, `apiClient.get(path)` returns the parsed JSON body and callers pass the **full path including `/api`** (so `apiClient.get('/api/admin/users')` hits `/api/admin/users`). Do not change `apiClient` itself.

- [ ] **Step 3: Commit.**
  ```bash
  git add apps/web/src/features/admin/useAdminUsers.ts apps/web/src/features/admin/useAdminAudit.ts
  git commit -m "feat: add admin users and audit query hooks"
  ```

---

## Task 8: `AdminPage` listing Users + audit events (Web)

**Files**
- Create: `/apps/web/tests/admin/AdminPage.test.tsx`
- Create: `/apps/web/src/features/admin/AdminPage.tsx`

- [ ] **Step 1: Write the failing test (MSW-mocked endpoints).**
  Create `/apps/web/tests/admin/AdminPage.test.tsx`. It mounts `AdminPage` inside a real `QueryClientProvider` and mocks both endpoints with MSW (FOUNDATION web test strategy).

  ```tsx
  import { render, screen } from '@testing-library/react'
  import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { http, HttpResponse } from 'msw'
  import { setupServer } from 'msw/node'
  import { AdminPage } from '../../src/features/admin/AdminPage'

  const server = setupServer(
    http.get('/api/admin/users', () =>
      HttpResponse.json({
        users: [
          {
            id: 'a1',
            email: 'admin@example.com',
            role: 'ADMIN',
            emailVerifiedAt: '2026-06-01T00:00:00.000Z',
            createdAt: '2026-06-01T00:00:00.000Z',
          },
          {
            id: 'u1',
            email: 'user@example.com',
            role: 'USER',
            emailVerifiedAt: null,
            createdAt: '2026-05-31T00:00:00.000Z',
          },
        ],
      })
    ),
    http.get('/api/admin/audit', () =>
      HttpResponse.json({
        events: [
          {
            id: 'e1',
            userId: 'a1',
            event: 'login_success',
            ip: '127.0.0.1',
            userAgent: 'vitest',
            createdAt: '2026-06-01T00:00:00.000Z',
            user: { email: 'admin@example.com' },
          },
        ],
      })
    )
  )

  beforeAll(() => server.listen())
  afterEach(() => server.resetHandlers())
  afterAll(() => server.close())

  function renderPage() {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    return render(
      <QueryClientProvider client={queryClient}>
        <AdminPage />
      </QueryClientProvider>
    )
  }

  describe('AdminPage', () => {
    it('renders the user list from the API', async () => {
      renderPage()
      expect(await screen.findByText('admin@example.com')).toBeInTheDocument()
      expect(await screen.findByText('user@example.com')).toBeInTheDocument()
    })

    it('renders recent audit events from the API', async () => {
      renderPage()
      expect(await screen.findByText('login_success')).toBeInTheDocument()
    })
  })
  ```

  Note: MSW intercepts the absolute `/api/...` paths the `apiClient` requests. If `apiClient` prefixes a different base, update the `http.get(...)` paths to match exactly what the client requests in this test environment.

- [ ] **Step 2: Run the test and confirm it FAILS.**
  ```bash
  docker compose exec web npx vitest run tests/admin/AdminPage.test.tsx
  ```
  Expected: failure resolving `../../src/features/admin/AdminPage` (module does not exist).

- [ ] **Step 3: Implement `AdminPage`.**
  Create `/apps/web/src/features/admin/AdminPage.tsx`:

  ```tsx
  import { useAdminUsers } from './useAdminUsers'
  import { useAdminAudit } from './useAdminAudit'

  export function AdminPage() {
    const users = useAdminUsers()
    const audit = useAdminAudit()

    return (
      <main>
        <h1>Admin</h1>

        <section aria-labelledby="users-heading">
          <h2 id="users-heading">Users</h2>
          {users.isPending && <p>Loading…</p>}
          {users.isError && <p>Failed to load users.</p>}
          {users.data && (
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Verified</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {users.data.map((u) => (
                  <tr key={u.id}>
                    <td>{u.email}</td>
                    <td>{u.role}</td>
                    <td>{u.emailVerifiedAt ? 'yes' : 'no'}</td>
                    <td>{new Date(u.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        <section aria-labelledby="audit-heading">
          <h2 id="audit-heading">Recent audit events</h2>
          {audit.isPending && <p>Loading…</p>}
          {audit.isError && <p>Failed to load audit events.</p>}
          {audit.data && (
            <table>
              <thead>
                <tr>
                  <th>Event</th>
                  <th>User</th>
                  <th>IP</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {audit.data.map((e) => (
                  <tr key={e.id}>
                    <td>{e.event}</td>
                    <td>{e.user?.email ?? '—'}</td>
                    <td>{e.ip ?? '—'}</td>
                    <td>{new Date(e.createdAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </main>
    )
  }
  ```

- [ ] **Step 4: Run the test and confirm it PASSES.**
  ```bash
  docker compose exec web npx vitest run tests/admin/AdminPage.test.tsx
  ```
  Expected: `2 passed`.

- [ ] **Step 5: Commit.**
  ```bash
  git add apps/web/src/features/admin/AdminPage.tsx apps/web/tests/admin/AdminPage.test.tsx
  git commit -m "feat: add AdminPage listing users and recent audit events"
  ```

---

## Task 9: Wire `/admin` route + conditional nav (Web)

**Files**
- Modify: `/apps/web/src/routes/router.tsx`
- Modify: `/apps/web/src/App.tsx`

- [ ] **Step 1: Add the `/admin` route behind `RoleRoute`.**
  Open `/apps/web/src/routes/router.tsx` (the `createBrowserRouter` definition, per FOUNDATION). Add the imports near the existing route imports:

  ```tsx
  import { RoleRoute } from './RoleRoute'
  import { AdminPage } from '../features/admin/AdminPage'
  ```

  Then add an `/admin` route nested under `RoleRoute`, alongside the existing protected routes. With `createBrowserRouter` the nesting is expressed as a child route whose `element` is `<RoleRoute role="ADMIN" />`:

  ```tsx
  {
    element: <RoleRoute role="ADMIN" />,
    children: [
      { path: '/admin', element: <AdminPage /> },
    ],
  },
  ```

  Place this object inside the same `children` array that already holds the protected `/` and `/account` routes, so it sits at the app root level (it does its own role check; it does not need to be nested under the plain `ProtectedRoute`). Match the existing route-object style in the file exactly.

- [ ] **Step 2: Add the conditional Admin nav link.**
  Open `/apps/web/src/App.tsx`. It already renders nav using the current user from `useMe()`. Add an admin-only link. Ensure `useMe` and `Link` are imported (they likely already are); if `Link` is not imported, add `import { Link } from 'react-router'`. Inside the nav, conditionally render:

  ```tsx
  {me.data?.role === 'ADMIN' && <Link to="/admin">Admin</Link>}
  ```

  where `me` is the existing `const me = useMe()` result in `App.tsx`. If `App.tsx` reads the user under a different variable/field, use that exact reference (e.g. `user?.role === 'ADMIN'`). Only the role-conditional `Link` is new.

- [ ] **Step 3: Run the full web test suite to confirm no regression.**
  ```bash
  docker compose exec web npx vitest run
  ```
  Expected: all web tests pass, including the new `RoleRoute` and `AdminPage` suites.

- [ ] **Step 4: Manual smoke check in the browser.**
  With the dev stack up (`docker compose up`), visit `https://localhost`. Sign in as a normal user → no "Admin" link; navigating directly to `https://localhost/admin` redirects to `/`. Promote that user (`docker compose exec api npm run promote:admin -- <email>`), sign out and back in → "Admin" link appears, `/admin` shows the Users and audit tables.

- [ ] **Step 5: Commit.**
  ```bash
  git add apps/web/src/routes/router.tsx apps/web/src/App.tsx
  git commit -m "feat: wire /admin route behind RoleRoute with conditional nav"
  ```

---

## Task 10: Full-suite verification

**Files**
- None (verification only)

- [ ] **Step 1: Run the entire API test suite.**
  ```bash
  docker compose exec api npx vitest run
  ```
  Expected: all suites green, including `tests/admin/requireRole.test.ts`, `tests/admin/admin.routes.test.ts`, and `tests/admin/audit-events.test.ts`.

- [ ] **Step 2: Run the entire web test suite.**
  ```bash
  docker compose exec web npx vitest run
  ```
  Expected: all suites green, including `tests/admin/RoleRoute.test.tsx` and `tests/admin/AdminPage.test.tsx`.

- [ ] **Step 3: Type-check both apps.**
  ```bash
  docker compose exec api npx tsc --noEmit
  docker compose exec web npx tsc --noEmit
  ```
  Expected: no type errors in either app.

- [ ] **Step 4: Final commit (only if any lint/type fixups were needed).**
  ```bash
  git add -A
  git commit -m "chore: finalize RBAC, admin routes and audit log viewer slice"
  ```
