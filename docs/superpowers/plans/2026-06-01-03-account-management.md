I have enough context. The plan must respect the domain language (Session, Sign in/out, Change password vs Reset password, Verification token). Now I'll write the implementation plan.

# Account Management — Change Password / Change Email / Sign Out Everywhere Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Let a signed-in User change their password, change their email (confirmed via a Verification token mailed to the new address), and sign out of every Session at once.

**Architecture:** Three new API endpoints under `/account` (change-password, change-email, confirm-email-change) plus `POST /auth/logout-all`, all guarded by `requireAuth` and validated by Zod. Argon2 verifies the current Credential before any change; email change is a two-step flow that creates an `EMAIL_CHANGE` Verification token (stored only as a sha256 hash, carrying `newEmail`) and applies the change only on confirmation. A single React `AccountSettingsPage` drives all three flows with React Hook Form + Zod and TanStack Query mutations, plus a "Sign out everywhere" button.

**Tech Stack:** Express 5 + TypeScript (ESM, strict), Zod 4, argon2, Prisma 7 (`prisma-client` generator), Redis (per-user Session set via `sessionStore.ts`), nodemailer→Mailpit, vitest + supertest (API) / vitest + React Testing Library + MSW (web), React Router v7, TanStack Query v5, react-hook-form 7 + `@hookform/resolvers` 5.

---

## Files Overview

API (all paths under `/Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/`):
- `src/modules/account/account.schema.ts` — Zod bodies + inferred types (NEW; this slice owns it)
- `src/modules/account/account.service.ts` — change-password / change-email / confirm-email-change logic (NEW)
- `src/modules/account/account.routes.ts` — `/account` router (NEW)
- `src/modules/auth/auth.routes.ts` — add `POST /auth/logout-all` (MODIFY)
- `src/app.ts` — mount the account router (MODIFY)
- `tests/account/account.int.test.ts` — change-password + email-change integration tests (NEW)
- `tests/auth/logout-all.int.test.ts` — logout-all integration test (NEW)

Web (all paths under `/Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web/`):
- `src/features/account/useChangePassword.ts` (NEW)
- `src/features/account/useChangeEmail.ts` (NEW)
- `src/features/account/useLogoutAll.ts` (NEW)
- `src/features/account/AccountSettingsPage.tsx` (NEW)
- `src/routes/router.tsx` — wire `/account` to `AccountSettingsPage` (MODIFY)
- `tests/account/AccountSettingsPage.test.tsx` (NEW)

Assumptions (delivered by earlier plans; do NOT recreate): the full Prisma schema + migration (Plan 00); `src/lib/password.ts` exporting `hashPassword(plain)` and `verifyPassword(hash, plain)` (argon2id), `src/lib/tokens.ts` exporting `createToken` / `consumeToken` (both object-in/object-out), `src/lib/mailer.ts` exporting `sendVerificationEmail` / `sendPasswordResetEmail` / `sendEmailChangeEmail`, `src/lib/audit.ts` exporting `writeAudit`, `src/lib/sessionStore.ts` exporting per-user Session helpers, `src/middleware/requireAuth.ts`, and the test harness in `tests/helpers/` (Plans 00–02). The exact signatures of those helpers are confirmed in Task 1 before they are used.

---

## Task 1: Confirm the shared helper signatures this slice depends on

This slice reuses helpers built in Plans 00–02. Read their real exports first so later tasks call them with the exact names and argument shapes — do not assume.

**Files**
- Read only: `apps/api/src/lib/tokens.ts`, `apps/api/src/lib/sessionStore.ts`, `apps/api/src/lib/audit.ts`, `apps/api/src/lib/mailer.ts`, `apps/api/src/lib/password.ts`, `apps/api/src/middleware/requireAuth.ts`, `apps/api/src/db/prisma.ts`, `apps/api/src/config/env.ts`, `apps/api/src/app.ts`, `apps/api/tests/` helpers (e.g. a Mailpit helper + truncate helper)

- [ ] **Step 1: Print the public surface of every helper this slice calls.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    grep -rn "export" \
      src/lib/tokens.ts \
      src/lib/sessionStore.ts \
      src/lib/audit.ts \
      src/lib/mailer.ts \
      src/lib/password.ts \
      src/middleware/requireAuth.ts \
      src/db/prisma.ts \
      src/config/env.ts
  ```

  Expected: you see the exported names this plan references. Confirm each of the following exists; if a name differs, note the real one and substitute it everywhere in later tasks:
  - `tokens.ts`: `createToken({ userId, type, newEmail? })` returning `{ token, tokenHash, expiresAt }` (the **plaintext** `token`, storing only its sha256 hash); `consumeToken({ token, type })` returning the matching unconsumed, unexpired row `{ userId, newEmail }` (marking it `consumedAt`) or `null`.
  - `sessionStore.ts`: a destroyer of every Session for a user — referenced below as `destroyAllUserSessions(userId)`. (Plan 01 created this; reset-password in Plan 02 already calls it.)
  - `audit.ts`: `writeAudit({ event, userId?, ip?, userAgent? })` (writes an `AuditLog` row; canonical event strings only).
  - `mailer.ts`: `sendEmailChangeEmail(to, token)` (used by this slice), plus `sendVerificationEmail` / `sendPasswordResetEmail`.
  - `password.ts`: `hashPassword(plain)` and `verifyPassword(hash, plain)`.
  - `requireAuth.ts`: an Express middleware `requireAuth` that 401s when there is no Session and otherwise leaves `req.session.userId` / `req.session.role` populated.
  - `prisma.ts`: `prisma` (the PrismaClient singleton, imported from the generated output dir).
  - `env.ts`: `env` with at least `APP_URL`.

- [ ] **Step 2: Find how the test harness truncates tables, resets Redis, and reads Mailpit, and how a test signs a User in.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    ls tests && echo "---" && \
    grep -rn "TRUNCATE\|flushDb\|api/v1/messages\|api/v1/search\|export\|agent\|request(app)" tests | head -60
  ```

  Expected: you find (a) a `beforeEach` that truncates `"User","VerificationToken","AuditLog"` + `flushDb()` + clears Mailpit, (b) a Mailpit helper such as `latestMessageTo(addr)` returning `{ Text, HTML, ... }`, and (c) the supertest pattern that establishes a signed-in agent (a supertest `agent` that calls `GET /api/csrf` to capture the csrf cookie/token, then `POST /api/auth/login`, so the Session cookie + csrf are reused on later mutations). Note the exact helper names; reuse them verbatim in Tasks 5 and 8. There is no commit in this task (read-only).

---

## Task 2: Account request schemas (Zod 4)

Zod schemas are the single source of truth for both validation and TS types.

**Files**
- Create: `apps/api/src/modules/account/account.schema.ts`

- [ ] **Step 1: Write the schemas.** Note `z.email()` (top-level — NOT the deprecated `z.string().email()`), and `error` for custom messages (NOT `message`).

  ```ts
  // apps/api/src/modules/account/account.schema.ts
  import { z } from 'zod'

  export const ChangePasswordBody = z.object({
    currentPassword: z.string().min(1, { error: 'Current password is required' }),
    newPassword: z.string().min(8, { error: 'New password must be at least 8 characters' }).max(256),
  })
  export type ChangePasswordBody = z.infer<typeof ChangePasswordBody>

  export const ChangeEmailBody = z.object({
    newEmail: z.email({ error: 'Enter a valid email address' }),
    currentPassword: z.string().min(1, { error: 'Current password is required' }),
  })
  export type ChangeEmailBody = z.infer<typeof ChangeEmailBody>

  export const ConfirmEmailChangeBody = z.object({
    token: z.string().min(1, { error: 'Token is required' }),
  })
  export type ConfirmEmailChangeBody = z.infer<typeof ConfirmEmailChangeBody>
  ```

- [ ] **Step 2: Type-check that the new file compiles.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && npx tsc --noEmit
  ```

  Expected: exits 0 with no output (the schema file has no unresolved references).

- [ ] **Step 3: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/api/src/modules/account/account.schema.ts && \
    git commit -m "feat(account): add zod schemas for change-password, change-email, confirm-email-change"
  ```

---

## Task 3: Account service — change-password (TDD)

The service holds the business logic; routes stay thin. Start with the change-password path. The test is written first against the HTTP layer in Task 5, but the service has a focused unit-style behavior we lock in here via the service signature + a compile gate, then prove end-to-end in Task 5.

**Files**
- Create: `apps/api/src/modules/account/account.service.ts`

- [ ] **Step 1: Create the service file with the change-password function only.** It loads the User, verifies the current Credential with `verifyPassword`, throws a typed error on mismatch (the central `errorHandler` maps it to 400), writes the new hash, and audits. Use the exact helper names confirmed in Task 1.

  ```ts
  // apps/api/src/modules/account/account.service.ts
  import { prisma } from '../../db/prisma.js'
  import { hashPassword, verifyPassword } from '../../lib/password.js'
  import { writeAudit } from '../../lib/audit.js'

  /** Thrown when a User-supplied current password does not match. Mapped to 400 by errorHandler. */
  export class InvalidCurrentPasswordError extends Error {
    status = 400 as const
    code = 'invalid_current_password' as const
    constructor() {
      super('Current password is incorrect')
      this.name = 'InvalidCurrentPasswordError'
    }
  }

  type AuditMeta = { ip?: string; userAgent?: string }

  export async function changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    meta: AuditMeta,
  ): Promise<void> {
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user) throw new InvalidCurrentPasswordError()

    const ok = await verifyPassword(user.passwordHash, currentPassword)
    if (!ok) {
      throw new InvalidCurrentPasswordError()
    }

    const passwordHash = await hashPassword(newPassword)
    await prisma.user.update({ where: { id: userId }, data: { passwordHash } })
    await writeAudit({ event: 'password_change', userId, ip: meta.ip, userAgent: meta.userAgent })
  }
  ```

  Note: if Task 1 found `verifyPassword(plain, hash)` argument order instead of `(hash, plain)`, swap the call accordingly. The FOUNDATION snippet uses `argon2.verify(encodedHash, plainPassword)`, so `(hash, plain)` is the expected order.

- [ ] **Step 2: Confirm `errorHandler` honors a `status` property on thrown errors.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    grep -n "status\|statusCode\|err\." src/middleware/errorHandler.ts
  ```

  Expected: the central handler reads `err.status` (or `err.statusCode`). If it uses `statusCode`, rename the field on `InvalidCurrentPasswordError` to match. The endpoint contract requires a 400, not a leaked 401, so the mapping must produce 400.

- [ ] **Step 3: Type-check.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && npx tsc --noEmit
  ```

  Expected: exits 0.

- [ ] **Step 4: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/api/src/modules/account/account.service.ts && \
    git commit -m "feat(account): add change-password service with current-credential verification"
  ```

---

## Task 4: Account service — change-email + confirm-email-change

Two-step email change. Step one verifies the current Credential, guards against a duplicate email, mints an `EMAIL_CHANGE` Verification token carrying `newEmail`, and mails the **new** address. Step two consumes the token and applies the email.

**Files**
- Modify: `apps/api/src/modules/account/account.service.ts`

- [ ] **Step 1: Add `requestEmailChange`.** It throws `InvalidCurrentPasswordError` on a bad current password. If the new email is already taken it returns silently with no email and no token (anti-enumeration: never reveal another User exists). Otherwise it creates the token via `createToken({ userId, type: 'EMAIL_CHANGE', newEmail })` and mails the **new** address a confirmation link built from `env.APP_URL`.

  ```ts
  // apps/api/src/modules/account/account.service.ts  (append imports)
  import { createToken, consumeToken } from '../../lib/tokens.js'
  import { sendEmailChangeEmail } from '../../lib/mailer.js'
  ```

  ```ts
  // apps/api/src/modules/account/account.service.ts  (append below changePassword)

  export async function requestEmailChange(
    userId: string,
    newEmail: string,
    currentPassword: string,
    meta: AuditMeta,
  ): Promise<void> {
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user) throw new InvalidCurrentPasswordError()

    const ok = await verifyPassword(user.passwordHash, currentPassword)
    if (!ok) {
      throw new InvalidCurrentPasswordError()
    }

    // Anti-enumeration: if the address is taken (or unchanged), do nothing observable.
    const existing = await prisma.user.findUnique({ where: { email: newEmail } })
    if (existing) {
      return
    }

    const { token } = await createToken({ userId, type: 'EMAIL_CHANGE', newEmail })
    await sendEmailChangeEmail(newEmail, token)
    await writeAudit({ event: 'email_change', userId, ip: meta.ip, userAgent: meta.userAgent })
  }
  ```

  Note: `createToken` returns `{ token, tokenHash, expiresAt }`, so destructure `{ token }` (per Task 1). The contract requires the mail to go to the **new** address via `sendEmailChangeEmail(newEmail, token)`.

- [ ] **Step 2: Add `confirmEmailChange`.** It consumes the `EMAIL_CHANGE` token (single-use, timing-safe compare, expiry — all inside `consumeToken`), reads `newEmail` off the consumed row, and applies it. A throw on an invalid/expired token surfaces as a generic error; map it to 400 with a typed error.

  ```ts
  // apps/api/src/modules/account/account.service.ts  (append)

  export class InvalidTokenError extends Error {
    status = 400 as const
    code = 'invalid_token' as const
    constructor() {
      super('This link is invalid or has expired')
      this.name = 'InvalidTokenError'
    }
  }

  export async function confirmEmailChange(token: string, meta: AuditMeta): Promise<void> {
    const rec = await consumeToken({ token, type: 'EMAIL_CHANGE' })
    if (!rec || !rec.newEmail) throw new InvalidTokenError()

    // The new address could have been claimed after the request was issued.
    const taken = await prisma.user.findUnique({ where: { email: rec.newEmail } })
    if (taken && taken.id !== rec.userId) throw new InvalidTokenError()

    await prisma.user.update({
      where: { id: rec.userId },
      data: { email: rec.newEmail },
    })
    await writeAudit({ event: 'email_change', userId: rec.userId, ip: meta.ip, userAgent: meta.userAgent })
  }
  ```

  Note: `consumeToken({ token, type })` returns `{ userId, newEmail }` (single-use, expiry-checked, timing-safe) or `null` for a bad token — the `if (!rec …)` branch covers `null`.

- [ ] **Step 3: Type-check.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && npx tsc --noEmit
  ```

  Expected: exits 0.

- [ ] **Step 4: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/api/src/modules/account/account.service.ts && \
    git commit -m "feat(account): add request/confirm email-change service emailing the new address"
  ```

---

## Task 5: Account routes + mount + integration tests (TDD)

Write the failing integration test first, then the router, then mount it, then go green.

**Files**
- Create: `apps/api/tests/account/account.int.test.ts`
- Create: `apps/api/src/modules/account/account.routes.ts`
- Modify: `apps/api/src/app.ts`

- [ ] **Step 1: Write the failing integration test.** Use the harness helpers confirmed in Task 1 (here named `signedInAgent`, `latestMessageTo`; substitute the real names). Each mutating request carries the csrf header — the agent helper should already attach it. The three acceptance criteria for this slice are encoded: wrong current password is rejected; email change only applies after confirmation.

  ```ts
  // apps/api/tests/account/account.int.test.ts
  import request from 'supertest'
  import { beforeEach, describe, expect, test } from 'vitest'
  import { app } from '../../src/app.js'
  import { prisma } from '../../src/db/prisma.js'
  // signedInAgent(app, creds) -> { agent, user, csrfToken } (registers+verifies+logs in)
  // Reuse the harness helpers found in Task 1:
  import { signedInAgent } from '../helpers/agent.js'
  import { resetState } from '../helpers/db.js'
  import { latestMessageTo } from '../helpers/mailpit.js'

  beforeEach(resetState) // truncate User/VerificationToken/AuditLog + flushDb + clear Mailpit

  describe('POST /api/account/change-password', () => {
    test('rejects a wrong current password with 400 and does not change the hash', async () => {
      const { agent, user } = await signedInAgent({ email: 'pw@example.com', password: 'OldPassw0rd!' })
      const before = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })

      const res = await agent
        .post('/api/account/change-password')
        .send({ currentPassword: 'WRONG-password', newPassword: 'BrandNewPassw0rd!' })

      expect(res.status).toBe(400)
      const after = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
      expect(after.passwordHash).toBe(before.passwordHash)
    })

    test('changes the password with the correct current password', async () => {
      const { agent, user } = await signedInAgent({ email: 'pw2@example.com', password: 'OldPassw0rd!' })
      const before = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })

      const res = await agent
        .post('/api/account/change-password')
        .send({ currentPassword: 'OldPassw0rd!', newPassword: 'BrandNewPassw0rd!' })

      expect(res.status).toBe(200)
      const after = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
      expect(after.passwordHash).not.toBe(before.passwordHash)
    })

    test('requires authentication', async () => {
      const res = await request(app)
        .post('/api/account/change-password')
        .send({ currentPassword: 'x', newPassword: 'BrandNewPassw0rd!' })
      expect(res.status).toBe(401)
    })
  })

  describe('email change flow', () => {
    test('only applies after confirming the token mailed to the new address', async () => {
      const { agent, user } = await signedInAgent({ email: 'old@example.com', password: 'OldPassw0rd!' })

      const reqRes = await agent
        .post('/api/account/change-email')
        .send({ newEmail: 'new@example.com', currentPassword: 'OldPassw0rd!' })
      expect(reqRes.status).toBe(200)

      // Email is NOT yet applied.
      const stillOld = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
      expect(stillOld.email).toBe('old@example.com')

      // Token was mailed to the NEW address.
      const message = await latestMessageTo('new@example.com')
      expect(message).not.toBeNull()
      const token = (message!.Text.match(/token=([^\s&"<]+)/) ?? [])[1]
      expect(token).toBeTruthy()

      const confirmRes = await request(app)
        .post('/api/account/confirm-email-change')
        .send({ token: decodeURIComponent(token!) })
      expect(confirmRes.status).toBe(200)

      const updated = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
      expect(updated.email).toBe('new@example.com')
    })

    test('rejects a wrong current password for change-email with 400', async () => {
      const { agent, user } = await signedInAgent({ email: 'old2@example.com', password: 'OldPassw0rd!' })
      const res = await agent
        .post('/api/account/change-email')
        .send({ newEmail: 'new2@example.com', currentPassword: 'WRONG' })
      expect(res.status).toBe(400)
      const unchanged = await prisma.user.findUniqueOrThrow({ where: { id: user.id } })
      expect(unchanged.email).toBe('old2@example.com')
    })
  })
  ```

- [ ] **Step 2: Run the test — expect FAIL (no `/api/account` routes yet).**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    npx vitest run tests/account/account.int.test.ts
  ```

  Expected: FAIL — change-password/change-email requests return 404 (route not mounted), so `expect(res.status).toBe(400/200)` fails.

- [ ] **Step 3: Write the router.** Each handler validates with the Zod schema (`safeParse` → 400 with `z.flattenError`), then calls the service, passing audit metadata from the request. `requireAuth` guards all three (the `confirm-email-change` step is invoked by an unauthenticated browser following a link, but the contract requires `requireAuth` only on change-password and change-email; confirm is reachable while signed out). Per the contract: change-password and change-email require auth; confirm-email-change does not.

  ```ts
  // apps/api/src/modules/account/account.routes.ts
  import { Router, type Request, type Response, type NextFunction } from 'express'
  import { z } from 'zod'
  import { requireAuth } from '../../middleware/requireAuth.js'
  import {
    ChangePasswordBody,
    ChangeEmailBody,
    ConfirmEmailChangeBody,
  } from './account.schema.js'
  import {
    changePassword,
    requestEmailChange,
    confirmEmailChange,
  } from './account.service.js'

  export const accountRouter = Router()

  function meta(req: Request) {
    return { ip: req.ip, userAgent: req.get('user-agent') ?? undefined }
  }

  accountRouter.post(
    '/change-password',
    requireAuth,
    async (req: Request, res: Response, next: NextFunction) => {
      const parsed = ChangePasswordBody.safeParse(req.body)
      if (!parsed.success) {
        return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors })
      }
      try {
        await changePassword(
          req.session.userId!,
          parsed.data.currentPassword,
          parsed.data.newPassword,
          meta(req),
        )
        res.status(200).json({ ok: true })
      } catch (err) {
        next(err)
      }
    },
  )

  accountRouter.post(
    '/change-email',
    requireAuth,
    async (req: Request, res: Response, next: NextFunction) => {
      const parsed = ChangeEmailBody.safeParse(req.body)
      if (!parsed.success) {
        return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors })
      }
      try {
        await requestEmailChange(
          req.session.userId!,
          parsed.data.newEmail,
          parsed.data.currentPassword,
          meta(req),
        )
        res.status(200).json({ ok: true })
      } catch (err) {
        next(err)
      }
    },
  )

  accountRouter.post(
    '/confirm-email-change',
    async (req: Request, res: Response, next: NextFunction) => {
      const parsed = ConfirmEmailChangeBody.safeParse(req.body)
      if (!parsed.success) {
        return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors })
      }
      try {
        await confirmEmailChange(parsed.data.token, meta(req))
        res.status(200).json({ ok: true })
      } catch (err) {
        next(err)
      }
    },
  )
  ```

  Note: if `requireAuth` populates a different field than `req.session.userId` (Task 1), use that exact field. The `!` non-null assertion is safe because `requireAuth` already 401s when there is no Session.

- [ ] **Step 4: Mount the router in `app.ts`.** First read the file to copy the exact mounting style and middleware order (the account router must be registered AFTER `cookie-parser`, the session middleware, and `doubleCsrfProtection`, and BEFORE `errorHandler`).

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    grep -n "use(\|Router\|errorHandler\|/api" src/app.ts
  ```

  Then add the import and the mount line matching the existing pattern (shown with the conventional `/api` prefix used by the other routers):

  ```ts
  // apps/api/src/app.ts  — add near the other module-router imports
  import { accountRouter } from './modules/account/account.routes.js'
  ```

  ```ts
  // apps/api/src/app.ts  — add alongside app.use('/api/auth', authRouter), BEFORE app.use(errorHandler)
  app.use('/api/account', accountRouter)
  ```

  Confirm `/api/account` (not `/account`) so the final paths are `/api/account/change-password`, `/api/account/change-email`, `/api/account/confirm-email-change`, matching how `auth.routes.ts` is mounted.

- [ ] **Step 5: Run the test — expect PASS.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    npx vitest run tests/account/account.int.test.ts
  ```

  Expected: PASS — all five tests green.

- [ ] **Step 6: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/api/src/modules/account/account.routes.ts apps/api/src/app.ts apps/api/tests/account/account.int.test.ts && \
    git commit -m "feat(account): add /account change-password, change-email, confirm-email-change endpoints with tests"
  ```

---

## Task 6: `POST /auth/logout-all` — sign out of every Session (TDD)

Reuse the Plan-01 `sessionStore` helper to destroy every Session for the User, then destroy the caller's current Session and clear the cookie.

**Files**
- Create: `apps/api/tests/auth/logout-all.int.test.ts`
- Modify: `apps/api/src/modules/auth/auth.routes.ts`

- [ ] **Step 1: Write the failing test.** It signs in the same User on two independent agents (two Sessions), calls `logout-all` on the first, and asserts the second agent's `GET /api/auth/me` now returns 401.

  ```ts
  // apps/api/tests/auth/logout-all.int.test.ts
  import { beforeEach, describe, expect, test } from 'vitest'
  import { signedInAgent, signInExistingUser } from '../helpers/agent.js'
  import { resetState } from '../helpers/db.js'

  beforeEach(resetState)

  describe('POST /api/auth/logout-all', () => {
    test('invalidates every Session for the User, including other devices', async () => {
      // First device signs in (also creates the User).
      const { agent: deviceA, user, credentials } = await signedInAgent({
        email: 'multi@example.com',
        password: 'OldPassw0rd!',
      })
      // Second device signs in as the SAME User -> a second Session.
      const deviceB = await signInExistingUser(credentials)

      // Both Sessions are valid before logout-all.
      expect((await deviceA.get('/api/auth/me')).status).toBe(200)
      expect((await deviceB.get('/api/auth/me')).status).toBe(200)

      // Device A signs out everywhere.
      const res = await deviceA.post('/api/auth/logout-all')
      expect(res.status).toBe(204)

      // Device B's Session is now gone too.
      expect((await deviceB.get('/api/auth/me')).status).toBe(401)
      expect(user.email).toBe('multi@example.com')
    })

    test('requires authentication', async () => {
      const { default: request } = await import('supertest')
      const { app } = await import('../../src/app.js')
      const res = await request(app).post('/api/auth/logout-all')
      expect(res.status).toBe(401)
    })
  })
  ```

  Note: `signInExistingUser` is the Plan-01 helper in `tests/helpers/agent.ts` with signature `signInExistingUser(app, agent, creds)` returning `{ csrfToken }`; it runs the `GET /api/csrf` → `POST /api/auth/login` dance for an already-created User. Use the existing export — do not recreate the helpers module.

- [ ] **Step 2: Run the test — expect FAIL.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    npx vitest run tests/auth/logout-all.int.test.ts
  ```

  Expected: FAIL — `POST /api/auth/logout-all` returns 404 (route absent), so `expect(res.status).toBe(204)` fails.

- [ ] **Step 3: Read the existing logout handler to copy its exact de-index + destroy + clearCookie pattern.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    grep -n "logout\|destroy\|clearCookie\|sessionStore\|requireAuth\|__Host-sid" src/modules/auth/auth.routes.ts
  ```

  Expected: you see the `POST /logout` handler and the imports it uses (`requireAuth`, the `sessionStore` helper, the `__Host-sid` cookie name). Reuse the same helper and cookie name in the next step.

- [ ] **Step 4: Add the `logout-all` handler.** Place it next to the existing `logout` route. It calls `destroyAllUserSessions(userId)` (Plan-01 helper) to wipe every Session for the User from Redis, then destroys the current Express Session and clears the `__Host-sid` cookie. Use the exact helper + cookie name found in Step 3.

  ```ts
  // apps/api/src/modules/auth/auth.routes.ts
  // Ensure these are imported (match what Step 3 showed; add only if missing):
  import { requireAuth } from '../../middleware/requireAuth.js'
  import { destroyAllUserSessions } from '../../lib/sessionStore.js'
  ```

  ```ts
  // apps/api/src/modules/auth/auth.routes.ts  — add beside the existing POST /logout route
  authRouter.post('/logout-all', requireAuth, async (req, res, next) => {
    const userId = req.session.userId!
    try {
      await destroyAllUserSessions(userId)
      req.session.destroy((err) => {
        if (err) return next(err)
        res.clearCookie('__Host-sid')
        res.status(204).end()
      })
    } catch (err) {
      next(err)
    }
  })
  ```

  Note: substitute the real Plan-01 helper name from Step 3 if it differs from `destroyAllUserSessions`, and the real session-userId field if `requireAuth` uses another. `destroyAllUserSessions` must remove both the Redis Session entries (the `sess:*` keys) and the `user_sessions:<userId>` set — that is exactly what the Plan-01 helper does and what reset-password (Plan 02) already relies on.

- [ ] **Step 5: Run the test — expect PASS.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && \
    npx vitest run tests/auth/logout-all.int.test.ts
  ```

  Expected: PASS — both tests green; device B's `me` is 401 after `logout-all`.

- [ ] **Step 6: Run the whole API suite to confirm no regression.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && npx vitest run
  ```

  Expected: all suites pass.

- [ ] **Step 7: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/api/src/modules/auth/auth.routes.ts apps/api/tests/auth/logout-all.int.test.ts && \
    git commit -m "feat(auth): add POST /auth/logout-all destroying every session for the user"
  ```

---

## Task 7: Web mutation hooks — change password, change email, sign out everywhere

TanStack Query v5 mutations calling the new endpoints through the shared `apiClient` (which already sets `credentials:'include'` and attaches `x-csrf-token` on mutations).

**Files**
- Create: `apps/web/src/features/account/useChangePassword.ts`
- Create: `apps/web/src/features/account/useChangeEmail.ts`
- Create: `apps/web/src/features/account/useLogoutAll.ts`

- [ ] **Step 1: Confirm the `apiClient` surface.** It must expose a JSON POST that throws on non-2xx so mutations enter `onError`.

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && \
    grep -n "export\|post\|credentials\|x-csrf-token\|throw" src/lib/apiClient.ts
  ```

  Expected: a default or named client with a `post(path, body)` (or an `apiFetch`) helper. The hooks below assume `import { apiClient } from '../../lib/apiClient'` with `apiClient.post(path, body)`; adjust to the real export from this output.

- [ ] **Step 2: Write `useChangePassword`.**

  ```ts
  // apps/web/src/features/account/useChangePassword.ts
  import { useMutation } from '@tanstack/react-query'
  import { apiClient } from '../../lib/apiClient'

  export type ChangePasswordInput = { currentPassword: string; newPassword: string }

  export function useChangePassword() {
    return useMutation({
      mutationFn: (input: ChangePasswordInput) =>
        apiClient.post('/api/account/change-password', input),
    })
  }
  ```

- [ ] **Step 3: Write `useChangeEmail`.**

  ```ts
  // apps/web/src/features/account/useChangeEmail.ts
  import { useMutation } from '@tanstack/react-query'
  import { apiClient } from '../../lib/apiClient'

  export type ChangeEmailInput = { newEmail: string; currentPassword: string }

  export function useChangeEmail() {
    return useMutation({
      mutationFn: (input: ChangeEmailInput) =>
        apiClient.post('/api/account/change-email', input),
    })
  }
  ```

- [ ] **Step 4: Write `useLogoutAll`.** On success, drop the cached Session (`me`) and send the User to `/login` — mirror the Plan-01/02 `useLogout` pattern (`removeQueries`, not `invalidateQueries`, to avoid a 401 refetch loop).

  ```ts
  // apps/web/src/features/account/useLogoutAll.ts
  import { useMutation, useQueryClient } from '@tanstack/react-query'
  import { useNavigate } from 'react-router'
  import { apiClient } from '../../lib/apiClient'

  export function useLogoutAll() {
    const qc = useQueryClient()
    const navigate = useNavigate()
    return useMutation({
      mutationFn: () => apiClient.post('/api/auth/logout-all'),
      onSuccess: () => {
        qc.removeQueries({ queryKey: ['me'] })
        navigate('/login', { replace: true })
      },
    })
  }
  ```

  Note: if `apiClient.post` requires a body argument, pass `undefined` or `{}` per its signature found in Step 1. Use the exact `['me']` query key established by `useMe.ts` — confirm with `grep -n "queryKey" src/features/auth/useMe.ts`.

- [ ] **Step 5: Type-check the web app.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && npx tsc --noEmit
  ```

  Expected: exits 0.

- [ ] **Step 6: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/web/src/features/account/useChangePassword.ts apps/web/src/features/account/useChangeEmail.ts apps/web/src/features/account/useLogoutAll.ts && \
    git commit -m "feat(account): add web mutation hooks for change-password, change-email, logout-all"
  ```

---

## Task 8: `AccountSettingsPage` with forms + tests (TDD)

One page with a change-password form, a change-email form (both RHF + Zod), and a "Sign out everywhere" button. Per the domain language: the UI verb for ending Sessions is "Sign out"; the in-Session password update is "Change password" (distinct from "Reset password").

**Files**
- Create: `apps/web/tests/account/AccountSettingsPage.test.tsx`
- Create: `apps/web/src/features/account/AccountSettingsPage.tsx`
- Modify: `apps/web/src/routes/router.tsx`

- [ ] **Step 1: Inspect the existing web test setup (MSW + render helper) to copy its exact conventions.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && \
    ls tests && echo "---" && \
    grep -rn "setupServer\|http.post\|HttpResponse\|render\|QueryClientProvider\|MemoryRouter\|renderWithProviders" tests | head -40
  ```

  Expected: an MSW server (`setupServer`) wired in a test setup file, and a render helper that wraps components in `QueryClientProvider` + a router. Reuse the real helper name (here `renderWithProviders`) and MSW `http`/`HttpResponse` imports.

- [ ] **Step 2: Write the failing component test.** It asserts the two acceptance criteria visible at the UI: a wrong-current-password change shows an error (server 400), and clicking "Sign out everywhere" calls `POST /api/auth/logout-all`.

  ```tsx
  // apps/web/tests/account/AccountSettingsPage.test.tsx
  import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
  import { screen, waitFor } from '@testing-library/react'
  import userEvent from '@testing-library/user-event'
  import { http, HttpResponse } from 'msw'
  import { server } from '../setup/server' // MSW server from Step 1 (use the real path)
  import { renderWithProviders } from '../setup/render' // render helper from Step 1
  import { AccountSettingsPage } from '../../src/features/account/AccountSettingsPage'

  describe('AccountSettingsPage', () => {
    test('shows an error when the current password is wrong', async () => {
      server.use(
        http.post('/api/account/change-password', () =>
          HttpResponse.json({ errors: { currentPassword: ['Current password is incorrect'] } }, { status: 400 }),
        ),
      )
      const user = userEvent.setup()
      renderWithProviders(<AccountSettingsPage />)

      await user.type(screen.getByLabelText(/current password/i), 'wrong')
      await user.type(screen.getByLabelText(/new password/i), 'BrandNewPassw0rd!')
      await user.click(screen.getByRole('button', { name: /change password/i }))

      expect(await screen.findByText(/current password is incorrect/i)).toBeInTheDocument()
    })

    test('submits a change-email request to the new address', async () => {
      let received: unknown = null
      server.use(
        http.post('/api/account/change-email', async ({ request }) => {
          received = await request.json()
          return HttpResponse.json({ ok: true }, { status: 200 })
        }),
      )
      const user = userEvent.setup()
      renderWithProviders(<AccountSettingsPage />)

      await user.type(screen.getByLabelText(/new email/i), 'new@example.com')
      await user.type(screen.getByLabelText(/confirm with your current password/i), 'OldPassw0rd!')
      await user.click(screen.getByRole('button', { name: /change email/i }))

      await waitFor(() =>
        expect(received).toEqual({ newEmail: 'new@example.com', currentPassword: 'OldPassw0rd!' }),
      )
      expect(await screen.findByText(/check your new inbox/i)).toBeInTheDocument()
    })

    test('signs out everywhere when the button is clicked', async () => {
      let called = false
      server.use(
        http.post('/api/auth/logout-all', () => {
          called = true
          return new HttpResponse(null, { status: 204 })
        }),
      )
      const user = userEvent.setup()
      renderWithProviders(<AccountSettingsPage />)

      await user.click(screen.getByRole('button', { name: /sign out everywhere/i }))
      await waitFor(() => expect(called).toBe(true))
    })
  })
  ```

- [ ] **Step 3: Run the test — expect FAIL (component does not exist).**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && \
    npx vitest run tests/account/AccountSettingsPage.test.tsx
  ```

  Expected: FAIL — import of `AccountSettingsPage` fails to resolve / nothing renders.

- [ ] **Step 4: Write the component.** Two RHF forms with `zodResolver` (Zod 4 schemas, `z.email()`), surfacing server field errors via `setError`, plus a sign-out-everywhere button. Labels match the test queries exactly.

  ```tsx
  // apps/web/src/features/account/AccountSettingsPage.tsx
  import { useForm } from 'react-hook-form'
  import { zodResolver } from '@hookform/resolvers/zod'
  import { z } from 'zod'
  import { useChangePassword } from './useChangePassword'
  import { useChangeEmail } from './useChangeEmail'
  import { useLogoutAll } from './useLogoutAll'

  const passwordSchema = z.object({
    currentPassword: z.string().min(1, { error: 'Current password is required' }),
    newPassword: z.string().min(8, { error: 'New password must be at least 8 characters' }),
  })
  type PasswordValues = z.infer<typeof passwordSchema>

  const emailSchema = z.object({
    newEmail: z.email({ error: 'Enter a valid email address' }),
    currentPassword: z.string().min(1, { error: 'Current password is required' }),
  })
  type EmailValues = z.infer<typeof emailSchema>

  type FieldErrors = Record<string, string[]>

  function readServerFieldErrors(err: unknown): FieldErrors | null {
    if (err && typeof err === 'object' && 'body' in err) {
      const body = (err as { body?: { errors?: FieldErrors } }).body
      if (body?.errors) return body.errors
    }
    return null
  }

  export function AccountSettingsPage() {
    const changePassword = useChangePassword()
    const changeEmail = useChangeEmail()
    const logoutAll = useLogoutAll()

    const pwForm = useForm<PasswordValues>({ resolver: zodResolver(passwordSchema) })
    const emailForm = useForm<EmailValues>({ resolver: zodResolver(emailSchema) })

    const onChangePassword = pwForm.handleSubmit(async (values) => {
      try {
        await changePassword.mutateAsync(values)
        pwForm.reset()
      } catch (err) {
        const fieldErrors = readServerFieldErrors(err)
        if (fieldErrors?.currentPassword?.[0]) {
          pwForm.setError('currentPassword', { message: fieldErrors.currentPassword[0] })
        } else if (fieldErrors?.newPassword?.[0]) {
          pwForm.setError('newPassword', { message: fieldErrors.newPassword[0] })
        } else {
          pwForm.setError('root', { message: 'Could not change your password' })
        }
      }
    })

    const onChangeEmail = emailForm.handleSubmit(async (values) => {
      try {
        await changeEmail.mutateAsync(values)
        emailForm.reset()
      } catch (err) {
        const fieldErrors = readServerFieldErrors(err)
        if (fieldErrors?.currentPassword?.[0]) {
          emailForm.setError('currentPassword', { message: fieldErrors.currentPassword[0] })
        } else if (fieldErrors?.newEmail?.[0]) {
          emailForm.setError('newEmail', { message: fieldErrors.newEmail[0] })
        } else {
          emailForm.setError('root', { message: 'Could not start the email change' })
        }
      }
    })

    return (
      <main>
        <h1>Account settings</h1>

        <section aria-labelledby="change-password-heading">
          <h2 id="change-password-heading">Change password</h2>
          <form onSubmit={onChangePassword}>
            <label htmlFor="cp-current">Current password</label>
            <input id="cp-current" type="password" {...pwForm.register('currentPassword')} />
            {pwForm.formState.errors.currentPassword && (
              <p role="alert">{pwForm.formState.errors.currentPassword.message}</p>
            )}

            <label htmlFor="cp-new">New password</label>
            <input id="cp-new" type="password" {...pwForm.register('newPassword')} />
            {pwForm.formState.errors.newPassword && (
              <p role="alert">{pwForm.formState.errors.newPassword.message}</p>
            )}

            {pwForm.formState.errors.root && <p role="alert">{pwForm.formState.errors.root.message}</p>}
            {changePassword.isSuccess && <p>Your password has been changed.</p>}

            <button type="submit" disabled={pwForm.formState.isSubmitting}>
              Change password
            </button>
          </form>
        </section>

        <section aria-labelledby="change-email-heading">
          <h2 id="change-email-heading">Change email</h2>
          <form onSubmit={onChangeEmail}>
            <label htmlFor="ce-email">New email</label>
            <input id="ce-email" type="email" {...emailForm.register('newEmail')} />
            {emailForm.formState.errors.newEmail && (
              <p role="alert">{emailForm.formState.errors.newEmail.message}</p>
            )}

            <label htmlFor="ce-current">Confirm with your current password</label>
            <input id="ce-current" type="password" {...emailForm.register('currentPassword')} />
            {emailForm.formState.errors.currentPassword && (
              <p role="alert">{emailForm.formState.errors.currentPassword.message}</p>
            )}

            {emailForm.formState.errors.root && <p role="alert">{emailForm.formState.errors.root.message}</p>}
            {changeEmail.isSuccess && <p>Check your new inbox to confirm the change.</p>}

            <button type="submit" disabled={emailForm.formState.isSubmitting}>
              Change email
            </button>
          </form>
        </section>

        <section aria-labelledby="sessions-heading">
          <h2 id="sessions-heading">Sessions</h2>
          <p>Sign out of every device, including this one.</p>
          <button type="button" onClick={() => logoutAll.mutate()} disabled={logoutAll.isPending}>
            Sign out everywhere
          </button>
        </section>
      </main>
    )
  }
  ```

  Note: `readServerFieldErrors` reads `err.body` because `apiClient` throws an `ApiError` with `{ status, body }` (the parsed JSON), per the Plan-01 contract. The success-message text "Check your new inbox to confirm the change." must contain "check your new inbox" to satisfy the test.

- [ ] **Step 5: Run the component test — expect PASS.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && \
    npx vitest run tests/account/AccountSettingsPage.test.tsx
  ```

  Expected: PASS — all three tests green.

- [ ] **Step 6: Wire `/account` to the page.** Read the router first, then point the existing protected `/account` route element at `AccountSettingsPage`.

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && \
    grep -n "account\|ProtectedRoute\|element\|path" src/routes/router.tsx
  ```

  Add the import and set the element on the protected `/account` route (keep it inside the existing `ProtectedRoute` wrapper):

  ```tsx
  // apps/web/src/routes/router.tsx  — add with the other route-component imports
  import { AccountSettingsPage } from '../features/account/AccountSettingsPage'
  ```

  ```tsx
  // apps/web/src/routes/router.tsx  — the protected /account route now renders the page
  { path: '/account', element: <AccountSettingsPage /> }
  ```

  Match the existing `createBrowserRouter` route-object style; if `/account` does not yet exist as a child of the protected branch, add it there alongside the dashboard route.

- [ ] **Step 7: Type-check + run the whole web suite.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && \
    npx tsc --noEmit && npx vitest run
  ```

  Expected: type-check exits 0; all web suites pass.

- [ ] **Step 8: Commit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    git add apps/web/src/features/account/AccountSettingsPage.tsx apps/web/src/routes/router.tsx apps/web/tests/account/AccountSettingsPage.test.tsx && \
    git commit -m "feat(account): add AccountSettingsPage with change-password, change-email, and sign-out-everywhere"
  ```

---

## Task 9: Full-stack verification of the slice

Run both suites and a manual smoke test through Docker to prove the three acceptance criteria end-to-end.

**Files**
- None (verification only)

- [ ] **Step 1: Run the complete API and web test suites.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api && npx vitest run && \
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web && npx vitest run
  ```

  Expected: both report all suites/tests passing, including `account.int.test.ts`, `logout-all.int.test.ts`, and `AccountSettingsPage.test.tsx`.

- [ ] **Step 2: Bring the stack up and smoke-test the email-change flow via Mailpit.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && \
    docker compose up -d --build && \
    docker compose ps
  ```

  Expected: `caddy`, `web`, `api`, `db`, `redis`, `mailpit` all healthy/running. Then in a browser at `https://localhost`: register + sign in, open `/account`, submit a change-email to a new address, confirm a message arrives at Mailpit (`https://localhost:8025` or the mapped UI), open the confirm link, and verify `GET /api/auth/me` reflects the new email. Try a wrong current password on change-password and confirm a 400/error message. Sign in on a second browser/profile, click "Sign out everywhere" on the first, and confirm the second is signed out (its next request 401s and redirects to `/login`).

- [ ] **Step 3: Tear down.**

  ```bash
  cd /Users/thammasornlueadtaharn/Desktop/project/authentication-flow && docker compose down
  ```

  Expected: services stop cleanly. No commit (verification only). The slice is complete: change-password (rejects wrong current), change-email (applies only after confirming the token mailed to the new address), and logout-all (invalidates other Sessions) are all proven by tests and a live smoke test.
