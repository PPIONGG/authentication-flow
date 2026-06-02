# Email Verification & Password Reset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Add email-dependent auth flows — email verification on register, login gated on a verified email, and a forgot/reset password cycle — using single-use, hashed, short-lived tokens delivered to Mailpit.
**Architecture:** New `lib/mailer.ts` (nodemailer → Mailpit) and `lib/tokens.ts` (random token → sha256 hash stored in `VerificationToken`, timing-safe single-use consume) back the auth service. `register` now leaves `emailVerifiedAt` null and mails an `EMAIL_VERIFY` token; `login` rejects unverified users; `forgot-password`/`reset-password` mint and consume `PASSWORD_RESET` tokens, and reset destroys every session via the Plan-01 `sessionStore` helper. The React SPA gains `VerifyEmailPage`, `ForgotPasswordPage`, `ResetPasswordPage` and a post-register "check your email" UX.
**Tech Stack:** Express 5 + TypeScript (ESM), Prisma 7 (`prisma-client` generator + `@prisma/adapter-pg`), Zod 4, argon2, nodemailer 8, Node `crypto` (sha256 + `timingSafeEqual`), vitest 4 + supertest 7 (Mailpit HTTP API for mail assertions), React Router 7 + TanStack Query 5 + React Hook Form 7 + `@hookform/resolvers` v5.

---

## Files Overview

**API (`/apps/api`)**

- Create `src/lib/mailer.ts` — nodemailer transport to Mailpit + `sendVerificationEmail` / `sendPasswordResetEmail`.
- Create `src/lib/tokens.ts` — `createToken`, `consumeToken` (sha256 hash, expiry, single-use, timing-safe).
- Modify `src/modules/auth/auth.schema.ts` — add `VerifyEmailBody`, `ResendVerificationBody`, `ForgotPasswordBody`, `ResetPasswordBody`.
- Modify `src/modules/auth/auth.service.ts` — change `register`, change `login`, add `verifyEmail`, `resendVerification`, `forgotPassword`, `resetPassword`.
- Modify `src/modules/auth/auth.routes.ts` — mount the four new endpoints.
- Create `tests/auth/verify-email.int.test.ts`, `tests/auth/login-verification.int.test.ts`, `tests/auth/password-reset.int.test.ts`.
- Create `tests/helpers/mailpit.ts` — Mailpit HTTP API helpers.

**WEB (`/apps/web`)**

- Create `src/features/auth/useVerifyEmail.ts`, `useResendVerification.ts`, `useForgotPassword.ts`, `useResetPassword.ts`.
- Create `src/features/auth/VerifyEmailPage.tsx`, `ForgotPasswordPage.tsx`, `ResetPasswordPage.tsx`.
- Modify `src/features/auth/RegisterPage.tsx` — show "check your email" after success.
- Modify `src/features/auth/LoginPage.tsx` — surface "email not verified" with a resend link.
- Modify `src/routes/router.tsx` — add `/verify-email`, `/forgot-password`, `/reset-password`.
- Create `tests/auth/verifyEmail.test.tsx`, `tests/auth/passwordReset.test.tsx`.

---

## Task 1: Token library (`lib/tokens.ts`)

Tokens are random 32-byte hex strings handed to the user; only their sha256 hash is persisted in `VerificationToken.tokenHash`. Verification re-hashes the presented token, looks up the row, and uses `crypto.timingSafeEqual` plus expiry + `consumedAt` checks before marking it consumed.

**Files**

- Create: `/apps/api/src/lib/tokens.ts`
- Test: `/apps/api/tests/lib/tokens.int.test.ts`

Steps:

- [ ] **Step 1: Write the failing test for `createToken` + `consumeToken` happy path.**
  Create `/apps/api/tests/lib/tokens.int.test.ts`:

  ```ts
  import { beforeEach, describe, expect, it } from 'vitest';
  import { prisma } from '../../src/db/prisma.js';
  import { redis } from '../../src/redis/client.js';
  import { createToken, consumeToken } from '../../src/lib/tokens.js';

  async function makeUser(email = 'tok@example.com') {
    return prisma.user.create({
      data: { email, passwordHash: 'x', emailVerifiedAt: null },
    });
  }

  beforeEach(async () => {
    await prisma.$executeRawUnsafe(
      'TRUNCATE TABLE "VerificationToken","AuditLog","User" RESTART IDENTITY CASCADE',
    );
    await redis.flushDb();
  });

  describe('tokens', () => {
    it('createToken returns a raw token and stores only its hash', async () => {
      const user = await makeUser();
      const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY' });
      expect(token).toMatch(/^[0-9a-f]{64}$/);
      const rows = await prisma.verificationToken.findMany({ where: { userId: user.id } });
      expect(rows).toHaveLength(1);
      expect(rows[0]!.tokenHash).not.toEqual(token);
      expect(rows[0]!.tokenHash).toMatch(/^[0-9a-f]{64}$/);
      expect(rows[0]!.type).toBe('EMAIL_VERIFY');
    });

    it('consumeToken returns {userId,newEmail} for a valid token and marks it consumed', async () => {
      const user = await makeUser();
      const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY' });
      const row = await consumeToken({ token, type: 'EMAIL_VERIFY' });
      expect(row).not.toBeNull();
      expect(row!.userId).toBe(user.id);
      expect(row!.newEmail).toBeNull();
      const reread = await prisma.verificationToken.findFirst({ where: { userId: user.id } });
      expect(reread!.consumedAt).not.toBeNull();
    });
  });
  ```

- [ ] **Step 2: Run the test and confirm it FAILS (module does not exist).**

  ```bash
  cd /apps/api && npx vitest run tests/lib/tokens.int.test.ts
  ```

  Expected: FAIL — `Failed to load .../src/lib/tokens.ts` / `Cannot find module './tokens.js'`.

- [ ] **Step 3: Implement `lib/tokens.ts`.**
  Create `/apps/api/src/lib/tokens.ts`:

  ```ts
  import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
  import { prisma } from '../db/prisma.js';
  import type { TokenType } from '../generated/prisma/client.js';

  // 7-day default lifetime for email verification; reset uses a shorter override.
  const DEFAULT_TTL_MS = 1000 * 60 * 60 * 24 * 7;

  function sha256Hex(input: string): string {
    return createHash('sha256').update(input).digest('hex');
  }

  function hashesEqual(a: string, b: string): boolean {
    const ab = Buffer.from(a, 'hex');
    const bb = Buffer.from(b, 'hex');
    if (ab.length !== bb.length) return false;
    return timingSafeEqual(ab, bb);
  }

  export interface CreateTokenInput {
    userId: string;
    type: TokenType;
    ttlMs?: number;
    newEmail?: string;
  }

  export async function createToken(
    input: CreateTokenInput,
  ): Promise<{ token: string; tokenHash: string; expiresAt: Date }> {
    const token = randomBytes(32).toString('hex'); // 64 hex chars
    const tokenHash = sha256Hex(token);
    const expiresAt = new Date(Date.now() + (input.ttlMs ?? DEFAULT_TTL_MS));
    await prisma.verificationToken.create({
      data: {
        userId: input.userId,
        type: input.type,
        tokenHash,
        expiresAt,
        newEmail: input.newEmail ?? null,
      },
    });
    return { token, tokenHash, expiresAt };
  }

  export interface ConsumeTokenInput {
    token: string;
    type: TokenType;
  }

  // Returns { userId, newEmail }, or null if the token is unknown / wrong type /
  // already consumed / expired. Single-use: sets consumedAt atomically.
  export async function consumeToken(
    input: ConsumeTokenInput,
  ): Promise<{ userId: string; newEmail: string | null } | null> {
    if (!/^[0-9a-f]{64}$/.test(input.token)) return null;
    const tokenHash = sha256Hex(input.token);
    const row = await prisma.verificationToken.findUnique({ where: { tokenHash } });
    if (!row) return null;
    if (row.type !== input.type) return null;
    if (!hashesEqual(row.tokenHash, tokenHash)) return null;
    if (row.consumedAt) return null;
    if (row.expiresAt.getTime() <= Date.now()) return null;

    // Atomic single-use guard: only the first caller flips consumedAt.
    const result = await prisma.verificationToken.updateMany({
      where: { id: row.id, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    if (result.count !== 1) return null;
    return { userId: row.userId, newEmail: row.newEmail ?? null };
  }
  ```

- [ ] **Step 4: Run the test and confirm it PASSES.**

  ```bash
  cd /apps/api && npx vitest run tests/lib/tokens.int.test.ts
  ```

  Expected: PASS — `2 passed`.

- [ ] **Step 5: Add failing tests for single-use and expiry edge cases.**
  Append to `/apps/api/tests/lib/tokens.int.test.ts` inside the `describe`:

  ```ts
    it('consumeToken is single-use (second consume returns null)', async () => {
      const user = await makeUser();
      const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY' });
      expect(await consumeToken({ token, type: 'EMAIL_VERIFY' })).not.toBeNull();
      expect(await consumeToken({ token, type: 'EMAIL_VERIFY' })).toBeNull();
    });

    it('consumeToken returns null for an expired token', async () => {
      const user = await makeUser();
      const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY', ttlMs: -1 });
      expect(await consumeToken({ token, type: 'EMAIL_VERIFY' })).toBeNull();
    });

    it('consumeToken returns null when the type does not match', async () => {
      const user = await makeUser();
      const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY' });
      expect(await consumeToken({ token, type: 'PASSWORD_RESET' })).toBeNull();
    });

    it('consumeToken returns null for an unknown token', async () => {
      expect(
        await consumeToken({ token: 'f'.repeat(64), type: 'EMAIL_VERIFY' }),
      ).toBeNull();
    });
  ```

- [ ] **Step 6: Run the test and confirm all PASS.**

  ```bash
  cd /apps/api && npx vitest run tests/lib/tokens.int.test.ts
  ```

  Expected: PASS — `6 passed`. (Implementation already covers these branches; no code change needed.)

- [ ] **Step 7: Commit.**

  ```bash
  cd /apps/api && git add src/lib/tokens.ts tests/lib/tokens.int.test.ts && git commit -m "feat(api): add single-use hashed verification tokens"
  ```

---

## Task 2: Mailer library (`lib/mailer.ts`)

A nodemailer transport pointed at Mailpit (no auth, plaintext on port 1025) plus two typed helpers that build the verification and reset URLs from `APP_URL`.

**Files**

- Create: `/apps/api/src/lib/mailer.ts`
- Test: `/apps/api/tests/helpers/mailpit.ts` (shared test helper), `/apps/api/tests/lib/mailer.int.test.ts`

Steps:

- [ ] **Step 1: Create the Mailpit test helper.**
  Create `/apps/api/tests/helpers/mailpit.ts`:

  ```ts
  const MAILPIT = process.env.MAILPIT_URL ?? 'http://mailpit:8025';

  export async function clearMailpit(): Promise<void> {
    await fetch(`${MAILPIT}/api/v1/messages`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
  }

  export interface MailpitMessage {
    ID: string;
    From: { Address: string; Name: string };
    To: { Address: string; Name: string }[];
    Subject: string;
    HTML: string;
    Text: string;
  }

  export async function latestMessageTo(addr: string): Promise<MailpitMessage | null> {
    const res = await fetch(
      `${MAILPIT}/api/v1/search?query=${encodeURIComponent('to:' + addr)}&limit=1`,
    );
    const body = (await res.json()) as { messages: { ID: string }[] };
    if (!body.messages?.length) return null;
    const full = await fetch(`${MAILPIT}/api/v1/message/${body.messages[0]!.ID}`);
    return (await full.json()) as MailpitMessage;
  }

  // Pulls the first ?token=<64 hex> query param out of an email body.
  export function extractToken(message: MailpitMessage): string | null {
    const haystack = `${message.HTML}\n${message.Text}`;
    const m = haystack.match(/[?&]token=([0-9a-f]{64})/);
    return m ? m[1]! : null;
  }
  ```

- [ ] **Step 2: Write the failing test for the mailer.**
  Create `/apps/api/tests/lib/mailer.int.test.ts`:

  ```ts
  import { beforeEach, describe, expect, it } from 'vitest';
  import { sendVerificationEmail, sendPasswordResetEmail } from '../../src/lib/mailer.js';
  import { clearMailpit, latestMessageTo, extractToken } from '../helpers/mailpit.js';

  beforeEach(async () => {
    await clearMailpit();
  });

  describe('mailer', () => {
    it('sendVerificationEmail delivers a message containing the token link', async () => {
      const token = 'a'.repeat(64);
      await sendVerificationEmail('verify@example.com', token);
      const msg = await latestMessageTo('verify@example.com');
      expect(msg).not.toBeNull();
      expect(msg!.Subject).toMatch(/verify/i);
      expect(extractToken(msg!)).toBe(token);
    });

    it('sendPasswordResetEmail delivers a message containing the token link', async () => {
      const token = 'b'.repeat(64);
      await sendPasswordResetEmail('reset@example.com', token);
      const msg = await latestMessageTo('reset@example.com');
      expect(msg).not.toBeNull();
      expect(msg!.Subject).toMatch(/reset/i);
      expect(extractToken(msg!)).toBe(token);
    });
  });
  ```

- [ ] **Step 3: Run the test and confirm it FAILS (module does not exist).**

  ```bash
  cd /apps/api && npx vitest run tests/lib/mailer.int.test.ts
  ```

  Expected: FAIL — `Failed to load .../src/lib/mailer.ts`.

- [ ] **Step 4: Implement `lib/mailer.ts`.**
  Create `/apps/api/src/lib/mailer.ts`:

  ```ts
  import nodemailer from 'nodemailer';
  import { env } from '../config/env.js';

  // Mailpit: plaintext SMTP on 1025, NO auth key (do not pass empty strings).
  export const mailer = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: false,
  });

  export async function sendVerificationEmail(to: string, token: string): Promise<void> {
    const url = `${env.APP_URL}/verify-email?token=${token}`;
    await mailer.sendMail({
      from: env.MAIL_FROM,
      to,
      subject: 'Verify your email',
      text: `Confirm your email address by opening this link:\n\n${url}\n\nThis link expires in 7 days.`,
      html: `<p>Confirm your email address:</p><p><a href="${url}">${url}</a></p><p>This link expires in 7 days.</p>`,
    });
  }

  export async function sendPasswordResetEmail(to: string, token: string): Promise<void> {
    const url = `${env.APP_URL}/reset-password?token=${token}`;
    await mailer.sendMail({
      from: env.MAIL_FROM,
      to,
      subject: 'Reset your password',
      text: `Reset your password by opening this link:\n\n${url}\n\nThis link expires in 1 hour. If you did not request this, ignore this email.`,
      html: `<p>Reset your password:</p><p><a href="${url}">${url}</a></p><p>This link expires in 1 hour. If you did not request this, ignore this email.</p>`,
    });
  }

  // Used by Plan 03's email-change flow; mails the confirmation link to the NEW address.
  export async function sendEmailChangeEmail(to: string, token: string): Promise<void> {
    const url = `${env.APP_URL}/verify-email?token=${token}`;
    await mailer.sendMail({
      from: env.MAIL_FROM,
      to,
      subject: 'Confirm your new email address',
      text: `Confirm your new email address by opening this link:\n\n${url}\n\nThis link expires in 7 days. If you did not request this, ignore this email.`,
      html: `<p>Confirm your new email address:</p><p><a href="${url}">${url}</a></p><p>This link expires in 7 days. If you did not request this, ignore this email.</p>`,
    });
  }
  ```

- [ ] **Step 5: Run the test and confirm it PASSES.**

  ```bash
  cd /apps/api && npx vitest run tests/lib/mailer.int.test.ts
  ```

  Expected: PASS — `2 passed`. (Requires the Mailpit container running; under `docker compose`, run via `docker compose exec api npx vitest run tests/lib/mailer.int.test.ts`.)

- [ ] **Step 6: Commit.**

  ```bash
  cd /apps/api && git add src/lib/mailer.ts tests/helpers/mailpit.ts tests/lib/mailer.int.test.ts && git commit -m "feat(api): add nodemailer Mailpit mailer with verify/reset emails"
  ```

---

## Task 3: Auth request schemas for the new endpoints

Add Zod 4 schemas for the four new bodies. These are the single source of truth for validation and inferred types.

**Files**

- Modify: `/apps/api/src/modules/auth/auth.schema.ts`

Steps:

- [ ] **Step 1: Read the existing schema file to find the insertion point.**

  ```bash
  cd /apps/api && cat src/modules/auth/auth.schema.ts
  ```

  Expected: existing `RegisterBody` and `LoginBody` `z.object` definitions (created in Plan 01). Note that `z` is already imported.

- [ ] **Step 2: Append the four new schemas.**
  Add to the end of `/apps/api/src/modules/auth/auth.schema.ts`:

  ```ts
  export const VerifyEmailBody = z.object({
    token: z.string().regex(/^[0-9a-f]{64}$/, { error: 'Invalid token' }),
  });
  export type VerifyEmailBody = z.infer<typeof VerifyEmailBody>;

  export const ResendVerificationBody = z.object({
    email: z.email(),
  });
  export type ResendVerificationBody = z.infer<typeof ResendVerificationBody>;

  export const ForgotPasswordBody = z.object({
    email: z.email(),
  });
  export type ForgotPasswordBody = z.infer<typeof ForgotPasswordBody>;

  export const ResetPasswordBody = z.object({
    token: z.string().regex(/^[0-9a-f]{64}$/, { error: 'Invalid token' }),
    password: z.string().min(8).max(256),
  });
  export type ResetPasswordBody = z.infer<typeof ResetPasswordBody>;
  ```

- [ ] **Step 3: Type-check to confirm the schemas compile.**

  ```bash
  cd /apps/api && npx tsc --noEmit
  ```

  Expected: no errors (exit code 0).

- [ ] **Step 4: Commit.**

  ```bash
  cd /apps/api && git add src/modules/auth/auth.schema.ts && git commit -m "feat(api): add zod schemas for verify/resend/forgot/reset"
  ```

---

## Task 4: Register now leaves email unverified and sends EMAIL_VERIFY mail

Plan 01's `register` created an ACTIVE user (`emailVerifiedAt = now()`) and sent no email. This task flips it: `emailVerifiedAt` stays `null` and an `EMAIL_VERIFY` token is mailed. Endpoint contract is unchanged (`201 {ok:true}`).

**Files**

- Modify: `/apps/api/src/modules/auth/auth.service.ts`
- Test: `/apps/api/tests/auth/verify-email.int.test.ts` (register half here; verify half in Task 5)

Steps:

- [ ] **Step 1: Read the existing `createUser` implementation.**

  ```bash
  cd /apps/api && cat src/modules/auth/auth.service.ts
  ```

  Expected (Plan 01 real code): a `createUser(email, password)` function that throws `HttpError(409, 'registration_failed')` on a duplicate, calls `hashPassword`, and ends with `return prisma.user.create({ data: { email, passwordHash, emailVerifiedAt: new Date() } });`. The register ROUTE (Plan 01) calls `createUser(...)` then `writeAudit({ userId, event: 'register', ... })`; that route stays unchanged. Note the exact import block.

- [ ] **Step 2: Write the failing test asserting register leaves user unverified and sends mail.**
  Create `/apps/api/tests/auth/verify-email.int.test.ts`:

  ```ts
  import { beforeEach, afterAll, describe, expect, it } from 'vitest';
  import { app } from '../../src/app.js';
  import { prisma } from '../../src/db/prisma.js';
  import { redis } from '../../src/redis/client.js';
  import { resetState } from '../helpers/db.js';
  import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';
  import { clearMailpit, latestMessageTo, extractToken } from '../helpers/mailpit.js';

  beforeEach(async () => {
    await resetState();
    await clearMailpit();
  });
  afterAll(async () => {
    await redis.quit();
  });

  describe('register -> email verification', () => {
    it('register creates an unverified user and mails a verification token', async () => {
      const email = 'newuser@example.com';
      const { agent, csrfToken } = await makeCsrfAgent(app);
      await agent
        .post('/api/auth/register')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email, password: 'correct horse battery' })
        .expect(201, { ok: true });

      const user = await prisma.user.findUnique({ where: { email } });
      expect(user).not.toBeNull();
      expect(user!.emailVerifiedAt).toBeNull();

      const msg = await latestMessageTo(email);
      expect(msg).not.toBeNull();
      expect(msg!.Subject).toMatch(/verify/i);
      expect(extractToken(msg!)).toMatch(/^[0-9a-f]{64}$/);
    });
  });
  ```

- [ ] **Step 3: Run the test and confirm it FAILS.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/verify-email.int.test.ts
  ```

  Expected: FAIL — `expected null` assertion fails because `emailVerifiedAt` is currently set, and `latestMessageTo` returns null (no mail sent).

- [ ] **Step 4: Update the imports in `auth.service.ts`.**
  Add these imports near the top of `/apps/api/src/modules/auth/auth.service.ts` (alongside the existing imports):

  ```ts
  import { createToken, consumeToken } from '../../lib/tokens.js';
  import { sendVerificationEmail, sendPasswordResetEmail } from '../../lib/mailer.js';
  ```

- [ ] **Step 5: Change `createUser` to leave the user unverified and send mail.**
  In `/apps/api/src/modules/auth/auth.service.ts`, replace the `return prisma.user.create({ ... })` at the end of `createUser`. Old code (from Plan 01):

  ```ts
    return prisma.user.create({
      data: {
        email,
        passwordHash,
        emailVerifiedAt: new Date(), // Plan 01: active immediately
      },
    });
  ```

  New code:

  ```ts
    const user = await prisma.user.create({
      data: {
        email,
        passwordHash,
        emailVerifiedAt: null, // Plan 02: verify by email before login
      },
    });
    const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY' });
    await sendVerificationEmail(user.email, token);
    return user;
  ```

  (The register ROUTE's `writeAudit({ userId: user.id, event: 'register', ... })` call stays exactly as Plan 01 wrote it.)

- [ ] **Step 6: Run the test and confirm it PASSES.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/verify-email.int.test.ts
  ```

  Expected: PASS — `1 passed`.

- [ ] **Step 7: Commit.**

  ```bash
  cd /apps/api && git add src/modules/auth/auth.service.ts tests/auth/verify-email.int.test.ts && git commit -m "feat(api): register leaves email unverified and sends verify mail"
  ```

---

## Task 5: `verify-email` and `resend-verification` endpoints

`verify-email` consumes an `EMAIL_VERIFY` token and sets `emailVerifiedAt`. `resend-verification` always returns 200 (anti-enumeration) and mails a fresh token only when the user exists and is still unverified.

**Files**

- Modify: `/apps/api/src/modules/auth/auth.service.ts`
- Modify: `/apps/api/src/modules/auth/auth.routes.ts`
- Test: `/apps/api/tests/auth/verify-email.int.test.ts`

Steps:

- [ ] **Step 1: Add failing tests for verify + resend.**
  Append to the `describe('register -> email verification', ...)` block in `/apps/api/tests/auth/verify-email.int.test.ts`:

  ```ts
    it('verify-email consumes the token and marks the user verified', async () => {
      const email = 'verifyme@example.com';
      const reg = await makeCsrfAgent(app);
      await reg.agent
        .post('/api/auth/register')
        .set(HTTPS)
        .set('x-csrf-token', reg.csrfToken)
        .send({ email, password: 'correct horse battery' })
        .expect(201);
      const token = extractToken((await latestMessageTo(email))!)!;

      const ver = await makeCsrfAgent(app);
      await ver.agent
        .post('/api/auth/verify-email')
        .set(HTTPS)
        .set('x-csrf-token', ver.csrfToken)
        .send({ token })
        .expect(200);

      const user = await prisma.user.findUnique({ where: { email } });
      expect(user!.emailVerifiedAt).not.toBeNull();
    });

    it('verify-email rejects a reused (single-use) token', async () => {
      const email = 'reuse@example.com';
      const reg = await makeCsrfAgent(app);
      await reg.agent
        .post('/api/auth/register')
        .set(HTTPS)
        .set('x-csrf-token', reg.csrfToken)
        .send({ email, password: 'correct horse battery' })
        .expect(201);
      const token = extractToken((await latestMessageTo(email))!)!;

      const first = await makeCsrfAgent(app);
      await first.agent
        .post('/api/auth/verify-email')
        .set(HTTPS)
        .set('x-csrf-token', first.csrfToken)
        .send({ token })
        .expect(200);
      const second = await makeCsrfAgent(app);
      await second.agent
        .post('/api/auth/verify-email')
        .set(HTTPS)
        .set('x-csrf-token', second.csrfToken)
        .send({ token })
        .expect(400);
    });

    it('verify-email returns 400 for an unknown token', async () => {
      const { agent, csrfToken } = await makeCsrfAgent(app);
      await agent
        .post('/api/auth/verify-email')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ token: 'c'.repeat(64) })
        .expect(400);
    });

    it('resend-verification returns 200 for an unknown email (no enumeration)', async () => {
      const { agent, csrfToken } = await makeCsrfAgent(app);
      await agent
        .post('/api/auth/resend-verification')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email: 'nobody@example.com' })
        .expect(200);
      expect(await latestMessageTo('nobody@example.com')).toBeNull();
    });

    it('resend-verification mails a fresh token for an unverified user', async () => {
      const email = 'resend@example.com';
      const reg = await makeCsrfAgent(app);
      await reg.agent
        .post('/api/auth/register')
        .set(HTTPS)
        .set('x-csrf-token', reg.csrfToken)
        .send({ email, password: 'correct horse battery' })
        .expect(201);
      await clearMailpit();

      const res = await makeCsrfAgent(app);
      await res.agent
        .post('/api/auth/resend-verification')
        .set(HTTPS)
        .set('x-csrf-token', res.csrfToken)
        .send({ email })
        .expect(200);
      const msg = await latestMessageTo(email);
      expect(extractToken(msg!)).toMatch(/^[0-9a-f]{64}$/);
    });
  ```

- [ ] **Step 2: Run the tests and confirm the new ones FAIL.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/verify-email.int.test.ts
  ```

  Expected: FAIL — `verify-email` returns 404 (route not mounted), so the `.expect(200)` calls fail.

- [ ] **Step 3: Add `verifyEmail` and `resendVerification` service functions.**
  Append to `/apps/api/src/modules/auth/auth.service.ts`:

  ```ts
  export async function verifyEmail(token: string): Promise<boolean> {
    const row = await consumeToken({ token, type: 'EMAIL_VERIFY' });
    if (!row) return false;
    await prisma.user.update({
      where: { id: row.userId },
      data: { emailVerifiedAt: new Date() },
    });
    return true;
  }

  export async function resendVerification(email: string): Promise<void> {
    const user = await prisma.user.findUnique({ where: { email } });
    // Anti-enumeration: silently no-op if the user is absent or already verified.
    if (!user || user.emailVerifiedAt) return;
    const { token } = await createToken({ userId: user.id, type: 'EMAIL_VERIFY' });
    await sendVerificationEmail(user.email, token);
  }
  ```

- [ ] **Step 4: Read the routes file to match the existing handler style.**

  ```bash
  cd /apps/api && cat src/modules/auth/auth.routes.ts
  ```

  Expected: a `Router()` with existing `register`/`login` handlers using `safeParse` + `z.flattenError`, and the imported service functions. Note the import line for `auth.service.js` and `auth.schema.js`.

- [ ] **Step 5: Mount the two routes.**
  In `/apps/api/src/modules/auth/auth.routes.ts`, extend the service/schema imports and add the handlers. Add to the schema import:

  ```ts
  import { VerifyEmailBody, ResendVerificationBody } from './auth.schema.js';
  ```

  Add to the service import:

  ```ts
  import { verifyEmail, resendVerification } from './auth.service.js';
  ```

  Add these handlers before `export default router;` (or `export { router }`, matching the file):

  ```ts
  router.post('/verify-email', async (req, res) => {
    const parsed = VerifyEmailBody.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors });
    }
    const ok = await verifyEmail(parsed.data.token);
    if (!ok) return res.status(400).json({ error: 'Invalid or expired token' });
    return res.status(200).json({ ok: true });
  });

  router.post('/resend-verification', async (req, res) => {
    const parsed = ResendVerificationBody.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors });
    }
    await resendVerification(parsed.data.email);
    return res.status(200).json({ ok: true }); // always 200
  });
  ```

  (Ensure `import { z } from 'zod';` is present at the top of the routes file; add it if not.)

- [ ] **Step 6: Run the tests and confirm all PASS.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/verify-email.int.test.ts
  ```

  Expected: PASS — `6 passed`.

- [ ] **Step 7: Commit.**

  ```bash
  cd /apps/api && git add src/modules/auth/auth.service.ts src/modules/auth/auth.routes.ts tests/auth/verify-email.int.test.ts && git commit -m "feat(api): add verify-email and resend-verification endpoints"
  ```

---

## Task 6: Login requires a verified email

Plan 01's `login` did not check verification. Now an unverified (but otherwise valid) user must be blocked with a clear, distinguishable error so the SPA can show a resend hint. Bad-credentials errors stay generic (anti-enumeration); the verification error is only returned AFTER the password is confirmed correct, so it never leaks whether an email exists.

**Files**

- Modify: `/apps/api/src/modules/auth/auth.service.ts`
- Modify: `/apps/api/src/modules/auth/auth.routes.ts`
- Test: `/apps/api/tests/auth/login-verification.int.test.ts`

Steps:

- [ ] **Step 1: Write the failing test.**
  Create `/apps/api/tests/auth/login-verification.int.test.ts`:

  ```ts
  import { beforeEach, afterAll, describe, expect, it } from 'vitest';
  import { app } from '../../src/app.js';
  import { prisma } from '../../src/db/prisma.js';
  import { redis } from '../../src/redis/client.js';
  import { resetState } from '../helpers/db.js';
  import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';
  import { clearMailpit, latestMessageTo, extractToken } from '../helpers/mailpit.js';

  const email = 'loginflow@example.com';
  const password = 'correct horse battery';

  beforeEach(async () => {
    await resetState();
    await clearMailpit();
    const reg = await makeCsrfAgent(app);
    await reg.agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', reg.csrfToken)
      .send({ email, password })
      .expect(201);
  });
  afterAll(async () => {
    await redis.quit();
  });

  describe('login requires verified email', () => {
    it('blocks login for an unverified user with an EMAIL_NOT_VERIFIED error', async () => {
      const { agent, csrfToken } = await makeCsrfAgent(app);
      const res = await agent
        .post('/api/auth/login')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email, password })
        .expect(403);
      expect(res.body.error).toBe('EMAIL_NOT_VERIFIED');
      expect(res.headers['set-cookie']).toBeUndefined();
    });

    it('still returns a generic 401 for a wrong password (no verification leak)', async () => {
      const { agent, csrfToken } = await makeCsrfAgent(app);
      await agent
        .post('/api/auth/login')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email, password: 'wrong-password' })
        .expect(401);
    });

    it('allows login once the email is verified', async () => {
      const token = extractToken((await latestMessageTo(email))!)!;
      const ver = await makeCsrfAgent(app);
      await ver.agent
        .post('/api/auth/verify-email')
        .set(HTTPS)
        .set('x-csrf-token', ver.csrfToken)
        .send({ token })
        .expect(200);

      const { agent, csrfToken } = await makeCsrfAgent(app);
      const res = await agent
        .post('/api/auth/login')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email, password })
        .expect(200);
      expect(res.body.user.email).toBe(email);
      expect(res.headers['set-cookie']?.join(';')).toContain('__Host-sid');
    });
  });
  ```

- [ ] **Step 2: Run the test and confirm it FAILS.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/login-verification.int.test.ts
  ```

  Expected: FAIL — the unverified-login test gets 200 instead of 403 (login currently ignores verification).

- [ ] **Step 3: No service change — the verification gate lives in the login ROUTE.**
  Per CONTRACTS, `verifyCredentials` (Plan 01, owned there) is left untouched: it still throws `HttpError(401, 'invalid_credentials')` on bad creds and otherwise RETURNS the `User`. Do not add a sentinel to the service. The email-verified gate is added in the route in Step 4.

- [ ] **Step 4: Add the verification gate to the login route, after `verifyCredentials` succeeds.**
  In `/apps/api/src/modules/auth/auth.routes.ts`, the Plan 01 login handler calls `verifyCredentials` inside a try/catch and, on success, calls `req.session.regenerate(...)`. Insert the gate between the successful `verifyCredentials` call and `req.session.regenerate`, so an unverified user gets a 403 and NO session is created. Old (Plan 01):

  ```ts
    let user;
    try {
      user = await verifyCredentials(parsed.data.email, parsed.data.password);
    } catch (err) {
      await writeAudit({
        event: 'login_fail',
        ip: req.ip,
        userAgent: req.get('user-agent'),
      });
      throw err;
    }

    // Anti-fixation: regenerate the session id before storing identity.
    req.session.regenerate((regenErr) => {
  ```

  New:

  ```ts
    let user;
    try {
      user = await verifyCredentials(parsed.data.email, parsed.data.password);
    } catch (err) {
      await writeAudit({
        event: 'login_fail',
        ip: req.ip,
        userAgent: req.get('user-agent'),
      });
      throw err;
    }

    // Plan 02 gate: credentials are valid, but block unverified emails. No session is created.
    if (!user.emailVerifiedAt) {
      return res.status(403).json({ error: 'EMAIL_NOT_VERIFIED' });
    }

    // Anti-fixation: regenerate the session id before storing identity.
    req.session.regenerate((regenErr) => {
  ```

  (This runs only AFTER the password is confirmed, so it never leaks whether an email exists; bad-credentials still return the generic 401 from `verifyCredentials`.)

- [ ] **Step 5: Run the test and confirm all PASS.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/login-verification.int.test.ts
  ```

  Expected: PASS — `3 passed`.

- [ ] **Step 6: Run the full auth suite to confirm no Plan-01 login tests regressed.**

  ```bash
  cd /apps/api && npx vitest run tests/auth
  ```

  Expected: PASS — all auth tests green. If a Plan-01 login test seeded a user with `emailVerifiedAt: new Date()`, it still passes; any that registered then logged in without verifying must now verify first (those are this plan's concern only if they exist — leave Plan-01 tests untouched unless they fail, in which case they were relying on the old behavior and the failure is expected and documented in Task 8).

- [ ] **Step 7: Commit.**

  ```bash
  cd /apps/api && git add src/modules/auth/auth.service.ts src/modules/auth/auth.routes.ts tests/auth/login-verification.int.test.ts && git commit -m "feat(api): require verified email to log in"
  ```

---

## Task 7: `forgot-password` and `reset-password` endpoints

`forgot-password` always returns 200 and mails a short-lived (1 hour) `PASSWORD_RESET` token only when the user exists. `reset-password` consumes the token, sets a new argon2 hash, destroys ALL of the user's sessions via the Plan-01 `sessionStore` helper, and audits.

**Files**

- Modify: `/apps/api/src/modules/auth/auth.service.ts`
- Modify: `/apps/api/src/modules/auth/auth.routes.ts`
- Test: `/apps/api/tests/auth/password-reset.int.test.ts`

Steps:

- [ ] **Step 1: Confirm the Plan-01 `sessionStore` helper signature.**

  ```bash
  cd /apps/api && cat src/lib/sessionStore.ts
  ```

  Expected: a per-user session-set helper exporting (per Plan 01) `addUserSession(userId, sessionId)`, `removeUserSession(userId, sessionId)`, and `destroyAllUserSessions(userId)` which deletes every Redis session for the user and clears the `user_sessions:<userId>` set. Use that exact name `destroyAllUserSessions` below.

- [ ] **Step 2: Write the failing test.**
  Create `/apps/api/tests/auth/password-reset.int.test.ts`:

  ```ts
  import { beforeEach, afterAll, describe, expect, it } from 'vitest';
  import { app } from '../../src/app.js';
  import { prisma } from '../../src/db/prisma.js';
  import { redis } from '../../src/redis/client.js';
  import { resetState } from '../helpers/db.js';
  import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';
  import { clearMailpit, latestMessageTo, extractToken } from '../helpers/mailpit.js';

  const email = 'resetflow@example.com';
  const password = 'correct horse battery';
  const newPassword = 'a-brand-new-passphrase';

  // Registers, verifies, and logs in; returns the authed agent plus a FRESH csrf token
  // (login regenerates the session, so the pre-login token is stale).
  async function registerVerifiedAndLogin() {
    const reg = await makeCsrfAgent(app);
    await reg.agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', reg.csrfToken)
      .send({ email, password })
      .expect(201);
    const token = extractToken((await latestMessageTo(email))!)!;
    const ver = await makeCsrfAgent(app);
    await ver.agent
      .post('/api/auth/verify-email')
      .set(HTTPS)
      .set('x-csrf-token', ver.csrfToken)
      .send({ token })
      .expect(200);
    await clearMailpit();
    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email, password })
      .expect(200);
    const fresh = await agent.get('/api/csrf').set(HTTPS).expect(200);
    return { agent, csrfToken: fresh.body.csrfToken as string };
  }

  beforeEach(async () => {
    await resetState();
    await clearMailpit();
  });
  afterAll(async () => {
    await redis.quit();
  });

  describe('forgot / reset password', () => {
    it('forgot-password returns 200 and sends no mail for an unknown email', async () => {
      const { agent, csrfToken } = await makeCsrfAgent(app);
      await agent
        .post('/api/auth/forgot-password')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email: 'ghost@example.com' })
        .expect(200);
      expect(await latestMessageTo('ghost@example.com')).toBeNull();
    });

    it('forgot-password mails a reset token for an existing user', async () => {
      await registerVerifiedAndLogin();
      const { agent, csrfToken } = await makeCsrfAgent(app);
      await agent
        .post('/api/auth/forgot-password')
        .set(HTTPS)
        .set('x-csrf-token', csrfToken)
        .send({ email })
        .expect(200);
      const msg = await latestMessageTo(email);
      expect(msg!.Subject).toMatch(/reset/i);
      expect(extractToken(msg!)).toMatch(/^[0-9a-f]{64}$/);
    });

    it('reset-password sets a new hash, invalidates sessions, and is single-use', async () => {
      const { agent } = await registerVerifiedAndLogin();
      // The logged-in session works before reset.
      await agent.get('/api/auth/me').set(HTTPS).expect(200);

      const forgot = await makeCsrfAgent(app);
      await forgot.agent
        .post('/api/auth/forgot-password')
        .set(HTTPS)
        .set('x-csrf-token', forgot.csrfToken)
        .send({ email })
        .expect(200);
      const token = extractToken((await latestMessageTo(email))!)!;

      const reset = await makeCsrfAgent(app);
      await reset.agent
        .post('/api/auth/reset-password')
        .set(HTTPS)
        .set('x-csrf-token', reset.csrfToken)
        .send({ token, password: newPassword })
        .expect(200);

      // All sessions destroyed -> old cookie is now unauthenticated.
      await agent.get('/api/auth/me').set(HTTPS).expect(401);

      // New password works, old one does not.
      const ok = await makeCsrfAgent(app);
      await ok.agent
        .post('/api/auth/login')
        .set(HTTPS)
        .set('x-csrf-token', ok.csrfToken)
        .send({ email, password: newPassword })
        .expect(200);
      const bad = await makeCsrfAgent(app);
      await bad.agent
        .post('/api/auth/login')
        .set(HTTPS)
        .set('x-csrf-token', bad.csrfToken)
        .send({ email, password })
        .expect(401);

      // Token is single-use.
      const reuse = await makeCsrfAgent(app);
      await reuse.agent
        .post('/api/auth/reset-password')
        .set(HTTPS)
        .set('x-csrf-token', reuse.csrfToken)
        .send({ token, password: 'yet-another-pass' })
        .expect(400);
    });
  });
  ```

- [ ] **Step 3: Run the test and confirm it FAILS.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/password-reset.int.test.ts
  ```

  Expected: FAIL — `forgot-password`/`reset-password` return 404 (routes not mounted).

- [ ] **Step 4: Add the service functions.**
  Ensure the sessionStore import is present at the top of `/apps/api/src/modules/auth/auth.service.ts`:

  ```ts
  import { destroyAllUserSessions } from '../../lib/sessionStore.js';
  ```

  (Use the exact name confirmed in Step 1.) Then append:

  ```ts
  const RESET_TTL_MS = 1000 * 60 * 60; // 1 hour

  export async function forgotPassword(email: string): Promise<void> {
    const user = await prisma.user.findUnique({ where: { email } });
    // Anti-enumeration: always succeed; only mail when the user exists.
    if (!user) return;
    const { token } = await createToken({
      userId: user.id,
      type: 'PASSWORD_RESET',
      ttlMs: RESET_TTL_MS,
    });
    await sendPasswordResetEmail(user.email, token);
  }

  export async function resetPassword(token: string, newPassword: string): Promise<string | null> {
    const row = await consumeToken({ token, type: 'PASSWORD_RESET' });
    if (!row) return null;
    const passwordHash = await argon2.hash(newPassword);
    await prisma.user.update({
      where: { id: row.userId },
      data: { passwordHash },
    });
    // Destroy every session for this user (Plan-01 helper).
    await destroyAllUserSessions(row.userId);
    return row.userId;
  }
  ```

  (`argon2` is already imported in this file from Plan 01; `createToken`/`consumeToken` and `sendPasswordResetEmail` were imported in Tasks 1, 2, 4.)

- [ ] **Step 5: Mount the routes with audit.**
  In `/apps/api/src/modules/auth/auth.routes.ts` add to the schema import:

  ```ts
  import { ForgotPasswordBody, ResetPasswordBody } from './auth.schema.js';
  ```

  Add to the service import:

  ```ts
  import { forgotPassword, resetPassword } from './auth.service.js';
  ```

  Add the handlers (using the Plan-01 `writeAudit` already imported in this file):

  ```ts
  router.post('/forgot-password', async (req, res) => {
    const parsed = ForgotPasswordBody.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors });
    }
    await forgotPassword(parsed.data.email);
    return res.status(200).json({ ok: true }); // always 200
  });

  router.post('/reset-password', async (req, res) => {
    const parsed = ResetPasswordBody.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ errors: z.flattenError(parsed.error).fieldErrors });
    }
    const userId = await resetPassword(parsed.data.token, parsed.data.password);
    if (!userId) return res.status(400).json({ error: 'Invalid or expired token' });
    await writeAudit({
      userId,
      event: 'password_reset',
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });
    return res.status(200).json({ ok: true });
  });
  ```

- [ ] **Step 6: Run the test and confirm all PASS.**

  ```bash
  cd /apps/api && npx vitest run tests/auth/password-reset.int.test.ts
  ```

  Expected: PASS — `3 passed`.

- [ ] **Step 7: Commit.**

  ```bash
  cd /apps/api && git add src/modules/auth/auth.service.ts src/modules/auth/auth.routes.ts tests/auth/password-reset.int.test.ts && git commit -m "feat(api): add forgot-password and reset-password endpoints"
  ```

---

## Task 8: Full API suite + type-check gate

Run everything together to catch cross-task regressions and ensure the build is clean before moving to the frontend.

**Files**

- (no source changes unless a regression surfaces)

Steps:

- [ ] **Step 1: Type-check the whole API.**

  ```bash
  cd /apps/api && npx tsc --noEmit
  ```

  Expected: exit code 0, no errors.

- [ ] **Step 2: Run the entire API test suite.**

  ```bash
  cd /apps/api && npx vitest run
  ```

  Expected: PASS — all suites green (tokens, mailer, verify-email, login-verification, password-reset, plus Plan 00/01 tests).

- [ ] **Step 3: If any Plan-01 login test fails because it registered then logged in without verifying, fix that test to verify first.**
  Such a test must register, read the token from Mailpit, call `/api/auth/verify-email`, then log in — mirroring `registerVerifiedAndLogin` in Task 7. Apply the minimal edit, re-run `npx vitest run`, confirm green. Commit:

  ```bash
  cd /apps/api && git add tests/auth && git commit -m "test(api): verify email before login in pre-existing login tests"
  ```

  (Skip this commit if no Plan-01 test regressed.)

---

## Task 9: WEB — verify-email page and post-register UX

The SPA register flow now shows "check your email"; a `/verify-email` page reads `?token=` and POSTs it. All mutations go through `apiClient` (credentials:"include", x-csrf-token on POST).

**Files**

- Create: `/apps/web/src/features/auth/useVerifyEmail.ts`, `/apps/web/src/features/auth/useResendVerification.ts`
- Create: `/apps/web/src/features/auth/VerifyEmailPage.tsx`
- Modify: `/apps/web/src/features/auth/RegisterPage.tsx`
- Modify: `/apps/web/src/routes/router.tsx`
- Test: `/apps/web/tests/auth/verifyEmail.test.tsx`

Steps:

- [ ] **Step 1: Inspect `apiClient` to use the exact request signature.**

  ```bash
  cd /apps/web && cat src/lib/apiClient.ts
  ```

  Expected: a fetch wrapper (e.g. `apiClient.post(path, body)`) that sets `credentials:"include"` and attaches `x-csrf-token` from the csrf cookie on mutations. Use its exact exported shape below (referred to as `apiClient.post`).

- [ ] **Step 2: Write the failing test for VerifyEmailPage.**
  Create `/apps/web/tests/auth/verifyEmail.test.tsx`:

  ```tsx
  import { describe, expect, it, beforeAll, afterEach, afterAll } from 'vitest';
  import { render, screen, waitFor } from '@testing-library/react';
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
  import { MemoryRouter, Routes, Route } from 'react-router';
  import { http, HttpResponse } from 'msw';
  import { setupServer } from 'msw/node';
  import { VerifyEmailPage } from '../../src/features/auth/VerifyEmailPage';

  const server = setupServer(
    http.post('/api/auth/verify-email', async ({ request }) => {
      const body = (await request.json()) as { token: string };
      if (body.token === 'good') return HttpResponse.json({ ok: true });
      return HttpResponse.json({ error: 'Invalid or expired token' }, { status: 400 });
    }),
  );

  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  function renderAt(url: string) {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route path="/verify-email" element={<VerifyEmailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  describe('VerifyEmailPage', () => {
    it('shows success when the token is valid', async () => {
      renderAt('/verify-email?token=good');
      await waitFor(() => expect(screen.getByText(/email verified/i)).toBeInTheDocument());
    });

    it('shows an error when the token is invalid', async () => {
      renderAt('/verify-email?token=bad');
      await waitFor(() => expect(screen.getByText(/invalid or expired/i)).toBeInTheDocument());
    });
  });
  ```

- [ ] **Step 3: Run the test and confirm it FAILS.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/verifyEmail.test.tsx
  ```

  Expected: FAIL — `Cannot find module '../../src/features/auth/VerifyEmailPage'`.

- [ ] **Step 4: Implement the verify + resend hooks.**
  Create `/apps/web/src/features/auth/useVerifyEmail.ts`:

  ```ts
  import { useMutation } from '@tanstack/react-query';
  import { apiClient } from '../../lib/apiClient';

  export function useVerifyEmail() {
    return useMutation({
      mutationFn: (token: string) =>
        apiClient.post('/api/auth/verify-email', { token }),
    });
  }
  ```

  Create `/apps/web/src/features/auth/useResendVerification.ts`:

  ```ts
  import { useMutation } from '@tanstack/react-query';
  import { apiClient } from '../../lib/apiClient';

  export function useResendVerification() {
    return useMutation({
      mutationFn: (email: string) =>
        apiClient.post('/api/auth/resend-verification', { email }),
    });
  }
  ```

- [ ] **Step 5: Implement `VerifyEmailPage`.**
  Create `/apps/web/src/features/auth/VerifyEmailPage.tsx`:

  ```tsx
  import { useEffect } from 'react';
  import { Link, useSearchParams } from 'react-router';
  import { useVerifyEmail } from './useVerifyEmail';

  export function VerifyEmailPage() {
    const [params] = useSearchParams();
    const token = params.get('token');
    const verify = useVerifyEmail();

    useEffect(() => {
      if (token) verify.mutate(token);
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [token]);

    if (!token) return <p>Missing verification token.</p>;
    if (verify.isPending) return <p>Verifying your email…</p>;
    if (verify.isError) {
      return (
        <div>
          <p>Invalid or expired verification link.</p>
          <Link to="/login">Back to login</Link>
        </div>
      );
    }
    if (verify.isSuccess) {
      return (
        <div>
          <h1>Email verified</h1>
          <p>Your email is confirmed. You can now log in.</p>
          <Link to="/login">Go to login</Link>
        </div>
      );
    }
    return null;
  }
  ```

- [ ] **Step 6: Run the test and confirm it PASSES.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/verifyEmail.test.tsx
  ```

  Expected: PASS — `2 passed`.

- [ ] **Step 7: Update `RegisterPage` to show a "check your email" state on success.**
  In `/apps/web/src/features/auth/RegisterPage.tsx`, the register mutation's success branch must no longer assume the user is logged in. Add a success-state render. Read the file first:

  ```bash
  cd /apps/web && cat src/features/auth/RegisterPage.tsx
  ```

  Then add, after the existing `useRegister()` hook and before the form `return`, a guard:

  ```tsx
    if (register.isSuccess) {
      return (
        <div>
          <h1>Check your email</h1>
          <p>We sent a verification link to your address. Click it to activate your account, then log in.</p>
        </div>
      );
    }
  ```

  (`register` is the existing `useRegister()` result variable; rename to match the file if different.)

- [ ] **Step 8: Add the `/verify-email` route.**
  In `/apps/web/src/routes/router.tsx`, import and register the page. Add the import:

  ```tsx
  import { VerifyEmailPage } from '../features/auth/VerifyEmailPage';
  ```

  Add a public route entry (matching the file's `createBrowserRouter` array shape):

  ```tsx
    { path: '/verify-email', element: <VerifyEmailPage /> },
  ```

- [ ] **Step 9: Run the web test suite for this slice.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/verifyEmail.test.tsx
  ```

  Expected: PASS — `2 passed`.

- [ ] **Step 10: Commit.**

  ```bash
  cd /apps/web && git add src/features/auth/useVerifyEmail.ts src/features/auth/useResendVerification.ts src/features/auth/VerifyEmailPage.tsx src/features/auth/RegisterPage.tsx src/routes/router.tsx tests/auth/verifyEmail.test.tsx && git commit -m "feat(web): verify-email page and check-your-email register UX"
  ```

---

## Task 10: WEB — forgot-password and reset-password pages

A `/forgot-password` form (always shows a generic "if that email exists…" confirmation) and a `/reset-password` page that reads `?token=` and submits a new password.

**Files**

- Create: `/apps/web/src/features/auth/useForgotPassword.ts`, `/apps/web/src/features/auth/useResetPassword.ts`
- Create: `/apps/web/src/features/auth/ForgotPasswordPage.tsx`, `/apps/web/src/features/auth/ResetPasswordPage.tsx`
- Modify: `/apps/web/src/routes/router.tsx`
- Test: `/apps/web/tests/auth/passwordReset.test.tsx`

Steps:

- [ ] **Step 1: Write the failing test.**
  Create `/apps/web/tests/auth/passwordReset.test.tsx`:

  ```tsx
  import { describe, expect, it, beforeAll, afterEach, afterAll } from 'vitest';
  import { render, screen, waitFor } from '@testing-library/react';
  import userEvent from '@testing-library/user-event';
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
  import { MemoryRouter, Routes, Route } from 'react-router';
  import { http, HttpResponse } from 'msw';
  import { setupServer } from 'msw/node';
  import { ForgotPasswordPage } from '../../src/features/auth/ForgotPasswordPage';
  import { ResetPasswordPage } from '../../src/features/auth/ResetPasswordPage';

  const server = setupServer(
    http.post('/api/auth/forgot-password', () => HttpResponse.json({ ok: true })),
    http.post('/api/auth/reset-password', async ({ request }) => {
      const body = (await request.json()) as { token: string };
      if (body.token === 'good') return HttpResponse.json({ ok: true });
      return HttpResponse.json({ error: 'Invalid or expired token' }, { status: 400 });
    }),
  );

  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  function renderAt(url: string, element: React.ReactElement, path: string) {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={[url]}>
          <Routes>
            <Route path={path} element={element} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  describe('ForgotPasswordPage', () => {
    it('shows a generic confirmation after submit', async () => {
      renderAt('/forgot-password', <ForgotPasswordPage />, '/forgot-password');
      await userEvent.type(screen.getByLabelText(/email/i), 'a@b.com');
      await userEvent.click(screen.getByRole('button', { name: /send/i }));
      await waitFor(() =>
        expect(screen.getByText(/if that email exists/i)).toBeInTheDocument(),
      );
    });
  });

  describe('ResetPasswordPage', () => {
    it('shows success for a valid token', async () => {
      renderAt('/reset-password?token=good', <ResetPasswordPage />, '/reset-password');
      await userEvent.type(screen.getByLabelText(/new password/i), 'a-brand-new-pass');
      await userEvent.click(screen.getByRole('button', { name: /reset/i }));
      await waitFor(() =>
        expect(screen.getByText(/password updated/i)).toBeInTheDocument(),
      );
    });

    it('shows an error for an invalid token', async () => {
      renderAt('/reset-password?token=bad', <ResetPasswordPage />, '/reset-password');
      await userEvent.type(screen.getByLabelText(/new password/i), 'a-brand-new-pass');
      await userEvent.click(screen.getByRole('button', { name: /reset/i }));
      await waitFor(() =>
        expect(screen.getByText(/invalid or expired/i)).toBeInTheDocument(),
      );
    });
  });
  ```

- [ ] **Step 2: Run the test and confirm it FAILS.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/passwordReset.test.tsx
  ```

  Expected: FAIL — `Cannot find module '../../src/features/auth/ForgotPasswordPage'`.

- [ ] **Step 3: Implement the hooks.**
  Create `/apps/web/src/features/auth/useForgotPassword.ts`:

  ```ts
  import { useMutation } from '@tanstack/react-query';
  import { apiClient } from '../../lib/apiClient';

  export function useForgotPassword() {
    return useMutation({
      mutationFn: (email: string) =>
        apiClient.post('/api/auth/forgot-password', { email }),
    });
  }
  ```

  Create `/apps/web/src/features/auth/useResetPassword.ts`:

  ```ts
  import { useMutation } from '@tanstack/react-query';
  import { apiClient } from '../../lib/apiClient';

  export function useResetPassword() {
    return useMutation({
      mutationFn: (input: { token: string; password: string }) =>
        apiClient.post('/api/auth/reset-password', input),
    });
  }
  ```

- [ ] **Step 4: Implement `ForgotPasswordPage`.**
  Create `/apps/web/src/features/auth/ForgotPasswordPage.tsx`:

  ```tsx
  import { useForm } from 'react-hook-form';
  import { zodResolver } from '@hookform/resolvers/zod';
  import { z } from 'zod';
  import { useForgotPassword } from './useForgotPassword';

  const schema = z.object({ email: z.email('Enter a valid email') });
  type FormValues = z.infer<typeof schema>;

  export function ForgotPasswordPage() {
    const forgot = useForgotPassword();
    const { register, handleSubmit, formState: { errors, isSubmitting } } =
      useForm<FormValues>({ resolver: zodResolver(schema) });

    const onSubmit = handleSubmit((values) => forgot.mutate(values.email));

    if (forgot.isSuccess) {
      return <p>If that email exists, we sent a password reset link.</p>;
    }

    return (
      <form onSubmit={onSubmit}>
        <h1>Forgot password</h1>
        <label htmlFor="email">Email</label>
        <input id="email" type="email" {...register('email')} />
        {errors.email && <span>{errors.email.message}</span>}
        <button type="submit" disabled={isSubmitting}>Send reset link</button>
      </form>
    );
  }
  ```

- [ ] **Step 5: Implement `ResetPasswordPage`.**
  Create `/apps/web/src/features/auth/ResetPasswordPage.tsx`:

  ```tsx
  import { useForm } from 'react-hook-form';
  import { zodResolver } from '@hookform/resolvers/zod';
  import { z } from 'zod';
  import { Link, useSearchParams } from 'react-router';
  import { useResetPassword } from './useResetPassword';

  const schema = z.object({
    password: z.string().min(8, 'Min 8 characters').max(256),
  });
  type FormValues = z.infer<typeof schema>;

  export function ResetPasswordPage() {
    const [params] = useSearchParams();
    const token = params.get('token');
    const reset = useResetPassword();
    const { register, handleSubmit, formState: { errors, isSubmitting } } =
      useForm<FormValues>({ resolver: zodResolver(schema) });

    if (!token) return <p>Missing reset token.</p>;

    const onSubmit = handleSubmit((values) =>
      reset.mutate({ token, password: values.password }),
    );

    if (reset.isSuccess) {
      return (
        <div>
          <h1>Password updated</h1>
          <p>Your password has been changed. Please log in.</p>
          <Link to="/login">Go to login</Link>
        </div>
      );
    }

    return (
      <form onSubmit={onSubmit}>
        <h1>Reset password</h1>
        <label htmlFor="password">New password</label>
        <input id="password" type="password" {...register('password')} />
        {errors.password && <span>{errors.password.message}</span>}
        {reset.isError && <span>Invalid or expired reset link.</span>}
        <button type="submit" disabled={isSubmitting}>Reset password</button>
      </form>
    );
  }
  ```

- [ ] **Step 6: Add both routes.**
  In `/apps/web/src/routes/router.tsx` add imports:

  ```tsx
  import { ForgotPasswordPage } from '../features/auth/ForgotPasswordPage';
  import { ResetPasswordPage } from '../features/auth/ResetPasswordPage';
  ```

  Add the public route entries:

  ```tsx
    { path: '/forgot-password', element: <ForgotPasswordPage /> },
    { path: '/reset-password', element: <ResetPasswordPage /> },
  ```

- [ ] **Step 7: Run the test and confirm it PASSES.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/passwordReset.test.tsx
  ```

  Expected: PASS — `3 passed`.

- [ ] **Step 8: Commit.**

  ```bash
  cd /apps/web && git add src/features/auth/useForgotPassword.ts src/features/auth/useResetPassword.ts src/features/auth/ForgotPasswordPage.tsx src/features/auth/ResetPasswordPage.tsx src/routes/router.tsx tests/auth/passwordReset.test.tsx && git commit -m "feat(web): forgot-password and reset-password pages"
  ```

---

## Task 11: WEB — surface "email not verified" on login with a resend hint

When login returns `403 { error: 'EMAIL_NOT_VERIFIED' }`, the login page shows a message and a resend control wired to `useResendVerification`.

**Files**

- Modify: `/apps/web/src/features/auth/useLogin.ts`
- Modify: `/apps/web/src/features/auth/LoginPage.tsx`
- Test: `/apps/web/tests/auth/loginUnverified.test.tsx`

Steps:

- [ ] **Step 1: Write the failing test.**
  Create `/apps/web/tests/auth/loginUnverified.test.tsx`:

  ```tsx
  import { describe, expect, it, beforeAll, afterEach, afterAll } from 'vitest';
  import { render, screen, waitFor } from '@testing-library/react';
  import userEvent from '@testing-library/user-event';
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
  import { MemoryRouter } from 'react-router';
  import { http, HttpResponse } from 'msw';
  import { setupServer } from 'msw/node';
  import { LoginPage } from '../../src/features/auth/LoginPage';

  const server = setupServer(
    http.post('/api/auth/login', () =>
      HttpResponse.json({ error: 'EMAIL_NOT_VERIFIED' }, { status: 403 }),
    ),
    http.post('/api/auth/resend-verification', () => HttpResponse.json({ ok: true })),
  );

  beforeAll(() => server.listen());
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  function renderLogin() {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <LoginPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  describe('LoginPage unverified email', () => {
    it('shows a verify-email message and a resend control on 403', async () => {
      renderLogin();
      await userEvent.type(screen.getByLabelText(/email/i), 'u@b.com');
      await userEvent.type(screen.getByLabelText(/password/i), 'a-password-123');
      await userEvent.click(screen.getByRole('button', { name: /log in/i }));
      await waitFor(() =>
        expect(screen.getByText(/verify your email/i)).toBeInTheDocument(),
      );
      expect(screen.getByRole('button', { name: /resend/i })).toBeInTheDocument();
    });
  });
  ```

- [ ] **Step 2: Run the test and confirm it FAILS.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/loginUnverified.test.tsx
  ```

  Expected: FAIL — no "verify your email" text / no resend button rendered.

- [ ] **Step 3: Make `useLogin` carry the server error code.**
  Read the existing hook:

  ```bash
  cd /apps/web && cat src/features/auth/useLogin.ts
  ```

  Its `mutationFn` currently throws a generic error on non-OK. Change it so the thrown error includes the response `code`. Replace the non-OK branch so it parses the body:

  ```ts
      mutationFn: async (creds: { email: string; password: string }) => {
        try {
          return await apiClient.post('/api/auth/login', creds);
        } catch (err) {
          // apiClient throws on non-2xx; re-throw a typed error carrying the server's error code.
          const code = (err as { body?: { error?: string } }).body?.error;
          const e = new Error(code ?? 'LOGIN_FAILED') as Error & { code?: string };
          e.code = code;
          throw e;
        }
      },
  ```

  (Adjust to the exact shape `apiClient` attaches to thrown errors, confirmed by reading `apiClient.ts` in Task 9 Step 1. If `apiClient` exposes the parsed body on `err.body`, the above matches; otherwise read the status/body off the error accordingly.)

- [ ] **Step 4: Render the unverified branch in `LoginPage`.**
  Read the file:

  ```bash
  cd /apps/web && cat src/features/auth/LoginPage.tsx
  ```

  Import the resend hook and add state. Add the import:

  ```tsx
  import { useResendVerification } from './useResendVerification';
  ```

  Inside the component, after the existing `useLogin()` hook, add:

  ```tsx
    const resend = useResendVerification();
    const loginError = login.error as (Error & { code?: string }) | null;
    const unverified = loginError?.code === 'EMAIL_NOT_VERIFIED';
  ```

  Then, in the JSX where errors are shown, add (the `email` value comes from the form's current input via `getValues('email')` — RHF `getValues` is available from `useForm`; destructure it):

  ```tsx
    {unverified && (
      <div>
        <p>Please verify your email before logging in.</p>
        {resend.isSuccess ? (
          <p>Verification email resent.</p>
        ) : (
          <button type="button" onClick={() => resend.mutate(getValues('email'))}>
            Resend verification email
          </button>
        )}
      </div>
    )}
  ```

  Ensure `getValues` is destructured from `useForm(...)` in this component.

- [ ] **Step 5: Run the test and confirm it PASSES.**

  ```bash
  cd /apps/web && npx vitest run tests/auth/loginUnverified.test.tsx
  ```

  Expected: PASS — `1 passed`.

- [ ] **Step 6: Commit.**

  ```bash
  cd /apps/web && git add src/features/auth/useLogin.ts src/features/auth/LoginPage.tsx tests/auth/loginUnverified.test.tsx && git commit -m "feat(web): show email-not-verified state with resend on login"
  ```

---

## Task 12: Final web suite + type-check, then full-stack smoke

Confirm the whole frontend builds and all slice tests pass, then run the end-to-end Docker stack once to eyeball the real flow against Mailpit.

**Files**

- (no source changes unless a regression surfaces)

Steps:

- [ ] **Step 1: Type-check the web app.**

  ```bash
  cd /apps/web && npx tsc --noEmit
  ```

  Expected: exit code 0.

- [ ] **Step 2: Run the entire web test suite.**

  ```bash
  cd /apps/web && npx vitest run
  ```

  Expected: PASS — all web suites green (verifyEmail, passwordReset, loginUnverified, plus earlier-plan tests).

- [ ] **Step 3: Bring up the full Docker stack.**

  ```bash
  docker compose up -d --build
  ```

  Expected: all 6 services healthy (`docker compose ps` shows `caddy`, `web`, `api`, `db`, `redis`, `mailpit` up; `api` ran `prisma migrate deploy` then started `tsx watch`).

- [ ] **Step 4: Smoke the register -> verify -> login -> reset flow against the live API.**

  ```bash
  curl -k -X POST https://localhost/api/auth/register -H 'content-type: application/json' -d '{"email":"smoke@example.com","password":"correct horse battery"}'
  curl -s 'http://localhost:8025/api/v1/search?query=to%3Asmoke@example.com&limit=1'
  ```

  Expected: register returns `{"ok":true}` (201); the Mailpit search returns one message with subject "Verify your email". Open `https://localhost/verify-email?token=<token from the mail body>` in a browser (trust Caddy's local CA once via `caddy trust` if prompted), confirm "Email verified", then log in.

- [ ] **Step 5: Tear down the stack.**

  ```bash
  docker compose down
  ```

  Expected: all services stopped and removed.

- [ ] **Step 6: Final slice commit (if Step 3/4 required any fix).**

  ```bash
  cd /apps/api && git add -A && git commit -m "chore: finalize email verification and password reset slice"
  ```

  (Skip if nothing changed during smoke testing.)
