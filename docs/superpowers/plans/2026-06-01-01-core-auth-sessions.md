# Core Auth — Register, Login, Logout, /me with Redis Sessions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the end-to-end authentication tracer bullet (register active-immediately, login, logout, GET /me) with server-side opaque Redis sessions, double-submit CSRF, helmet/cors/rate-limit security, and a React SPA login/register flow with a protected dashboard.

**Architecture:** An Express 5 + TypeScript (ESM, strict) API stores sessions in Redis via `express-session` + `connect-redis` behind an `__Host-sid` httpOnly cookie; argon2id hashes passwords; per-user session sets in Redis enable future logout-all; all auth errors are generic to prevent enumeration. A Vite + React SPA calls the API same-origin (through Caddy/Vite proxy) with `credentials:"include"`, echoes a CSRF token in `x-csrf-token`, and uses TanStack Query (`useMe`) to drive a `ProtectedRoute` guard.

**Tech Stack:** Express 5, express-session 1.19, connect-redis 9, node-redis 6, csrf-csrf 4, helmet 8, cors, express-rate-limit 8 + rate-limit-redis 5, argon2 0.43, zod 4, Prisma 7 (`prisma-client` generator + `@prisma/adapter-pg`), Vitest 4 + supertest 7, React 19 + React Router 7, TanStack Query 5, React Hook Form 7 + @hookform/resolvers 5, Vitest + React Testing Library + MSW.

---

## Files Overview

This plan assumes Plan 00 already created the full `prisma/schema.prisma`, the initial migration, `apps/api/package.json`, `tsconfig.json`, `apps/api/Dockerfile`, `apps/web/package.json`, and the Docker/Caddy infra. We BUILD ON that — no new Prisma migrations are added here.

**API files (`apps/api/`):**

- `src/config/env.ts` — zod-validated `process.env`. **Owned by Plan 00 — this plan imports `env`, it does NOT create this file.**
- `src/db/prisma.ts` — PrismaClient singleton (driver-adapter). **Owned by Plan 00 — this plan imports `prisma`, it does NOT create this file.**
- `src/redis/client.ts` — connected node-redis singleton. **Owned by Plan 00 — this plan imports `redis`, it does NOT create this file.**
- `src/lib/password.ts` — argon2id `hashPassword` / `verifyPassword`.
- `src/lib/audit.ts` — `writeAudit` (inserts `AuditLog`).
- `src/lib/sessionStore.ts` — per-user Redis session-id set helpers.
- `src/middleware/session.ts` — express-session + connect-redis (`__Host-sid`).
- `src/middleware/csrf.ts` — csrf-csrf double-submit + `generateCsrfToken`.
- `src/middleware/security.ts` — helmet + cors.
- `src/middleware/rateLimit.ts` — global + auth limiters (rate-limit-redis).
- `src/middleware/requireAuth.ts` — 401 if no session user.
- `src/middleware/errorHandler.ts` — central error responder.
- `src/modules/auth/auth.schema.ts` — zod register/login bodies.
- `src/modules/auth/auth.service.ts` — `createUser`, `verifyCredentials`.
- `src/modules/auth/auth.routes.ts` — register/login/logout/me routes.
- `src/types/session.d.ts` — augments `express-session` SessionData.
- `src/app.ts` — assembles middleware + mounts routes + health + csrf. **Owned by Plan 00 (health + base middleware) — this plan MODIFIES it to add session/csrf/routes, it does NOT create this file.**
- `src/server.ts` — http bootstrap (`app.listen`). **Owned by Plan 00 — this plan does NOT create or modify this file.**

**API tests (`apps/api/tests/`):**

- `tests/helpers/db.ts` — truncate + redis flush + mailpit clear.
- `tests/helpers/agent.ts` — supertest agent + CSRF priming helper.
- `tests/auth/register.test.ts`, `login.test.ts`, `logout.test.ts`, `me.test.ts`, `enumeration.test.ts`.

**Web files (`apps/web/`):**

- `src/lib/apiClient.ts` — fetch wrapper (`credentials:"include"` + CSRF header).
- `src/lib/queryClient.ts` — TanStack Query client.
- `src/features/auth/useMe.ts`, `useLogin.ts`, `useRegister.ts`, `useLogout.ts`.
- `src/features/auth/LoginPage.tsx`, `RegisterPage.tsx`.
- `src/features/dashboard/Dashboard.tsx`.
- `src/routes/ProtectedRoute.tsx`, `src/routes/router.tsx`.
- `src/App.tsx`, `src/main.tsx`.

**Web tests (`apps/web/tests/`):**

- `tests/setup.ts` — RTL/jest-dom + MSW server lifecycle.
- `tests/mocks/server.ts`, `tests/mocks/handlers.ts` — MSW.
- `tests/LoginPage.test.tsx`, `tests/ProtectedRoute.test.tsx`.

---

## Task 1: API config — zod-validated env (Plan 00 owns; verify only)

> **Plan 00 owns `apps/api/src/config/env.ts`** and exports the zod-validated `env` (on failure it logs + `process.exit(1)`). This plan does **NOT** create or modify that file — it only imports `env` everywhere below. This task is a verification gate that the contract export exists and validates correctly.

**Files:**

- Import only: `apps/api/src/config/env.ts` (created by Plan 00)
- Test: `apps/api/tests/config/env.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/config/env.test.ts
import { describe, it, expect } from 'vitest';

describe('env', () => {
  it('parses a valid environment', async () => {
    const { parseEnv } = await import('../../src/config/env.js');
    const parsed = parseEnv({
      DATABASE_URL: 'postgres://app:app@db:5432/app',
      REDIS_URL: 'redis://redis:6379',
      SESSION_SECRET: 'x'.repeat(32),
      CSRF_SECRET: 'y'.repeat(32),
      SMTP_HOST: 'mailpit',
      SMTP_PORT: '1025',
      MAIL_FROM: 'auth@example.com',
      APP_URL: 'https://localhost',
      NODE_ENV: 'test',
    });
    expect(parsed.SMTP_PORT).toBe(1025);
    expect(parsed.APP_URL).toBe('https://localhost');
  });

  it('throws when SESSION_SECRET is too short', async () => {
    const { parseEnv } = await import('../../src/config/env.js');
    expect(() =>
      parseEnv({
        DATABASE_URL: 'postgres://app:app@db:5432/app',
        REDIS_URL: 'redis://redis:6379',
        SESSION_SECRET: 'short',
        CSRF_SECRET: 'y'.repeat(32),
        SMTP_HOST: 'mailpit',
        SMTP_PORT: '1025',
        MAIL_FROM: 'auth@example.com',
        APP_URL: 'https://localhost',
        NODE_ENV: 'test',
      }),
    ).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/config/env.test.ts`
Expected: FAIL only if Plan 00 has not yet provided `src/config/env.ts` with the contract export.

- [ ] **Step 3: Confirm Plan 00's implementation (do NOT create this file)**

`apps/api/src/config/env.ts` is **created and owned by Plan 00**. It exports the zod-validated `env` singleton (and the `parseEnv` helper the test exercises); on validation failure it logs the issues and calls `process.exit(1)`. Do **not** recreate or edit it here — just confirm the contract export shape:

```ts
// apps/api/src/config/env.ts  (Plan 00 owns — reference only)
export const env: Readonly<{
  NODE_ENV: string; PORT: number;
  DATABASE_URL: string; REDIS_URL: string;
  SESSION_SECRET: string; CSRF_SECRET: string;
  SMTP_HOST: string; SMTP_PORT: number; MAIL_FROM: string;
  APP_URL: string;
}>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/config/env.test.ts`
Expected: PASS — 2 passed.

> Note: `env` is evaluated at module load against the test runner's env vars. Plan 00's `vitest.config.ts` loads `.env.test`; if `env` evaluation fails in tests, ensure `apps/api/.env.test` exists with the keys above. The test imports `parseEnv` directly and never relies on the module-level `env`, so it is robust either way.

- [ ] **Step 5: Commit**

```bash
git add apps/api/tests/config/env.test.ts
git commit -m "test: verify Plan 00 zod-validated env config contract"
```

---

## Task 2: Redis client singleton (Plan 00 owns; verify only)

> **Plan 00 owns `apps/api/src/redis/client.ts`** and exports the canonical `redis` client plus `connectRedis()` / `disconnectRedis()`. This plan does **NOT** create or modify that file — it only imports `redis`. This task is a verification gate.

**Files:**

- Import only: `apps/api/src/redis/client.ts` (created by Plan 00)
- Test: `apps/api/tests/redis/client.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/redis/client.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { redis, connectRedis } from '../../src/redis/client.js';

describe('redis client', () => {
  beforeAll(async () => {
    await connectRedis();
  });

  afterAll(async () => {
    await redis.quit();
  });

  it('is connected and responds to PING', async () => {
    const pong = await redis.ping();
    expect(pong).toBe('PONG');
  });

  it('can set and get a key', async () => {
    await redis.set('test:key', 'hello');
    const value = await redis.get('test:key');
    expect(value).toBe('hello');
    await redis.del('test:key');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/redis/client.test.ts`
Expected: FAIL only if Plan 00 has not yet provided `src/redis/client.ts` with the contract exports.

- [ ] **Step 3: Confirm Plan 00's implementation (do NOT create this file)**

`apps/api/src/redis/client.ts` is **created and owned by Plan 00**. The canonical export is `redis` (NOT `redisClient`); the client is created but **not** auto-connected — `connectRedis()` opens it and `disconnectRedis()` closes it. Do **not** recreate or edit it here — just confirm the contract export shape:

```ts
// apps/api/src/redis/client.ts  (Plan 00 owns — reference only)
import { type RedisClientType } from 'redis';
export const redis: RedisClientType;
export async function connectRedis(): Promise<void>;
export async function disconnectRedis(): Promise<void>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/redis/client.test.ts`
Expected: PASS — 2 passed (requires the test Redis from docker-compose to be reachable at `REDIS_URL`).

- [ ] **Step 5: Commit**

```bash
git add apps/api/tests/redis/client.test.ts
git commit -m "test: verify Plan 00 redis client singleton contract"
```

---

## Task 3: Prisma client singleton (Plan 00 owns; verify only)

> **Plan 00 owns `apps/api/src/db/prisma.ts`** and exports the `prisma` PrismaClient singleton (driver-adapter). This plan does **NOT** create or modify that file — it only imports `prisma`. This task is a verification gate.

**Files:**

- Import only: `apps/api/src/db/prisma.ts` (created by Plan 00)
- Test: `apps/api/tests/db/prisma.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/db/prisma.test.ts
import { describe, it, expect } from 'vitest';
import { prisma } from '../../src/db/prisma.js';

describe('prisma client', () => {
  it('runs a trivial query against the test database', async () => {
    const rows = await prisma.$queryRaw<{ one: number }[]>`SELECT 1 as one`;
    expect(rows[0].one).toBe(1);
  });

  it('exposes the user model', () => {
    expect(typeof prisma.user.findUnique).toBe('function');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/db/prisma.test.ts`
Expected: FAIL only if Plan 00 has not yet provided `src/db/prisma.ts` with the contract export.

- [ ] **Step 3: Confirm Plan 00's implementation (do NOT create this file)**

`apps/api/src/db/prisma.ts` is **created and owned by Plan 00** (Prisma 7 driver adapter, `PrismaClient` from the generated output dir `src/generated/prisma`). Do **not** recreate or edit it here — just confirm the contract export shape:

```ts
// apps/api/src/db/prisma.ts  (Plan 00 owns — reference only)
import { PrismaClient } from '../generated/prisma/client.js';
export const prisma: PrismaClient;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/db/prisma.test.ts`
Expected: PASS — 2 passed (requires the test Postgres reachable + `prisma migrate deploy` already applied by Plan 00).

- [ ] **Step 5: Commit**

```bash
git add apps/api/tests/db/prisma.test.ts
git commit -m "test: verify Plan 00 prisma client singleton contract"
```

---

## Task 4: Password hashing (argon2id)

**Files:**

- Create: `apps/api/src/lib/password.ts`
- Test: `apps/api/tests/lib/password.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/lib/password.test.ts
import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword } from '../../src/lib/password.js';

describe('password', () => {
  it('hashes to a PHC argon2id string distinct from the plaintext', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).not.toBe('correct horse battery staple');
    expect(hash.startsWith('$argon2id$')).toBe(true);
  });

  it('verifies a correct password', async () => {
    const hash = await hashPassword('s3cret-password');
    expect(await verifyPassword(hash, 's3cret-password')).toBe(true);
  });

  it('rejects an incorrect password', async () => {
    const hash = await hashPassword('s3cret-password');
    expect(await verifyPassword(hash, 'wrong-password')).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/lib/password.test.ts`
Expected: FAIL — `Cannot find module '../../src/lib/password.js'`.

- [ ] **Step 3: Write minimal implementation**

node-argon2 defaults are argon2id and already exceed OWASP — no options needed.

```ts
// apps/api/src/lib/password.ts
import argon2 from 'argon2';

export function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain);
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    // argon2.verify throws only on a malformed stored hash; treat as non-match.
    return false;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/lib/password.test.ts`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/lib/password.ts apps/api/tests/lib/password.test.ts
git commit -m "feat: add argon2id password hashing helpers"
```

---

## Task 5: Audit log helper

**Files:**

- Create: `apps/api/src/lib/audit.ts`
- Test: `apps/api/tests/lib/audit.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/lib/audit.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { writeAudit } from '../../src/lib/audit.js';
import { prisma } from '../../src/db/prisma.js';

beforeEach(async () => {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
  );
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('writeAudit', () => {
  it('records an event with no user (e.g. login_fail)', async () => {
    await writeAudit({ event: 'login_fail', ip: '127.0.0.1', userAgent: 'vitest' });
    const rows = await prisma.auditLog.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0].event).toBe('login_fail');
    expect(rows[0].userId).toBeNull();
  });

  it('records an event tied to a user', async () => {
    const user = await prisma.user.create({
      data: { email: 'a@b.com', passwordHash: 'x', emailVerifiedAt: new Date() },
    });
    await writeAudit({ userId: user.id, event: 'login_success' });
    const rows = await prisma.auditLog.findMany();
    expect(rows[0].userId).toBe(user.id);
    expect(rows[0].event).toBe('login_success');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/lib/audit.test.ts`
Expected: FAIL — `Cannot find module '../../src/lib/audit.js'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// apps/api/src/lib/audit.ts
import { prisma } from '../db/prisma.js';

// Canonical audit event union (CONTRACTS). Used by Plans 01–04.
export type AuditEvent =
  | 'register' | 'login_success' | 'login_fail' | 'logout' | 'logout_all'
  | 'password_reset' | 'password_change' | 'email_change' | 'email_verified';

export interface AuditInput {
  event: AuditEvent;
  userId?: string;
  ip?: string;
  userAgent?: string;
}

export async function writeAudit(input: AuditInput): Promise<void> {
  await prisma.auditLog.create({
    data: {
      userId: input.userId ?? null,
      event: input.event,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
    },
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/lib/audit.test.ts`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/lib/audit.ts apps/api/tests/lib/audit.test.ts
git commit -m "feat: add audit log helper"
```

---

## Task 6: Per-user session store (Redis set)

**Files:**

- Create: `apps/api/src/lib/sessionStore.ts`
- Test: `apps/api/tests/lib/sessionStore.test.ts`

This is the helper Plan 02 (reset-password) and Plan 03 (logout-all) reuse to destroy every session for a user. It maintains a Redis set `user_sessions:<userId>` of session ids. Session blobs are stored by express-session under the key prefix `app:sess:` (configured in Task 8), so destroying a session means deleting `app:sess:<sid>`.

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/lib/sessionStore.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { redis } from '../../src/redis/client.js';
import {
  SESSION_PREFIX,
  addUserSession,
  removeUserSession,
  destroyAllUserSessions,
} from '../../src/lib/sessionStore.js';

beforeEach(async () => {
  await redis.flushDb();
});

afterAll(async () => {
  await redis.quit();
});

describe('sessionStore', () => {
  it('indexes a session id under the user set', async () => {
    await addUserSession('user1', 'sidA');
    const members = await redis.sMembers('user_sessions:user1');
    expect(members).toEqual(['sidA']);
  });

  it('de-indexes a single session id', async () => {
    await addUserSession('user1', 'sidA');
    await addUserSession('user1', 'sidB');
    await removeUserSession('user1', 'sidA');
    const members = await redis.sMembers('user_sessions:user1');
    expect(members).toEqual(['sidB']);
  });

  it('destroys every session blob and clears the set', async () => {
    await redis.set(`${SESSION_PREFIX}sidA`, 'blobA');
    await redis.set(`${SESSION_PREFIX}sidB`, 'blobB');
    await addUserSession('user1', 'sidA');
    await addUserSession('user1', 'sidB');

    await destroyAllUserSessions('user1');

    expect(await redis.get(`${SESSION_PREFIX}sidA`)).toBeNull();
    expect(await redis.get(`${SESSION_PREFIX}sidB`)).toBeNull();
    expect(await redis.exists('user_sessions:user1')).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/lib/sessionStore.test.ts`
Expected: FAIL — `Cannot find module '../../src/lib/sessionStore.js'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// apps/api/src/lib/sessionStore.ts
import { redis } from '../redis/client.js';

// Must match the connect-redis store prefix configured in middleware/session.ts
export const SESSION_PREFIX = 'app:sess:';

function userSetKey(userId: string): string {
  return `user_sessions:${userId}`;
}

export async function addUserSession(userId: string, sessionId: string): Promise<void> {
  await redis.sAdd(userSetKey(userId), sessionId);
}

export async function removeUserSession(userId: string, sessionId: string): Promise<void> {
  await redis.sRem(userSetKey(userId), sessionId);
}

export async function destroyAllUserSessions(userId: string): Promise<void> {
  const key = userSetKey(userId);
  const sessionIds = await redis.sMembers(key);
  if (sessionIds.length > 0) {
    await redis.del(sessionIds.map((sid) => `${SESSION_PREFIX}${sid}`));
  }
  await redis.del(key);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/lib/sessionStore.test.ts`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/lib/sessionStore.ts apps/api/tests/lib/sessionStore.test.ts
git commit -m "feat: add per-user redis session set helper"
```

---

## Task 7: Session type augmentation

**Files:**

- Create: `apps/api/src/types/session.d.ts`

This makes `req.session.userId` and `req.session.role` type-safe across the codebase. Session data per FOUNDATION is `{ userId, role }`.

- [ ] **Step 1: Write the declaration file**

```ts
// apps/api/src/types/session.d.ts
import 'express-session';
import type { Role } from '../generated/prisma/client.js';

declare module 'express-session' {
  interface SessionData {
    userId?: string;
    role?: Role;
  }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd apps/api && npx tsc --noEmit`
Expected: PASS — no type errors (the file is picked up because `tsconfig.json` includes `src/**/*`).

- [ ] **Step 3: Commit**

```bash
git add apps/api/src/types/session.d.ts
git commit -m "chore: augment express-session SessionData with userId and role"
```

---

## Task 8: Session middleware (express-session + connect-redis)

**Files:**

- Create: `apps/api/src/middleware/session.ts`
- Test: `apps/api/tests/middleware/session.test.ts`

- [ ] **Step 1: Write the failing test**

The test mounts the session middleware on a tiny app, sets a value, then re-requests with the returned cookie to prove the session persisted in Redis. The cookie is named `__Host-sid`.

```ts
// apps/api/tests/middleware/session.test.ts
import { describe, it, expect, afterAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { sessionMiddleware } from '../../src/middleware/session.js';
import { redis } from '../../src/redis/client.js';

function buildApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(sessionMiddleware);
  app.post('/set', (req, res) => {
    req.session.userId = 'u123';
    res.json({ ok: true });
  });
  app.get('/get', (req, res) => {
    res.json({ userId: req.session.userId ?? null });
  });
  return app;
}

afterAll(async () => {
  await redis.quit();
});

describe('sessionMiddleware', () => {
  it('issues a __Host-sid cookie and persists session data in redis', async () => {
    const app = buildApp();
    const agent = request.agent(app);

    const setRes = await agent.post('/set').set('X-Forwarded-Proto', 'https').expect(200);
    const cookies = setRes.headers['set-cookie'];
    expect(cookies.some((c: string) => c.startsWith('__Host-sid='))).toBe(true);

    const getRes = await agent.get('/get').set('X-Forwarded-Proto', 'https').expect(200);
    expect(getRes.body.userId).toBe('u123');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/middleware/session.test.ts`
Expected: FAIL — `Cannot find module '../../src/middleware/session.js'`.

- [ ] **Step 3: Write minimal implementation**

Cookie name `__Host-sid`; `secure:true`, `httpOnly:true`, `sameSite:'lax'`, `path:'/'`, rolling idle TTL 7 days. The connect-redis store prefix is `app:sess:` — matching `SESSION_PREFIX` from Task 6.

```ts
// apps/api/src/middleware/session.ts
import session from 'express-session';
import { RedisStore } from 'connect-redis';
import { redis } from '../redis/client.js';
import { env } from '../config/env.js';
import { SESSION_PREFIX } from '../lib/sessionStore.js';

const SEVEN_DAYS_MS = 1000 * 60 * 60 * 24 * 7;

const store = new RedisStore({
  client: redis,
  prefix: SESSION_PREFIX,
  ttl: SEVEN_DAYS_MS / 1000, // connect-redis ttl is in SECONDS
});

export const sessionMiddleware = session({
  store,
  name: '__Host-sid',
  secret: env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true, // refresh idle TTL on every response
  cookie: {
    httpOnly: true,
    secure: true, // mandatory for __Host- prefix
    sameSite: 'lax',
    path: '/', // mandatory for __Host- prefix
    maxAge: SEVEN_DAYS_MS,
    // do NOT set `domain` — __Host- forbids it
  },
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/middleware/session.test.ts`
Expected: PASS — 1 passed.

> Why `X-Forwarded-Proto: https` + `trust proxy`: `secure:true` cookies are only emitted when express considers the connection HTTPS. In production Caddy terminates TLS and forwards this header; the test simulates it.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/middleware/session.ts apps/api/tests/middleware/session.test.ts
git commit -m "feat: add express-session + connect-redis session middleware"
```

---

## Task 9: CSRF middleware (csrf-csrf double-submit)

**Files:**

- Create: `apps/api/src/middleware/csrf.ts`
- Test: `apps/api/tests/middleware/csrf.test.ts`

csrf-csrf v4: `generateCsrfToken` (NOT `generateToken`), `getSessionIdentifier` is REQUIRED, token read from the `x-csrf-token` header, cookie-parser registered BEFORE the middleware.

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/middleware/csrf.test.ts
import { describe, it, expect, afterAll } from 'vitest';
import express from 'express';
import cookieParser from 'cookie-parser';
import request from 'supertest';
import { sessionMiddleware } from '../../src/middleware/session.js';
import { csrfProtection, issueCsrfToken } from '../../src/middleware/csrf.js';
import { redis } from '../../src/redis/client.js';

function buildApp() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json());
  app.use(cookieParser());
  app.use(sessionMiddleware);
  app.get('/csrf', (req, res) => res.json({ csrfToken: issueCsrfToken(req, res) }));
  app.use(csrfProtection);
  app.post('/mutate', (_req, res) => res.json({ ok: true }));
  return app;
}

afterAll(async () => {
  await redis.quit();
});

describe('csrf middleware', () => {
  it('rejects a POST without a csrf token (403)', async () => {
    const agent = request.agent(buildApp());
    await agent.post('/mutate').set('X-Forwarded-Proto', 'https').send({}).expect(403);
  });

  it('accepts a POST that echoes the issued token in x-csrf-token', async () => {
    const agent = request.agent(buildApp());
    const csrfRes = await agent.get('/csrf').set('X-Forwarded-Proto', 'https').expect(200);
    const token = csrfRes.body.csrfToken as string;
    await agent
      .post('/mutate')
      .set('X-Forwarded-Proto', 'https')
      .set('x-csrf-token', token)
      .send({})
      .expect(200);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/middleware/csrf.test.ts`
Expected: FAIL — `Cannot find module '../../src/middleware/csrf.js'`.

- [ ] **Step 3: Write minimal implementation**

The CSRF cookie is non-`__Host-` and `httpOnly:false` so the SPA can read it; the secret + session id bind the token. (Per FOUNDATION the client attaches `x-csrf-token` from a csrf cookie; csrf-csrf manages that cookie.)

```ts
// apps/api/src/middleware/csrf.ts
import type { Request, Response } from 'express';
import { doubleCsrf } from 'csrf-csrf';
import { env } from '../config/env.js';

const {
  doubleCsrfProtection,
  generateCsrfToken,
  invalidCsrfTokenError,
} = doubleCsrf({
  getSecret: () => env.CSRF_SECRET,
  getSessionIdentifier: (req: Request) => req.session.id,
  cookieName: 'x-csrf-token',
  cookieOptions: {
    sameSite: 'lax',
    secure: true,
    httpOnly: false, // SPA must read it to echo in the header
    path: '/',
  },
  getCsrfTokenFromRequest: (req: Request) => req.headers['x-csrf-token'] as string | undefined,
});

export const csrfProtection = doubleCsrfProtection;
export const csrfInvalidError = invalidCsrfTokenError;

export function issueCsrfToken(req: Request, res: Response): string {
  return generateCsrfToken(req, res);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/middleware/csrf.test.ts`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/middleware/csrf.ts apps/api/tests/middleware/csrf.test.ts
git commit -m "feat: add csrf-csrf double-submit middleware"
```

---

## Task 10: Security middleware (helmet + cors)

**Files:**

- Create: `apps/api/src/middleware/security.ts`
- Test: `apps/api/tests/middleware/security.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/middleware/security.test.ts
import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { securityMiddleware } from '../../src/middleware/security.js';

function buildApp() {
  const app = express();
  app.use(securityMiddleware);
  app.get('/x', (_req, res) => res.json({ ok: true }));
  return app;
}

describe('security middleware', () => {
  it('sets helmet security headers (HSTS + CSP)', async () => {
    const res = await request(buildApp()).get('/x').expect(200);
    expect(res.headers['strict-transport-security']).toContain('max-age=');
    expect(res.headers['content-security-policy']).toContain("default-src 'self'");
  });

  it('reflects the configured origin with credentials for allowed origin', async () => {
    const res = await request(buildApp())
      .get('/x')
      .set('Origin', 'https://localhost')
      .expect(200);
    expect(res.headers['access-control-allow-origin']).toBe('https://localhost');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/middleware/security.test.ts`
Expected: FAIL — `Cannot find module '../../src/middleware/security.js'`.

- [ ] **Step 3: Write minimal implementation**

CORS is locked to the single origin (`env.APP_URL`) with `credentials:true`. helmet uses v8 camelCase option names.

```ts
// apps/api/src/middleware/security.ts
import { type RequestHandler } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { env } from '../config/env.js';

const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:'],
      'connect-src': ["'self'"],
      'object-src': ["'none'"],
      'frame-ancestors': ["'self'"],
    },
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
});

const corsMiddleware = cors({
  origin: env.APP_URL,
  credentials: true,
});

export const securityMiddleware: RequestHandler[] = [helmetMiddleware, corsMiddleware];
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/middleware/security.test.ts`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/middleware/security.ts apps/api/tests/middleware/security.test.ts
git commit -m "feat: add helmet + cors security middleware"
```

---

## Task 11: Rate-limit middleware (express-rate-limit + rate-limit-redis)

**Files:**

- Create: `apps/api/src/middleware/rateLimit.ts`
- Test: `apps/api/tests/middleware/rateLimit.test.ts`

- [ ] **Step 1: Write the failing test**

A tight `authLimiter` (limit 3 in test window) returns 429 on the 4th request.

```ts
// apps/api/tests/middleware/rateLimit.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { authLimiter } from '../../src/middleware/rateLimit.js';
import { redis } from '../../src/redis/client.js';

function buildApp() {
  const app = express();
  app.use('/auth', authLimiter);
  app.post('/auth/login', (_req, res) => res.json({ ok: true }));
  return app;
}

beforeEach(async () => {
  await redis.flushDb();
});

afterAll(async () => {
  await redis.quit();
});

describe('authLimiter', () => {
  it('returns 429 after exceeding the auth limit', async () => {
    const app = buildApp();
    for (let i = 0; i < 10; i++) {
      const res = await request(app).post('/auth/login').send({});
      if (res.status === 429) {
        expect(res.status).toBe(429);
        return;
      }
    }
    throw new Error('expected a 429 within 10 requests');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/middleware/rateLimit.test.ts`
Expected: FAIL — `Cannot find module '../../src/middleware/rateLimit.js'`.

- [ ] **Step 3: Write minimal implementation**

node-redis `sendCommand: (...args) => redis.sendCommand(args)` form. Use `limit` (not deprecated `max`). The auth limiter is tighter than the global one. Use a small limit in test mode so the test is fast.

```ts
// apps/api/src/middleware/rateLimit.ts
import { rateLimit } from 'express-rate-limit';
import { RedisStore } from 'rate-limit-redis';
import { redis } from '../redis/client.js';
import { env } from '../config/env.js';

const isTest = env.NODE_ENV === 'test';

export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 1000,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  store: new RedisStore({
    prefix: 'rl:global:',
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: isTest ? 3 : 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  store: new RedisStore({
    prefix: 'rl:auth:',
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
});
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/middleware/rateLimit.test.ts`
Expected: PASS — 1 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/middleware/rateLimit.ts apps/api/tests/middleware/rateLimit.test.ts
git commit -m "feat: add redis-backed global and auth rate limiters"
```

---

## Task 12: requireAuth middleware

**Files:**

- Create: `apps/api/src/middleware/requireAuth.ts`
- Test: `apps/api/tests/middleware/requireAuth.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/middleware/requireAuth.test.ts
import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { requireAuth } from '../../src/middleware/requireAuth.js';

function buildApp(seedUserId?: string) {
  const app = express();
  app.use((req, _res, next) => {
    // Fake a session object for the test.
    (req as unknown as { session: { userId?: string } }).session = { userId: seedUserId };
    next();
  });
  app.get('/protected', requireAuth, (_req, res) => res.json({ ok: true }));
  return app;
}

describe('requireAuth', () => {
  it('returns 401 when there is no session user', async () => {
    await request(buildApp(undefined)).get('/protected').expect(401);
  });

  it('calls next when a session user exists', async () => {
    await request(buildApp('u123')).get('/protected').expect(200, { ok: true });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/middleware/requireAuth.test.ts`
Expected: FAIL — `Cannot find module '../../src/middleware/requireAuth.js'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// apps/api/src/middleware/requireAuth.ts
import type { Request, Response, NextFunction } from 'express';

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session?.userId) {
    res.status(401).json({ error: 'unauthenticated' });
    return;
  }
  next();
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/middleware/requireAuth.test.ts`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/middleware/requireAuth.ts apps/api/tests/middleware/requireAuth.test.ts
git commit -m "feat: add requireAuth middleware"
```

---

## Task 13: errorHandler middleware

**Files:**

- Create: `apps/api/src/middleware/errorHandler.ts`
- Test: `apps/api/tests/middleware/errorHandler.test.ts`

Central handler returns generic JSON; maps the csrf invalid-token error to 403; never leaks internals.

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/middleware/errorHandler.test.ts
import { describe, it, expect } from 'vitest';
import express from 'express';
import request from 'supertest';
import { errorHandler } from '../../src/middleware/errorHandler.js';
import { csrfInvalidError } from '../../src/middleware/csrf.js';

describe('errorHandler', () => {
  it('returns 500 with a generic message for unexpected errors', async () => {
    const app = express();
    app.get('/boom', () => {
      throw new Error('secret internal detail');
    });
    app.use(errorHandler);
    const res = await request(app).get('/boom').expect(500);
    expect(res.body).toEqual({ error: 'internal_error' });
    expect(JSON.stringify(res.body)).not.toContain('secret internal detail');
  });

  it('returns 403 for the csrf invalid-token error', async () => {
    const app = express();
    app.get('/csrf-boom', () => {
      throw csrfInvalidError;
    });
    app.use(errorHandler);
    const res = await request(app).get('/csrf-boom').expect(403);
    expect(res.body).toEqual({ error: 'invalid_csrf_token' });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/middleware/errorHandler.test.ts`
Expected: FAIL — `Cannot find module '../../src/middleware/errorHandler.js'`.

- [ ] **Step 3: Write minimal implementation**

`HttpError` lets services throw status-bearing errors; everything else becomes a generic 500.

```ts
// apps/api/src/middleware/errorHandler.ts
import type { Request, Response, NextFunction } from 'express';
import { csrfInvalidError } from './csrf.js';

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(code);
    this.name = 'HttpError';
  }
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction,
): void {
  if (err === csrfInvalidError) {
    res.status(403).json({ error: 'invalid_csrf_token' });
    return;
  }
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('[errorHandler] unexpected error', err);
  res.status(500).json({ error: 'internal_error' });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/middleware/errorHandler.test.ts`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/middleware/errorHandler.ts apps/api/tests/middleware/errorHandler.test.ts
git commit -m "feat: add central errorHandler with generic responses"
```

---

## Task 14: Auth zod schemas

**Files:**

- Create: `apps/api/src/modules/auth/auth.schema.ts`
- Test: `apps/api/tests/auth/auth.schema.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/auth/auth.schema.test.ts
import { describe, it, expect } from 'vitest';
import { RegisterBody, LoginBody } from '../../src/modules/auth/auth.schema.js';

describe('auth schemas', () => {
  it('accepts a valid register body', () => {
    const r = RegisterBody.safeParse({ email: 'a@b.com', password: 'longenough1' });
    expect(r.success).toBe(true);
  });

  it('rejects a short password on register', () => {
    const r = RegisterBody.safeParse({ email: 'a@b.com', password: 'short' });
    expect(r.success).toBe(false);
  });

  it('rejects a malformed email on register', () => {
    const r = RegisterBody.safeParse({ email: 'not-an-email', password: 'longenough1' });
    expect(r.success).toBe(false);
  });

  it('accepts a valid login body', () => {
    const r = LoginBody.safeParse({ email: 'a@b.com', password: 'whatever' });
    expect(r.success).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/auth/auth.schema.test.ts`
Expected: FAIL — `Cannot find module '../../src/modules/auth/auth.schema.js'`.

- [ ] **Step 3: Write minimal implementation**

Zod 4 top-level `z.email()` (NOT `z.string().email()`).

```ts
// apps/api/src/modules/auth/auth.schema.ts
import { z } from 'zod';

export const RegisterBody = z.object({
  email: z.email(),
  password: z.string().min(8).max(256),
});
export type RegisterBody = z.infer<typeof RegisterBody>;

export const LoginBody = z.object({
  email: z.email(),
  password: z.string().min(1).max(256),
});
export type LoginBody = z.infer<typeof LoginBody>;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/auth/auth.schema.test.ts`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/modules/auth/auth.schema.ts apps/api/tests/auth/auth.schema.test.ts
git commit -m "feat: add auth register/login zod schemas"
```

---

## Task 15: Auth service (createUser + verifyCredentials)

**Files:**

- Create: `apps/api/src/modules/auth/auth.service.ts`
- Test: `apps/api/tests/auth/auth.service.test.ts`

Per FOUNDATION + Plan 01 evolution: `createUser` sets `emailVerifiedAt = now()` (active immediately) and sends NO email. `verifyCredentials` does NOT check verification (Plan 02 adds that). Both use generic errors for anti-enumeration.

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/auth/auth.service.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { createUser, verifyCredentials } from '../../src/modules/auth/auth.service.js';
import { HttpError } from '../../src/middleware/errorHandler.js';
import { prisma } from '../../src/db/prisma.js';

beforeEach(async () => {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
  );
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('createUser', () => {
  it('creates an active (verified) user with a hashed password', async () => {
    const user = await createUser('new@user.com', 'longenough1');
    expect(user.email).toBe('new@user.com');
    expect(user.emailVerifiedAt).not.toBeNull();
    expect(user.passwordHash).not.toBe('longenough1');
    expect(user.role).toBe('USER');
  });

  it('throws a generic 409 when the email already exists', async () => {
    await createUser('dupe@user.com', 'longenough1');
    await expect(createUser('dupe@user.com', 'anotherlong1')).rejects.toMatchObject({
      status: 409,
    });
  });
});

describe('verifyCredentials', () => {
  it('returns the user for correct credentials', async () => {
    await createUser('login@user.com', 'longenough1');
    const user = await verifyCredentials('login@user.com', 'longenough1');
    expect(user.email).toBe('login@user.com');
  });

  it('throws a generic 401 for a wrong password', async () => {
    await createUser('login@user.com', 'longenough1');
    await expect(verifyCredentials('login@user.com', 'wrongpass1')).rejects.toBeInstanceOf(
      HttpError,
    );
    await expect(verifyCredentials('login@user.com', 'wrongpass1')).rejects.toMatchObject({
      status: 401,
    });
  });

  it('throws a generic 401 for an unknown email (same as wrong password)', async () => {
    await expect(verifyCredentials('ghost@user.com', 'whatever1')).rejects.toMatchObject({
      status: 401,
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/auth/auth.service.test.ts`
Expected: FAIL — `Cannot find module '../../src/modules/auth/auth.service.js'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// apps/api/src/modules/auth/auth.service.ts
import { prisma } from '../../db/prisma.js';
import { hashPassword, verifyPassword } from '../../lib/password.js';
import { HttpError } from '../../middleware/errorHandler.js';
import type { User } from '../../generated/prisma/client.js';

// Constant argon2id PHC hash of a random throwaway secret. On an unknown email we still run
// argon2.verify against THIS so the response timing matches the wrong-password path
// (anti-enumeration). Plan 05's SECURITY.md anti-enumeration timing claim relies on this.
const DECOY_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$c29tZS1jb25zdGFudC1zYWx0$3hgQ8Yc1Yp0r2yq1m9C0e0c4Yk2vJpQ6m7nQyq1m9C';

export async function createUser(email: string, password: string): Promise<User> {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    // Generic conflict; route layer returns the same shape regardless of cause.
    throw new HttpError(409, 'registration_failed');
  }
  const passwordHash = await hashPassword(password);
  return prisma.user.create({
    data: {
      email,
      passwordHash,
      emailVerifiedAt: new Date(), // Plan 01: active immediately
    },
  });
}

export async function verifyCredentials(email: string, password: string): Promise<User> {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    // Anti-enumeration: still run a verify against a constant decoy hash to equalize timing,
    // then throw the identical error whether or not the email exists.
    await verifyPassword(DECOY_HASH, password);
    throw new HttpError(401, 'invalid_credentials');
  }
  const ok = await verifyPassword(user.passwordHash, password);
  if (!ok) {
    throw new HttpError(401, 'invalid_credentials');
  }
  return user;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/auth/auth.service.test.ts`
Expected: PASS — all passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/modules/auth/auth.service.ts apps/api/tests/auth/auth.service.test.ts
git commit -m "feat: add auth service createUser and verifyCredentials"
```

---

## Task 16: Auth routes (register / login / logout / me)

**Files:**

- Create: `apps/api/src/modules/auth/auth.routes.ts`
- Test: deferred to the integration tests in Tasks 19–23 (routes are exercised through the full app).

This task wires the service into Express, with: session regeneration + indexing on login, audit events, anti-enumeration generic responses. It is verified end-to-end once `app.ts` (Task 18) and the integration tests exist.

- [ ] **Step 1: Write the router**

Login regenerates the session id (anti-fixation), stores `{ userId, role }`, indexes the session via `addUserSession`, audits `login_success`/`login_fail`. Logout destroys the session, de-indexes it, clears the cookie. `/me` returns the user or 401.

```ts
// apps/api/src/modules/auth/auth.routes.ts
import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { RegisterBody, LoginBody } from './auth.schema.js';
import { createUser, verifyCredentials } from './auth.service.js';
import { prisma } from '../../db/prisma.js';
import { writeAudit } from '../../lib/audit.js';
import { addUserSession, removeUserSession } from '../../lib/sessionStore.js';

export const authRouter = Router();

function badRequest(res: Response): void {
  res.status(400).json({ error: 'invalid_input' });
}

authRouter.post('/register', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = RegisterBody.safeParse(req.body);
    if (!parsed.success) return badRequest(res);
    const user = await createUser(parsed.data.email, parsed.data.password);
    await writeAudit({
      userId: user.id,
      event: 'register',
      ip: req.ip,
      userAgent: req.get('user-agent'),
    });
    res.status(201).json({ ok: true });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/login', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const parsed = LoginBody.safeParse(req.body);
    if (!parsed.success) return badRequest(res);

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
      if (regenErr) return next(regenErr);
      req.session.userId = user.id;
      req.session.role = user.role;
      req.session.save(async (saveErr) => {
        if (saveErr) return next(saveErr);
        try {
          await addUserSession(user.id, req.session.id);
          await writeAudit({
            userId: user.id,
            event: 'login_success',
            ip: req.ip,
            userAgent: req.get('user-agent'),
          });
          res.status(200).json({
            user: { id: user.id, email: user.email, role: user.role },
          });
        } catch (postErr) {
          next(postErr);
        }
      });
    });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/logout', (req: Request, res: Response, next: NextFunction) => {
  const userId = req.session.userId;
  const sid = req.session.id;
  req.session.destroy(async (destroyErr) => {
    if (destroyErr) return next(destroyErr);
    try {
      if (userId) await removeUserSession(userId, sid);
      res.clearCookie('__Host-sid', { path: '/' });
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  });
});

authRouter.get('/me', async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.session.userId) {
      res.status(401).json({ error: 'unauthenticated' });
      return;
    }
    const user = await prisma.user.findUnique({ where: { id: req.session.userId } });
    if (!user) {
      res.status(401).json({ error: 'unauthenticated' });
      return;
    }
    res.status(200).json({ user: { id: user.id, email: user.email, role: user.role } });
  } catch (err) {
    next(err);
  }
});

// Keep `z` referenced for future schema reuse without unused-import lint noise.
void z;
```

- [ ] **Step 2: Verify it compiles**

Run: `cd apps/api && npx tsc --noEmit`
Expected: PASS — no type errors.

> The `void z;` line avoids an unused-import error while keeping `z` available for the next plans. If your lint config is fine without it, remove both the import of `z` and that line.

- [ ] **Step 3: Commit**

```bash
git add apps/api/src/modules/auth/auth.routes.ts
git commit -m "feat: add auth routes register/login/logout/me with session + audit"
```

---

## Task 17: Auth router unused-import cleanup

**Files:**

- Modify: `apps/api/src/modules/auth/auth.routes.ts`

`z` is not actually used in the router; remove it to keep the code clean (DRY/YAGNI).

- [ ] **Step 1: Remove the unused import and its guard line**

Delete this import line:

```ts
import { z } from 'zod';
```

And delete this trailing line:

```ts
// Keep `z` referenced for future schema reuse without unused-import lint noise.
void z;
```

- [ ] **Step 2: Verify it still compiles**

Run: `cd apps/api && npx tsc --noEmit`
Expected: PASS — no type errors.

- [ ] **Step 3: Commit**

```bash
git add apps/api/src/modules/auth/auth.routes.ts
git commit -m "chore: remove unused zod import from auth routes"
```

---

## Task 18: Assemble the Express app + health + csrf endpoint

> **`apps/api/src/app.ts` is owned by Plan 00** (it creates `app` with `trust proxy`, `securityMiddleware`, `express.json()`, `cookie-parser`, and `GET /api/health`). This plan **MODIFIES** it to add session, the CSRF endpoint + protection, the global/auth limiters, the auth router, and the error handler. **`apps/api/src/server.ts` is owned by Plan 00 — do NOT create or modify it here.**

**Files:**

- Modify: `apps/api/src/app.ts` (created by Plan 00)
- Test: `apps/api/tests/app.test.ts`

Middleware order matters: security -> json -> cookie-parser -> session -> global limiter -> csrf endpoint (before csrf protection) -> csrf protection -> routes (auth limiter on `/api/auth`) -> errorHandler last. `GET /api/health` and `GET /api/csrf` per FOUNDATION.

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/app.test.ts
import { describe, it, expect, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/app.js';
import { redis } from '../src/redis/client.js';

afterAll(async () => {
  await redis.quit();
});

describe('app', () => {
  it('GET /api/health returns ok with no auth', async () => {
    const res = await request(app).get('/api/health').expect(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('GET /api/csrf returns a token', async () => {
    const res = await request(app)
      .get('/api/csrf')
      .set('X-Forwarded-Proto', 'https')
      .expect(200);
    expect(typeof res.body.csrfToken).toBe('string');
    expect(res.body.csrfToken.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/api && npx vitest run tests/app.test.ts`
Expected: FAIL — `Cannot find module '../src/app.js'`.

- [ ] **Step 3: Modify `app.ts` (Plan 00 created it with `app`, `trust proxy`, security/json/cookie-parser and `GET /api/health`)**

Add the session middleware, the CSRF endpoint + protection, the global/auth limiters, the auth router, and the error handler so the final assembled `apps/api/src/app.ts` reads as below. Do **not** create `server.ts` — Plan 00 owns it (`await connectRedis()` then `app.listen(env.PORT)`).

```ts
// apps/api/src/app.ts  (Plan 00 created; this plan MODIFIES it)
import express from 'express';
import cookieParser from 'cookie-parser';
import { securityMiddleware } from './middleware/security.js';
import { sessionMiddleware } from './middleware/session.js';
import { csrfProtection, issueCsrfToken } from './middleware/csrf.js';
import { globalLimiter, authLimiter } from './middleware/rateLimit.js';
import { errorHandler } from './middleware/errorHandler.js';
import { authRouter } from './modules/auth/auth.routes.js';

export const app = express();

// Behind Caddy (TLS terminator) so Secure cookies + correct req.ip work.
app.set('trust proxy', 1);

app.use(securityMiddleware);
app.use(express.json());
app.use(cookieParser());
app.use(sessionMiddleware);
app.use(globalLimiter);

// Public, no auth, no csrf.
app.get('/api/health', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Issue/return the CSRF token BEFORE csrf protection so the SPA can bootstrap.
app.get('/api/csrf', (req, res) => {
  res.status(200).json({ csrfToken: issueCsrfToken(req, res) });
});

// All mutating routes below are CSRF-protected.
app.use(csrfProtection);

// Tighter rate limit on auth endpoints.
app.use('/api/auth', authLimiter, authRouter);

// Central error handler LAST.
app.use(errorHandler);
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/app.test.ts`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/api/src/app.ts apps/api/tests/app.test.ts
git commit -m "feat: assemble express app with session, csrf, limiters, auth router and error handler"
```

---

## Task 19: Test helpers (DB reset + supertest CSRF agent)

**Files:**

- Create: `apps/api/tests/helpers/db.ts`
- Create: `apps/api/tests/helpers/agent.ts`

Shared helpers the integration tests reuse. `resetState` truncates Postgres + flushes Redis. `makeCsrfAgent` primes a CSRF token so mutating requests pass csrf; `signedInAgent` registers+logs in and returns an authed agent with a FRESH csrf token; `signInExistingUser` logs an existing agent in and returns a FRESH csrf token (the session regenerates on login, so the pre-login token is invalidated and must be re-fetched).

- [ ] **Step 1: Write the DB helper**

```ts
// apps/api/tests/helpers/db.ts
import { prisma } from '../../src/db/prisma.js';
import { redis } from '../../src/redis/client.js';

export async function resetState(): Promise<void> {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
  );
  await redis.flushDb();
}
```

- [ ] **Step 2: Write the agent helper**

```ts
// apps/api/tests/helpers/agent.ts
import request from 'supertest';
import type { Express } from 'express';

const HTTPS = { 'X-Forwarded-Proto': 'https' } as const;

export type Agent = ReturnType<typeof request.agent>;

export interface CsrfAgent {
  agent: Agent;
  csrfToken: string;
}

export interface Creds {
  email: string;
  password: string;
}

// Returns a cookie-jar agent plus a CSRF token bound to that agent's session.
export async function makeCsrfAgent(app: Express): Promise<CsrfAgent> {
  const agent = request.agent(app);
  const res = await agent.get('/api/csrf').set(HTTPS).expect(200);
  return { agent, csrfToken: res.body.csrfToken as string };
}

// Logs an EXISTING user in on the given agent, then re-fetches CSRF — login regenerates the
// session id, which invalidates the pre-login token, so a fresh one must be bound to the new
// session before any further mutating request.
export async function signInExistingUser(
  app: Express,
  agent: Agent,
  creds: Creds,
): Promise<{ csrfToken: string }> {
  const csrfRes = await agent.get('/api/csrf').set(HTTPS).expect(200);
  await agent
    .post('/api/auth/login')
    .set(HTTPS)
    .set('x-csrf-token', csrfRes.body.csrfToken as string)
    .send(creds)
    .expect(200);
  // Re-fetch CSRF after the session regeneration.
  const fresh = await agent.get('/api/csrf').set(HTTPS).expect(200);
  return { csrfToken: fresh.body.csrfToken as string };
}

// Registers (active-immediately) + logs in, returning the authed agent, the user, and a FRESH
// CSRF token bound to the post-login (regenerated) session.
export async function signedInAgent(
  app: Express,
  creds: Creds,
): Promise<{ agent: Agent; user: { id: string; email: string; role: string }; csrfToken: string }> {
  const { agent, csrfToken } = await makeCsrfAgent(app);
  await agent
    .post('/api/auth/register')
    .set(HTTPS)
    .set('x-csrf-token', csrfToken)
    .send(creds)
    .expect(201);

  const loginCsrf = await agent.get('/api/csrf').set(HTTPS).expect(200);
  const loginRes = await agent
    .post('/api/auth/login')
    .set(HTTPS)
    .set('x-csrf-token', loginCsrf.body.csrfToken as string)
    .send(creds)
    .expect(200);

  // Re-fetch CSRF after login regenerates the session.
  const fresh = await agent.get('/api/csrf').set(HTTPS).expect(200);
  return {
    agent,
    user: loginRes.body.user,
    csrfToken: fresh.body.csrfToken as string,
  };
}

export { HTTPS };
```

- [ ] **Step 3: Verify it compiles**

Run: `cd apps/api && npx tsc --noEmit`
Expected: PASS — no type errors.

- [ ] **Step 4: Commit**

```bash
git add apps/api/tests/helpers/db.ts apps/api/tests/helpers/agent.ts
git commit -m "test: add db reset and csrf/signed-in supertest agent helpers"
```

---

## Task 20: Register integration tests

**Files:**

- Create: `apps/api/tests/auth/register.test.ts`

- [ ] **Step 1: Write the failing test**

```ts
// apps/api/tests/auth/register.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db/prisma.js';
import { redis } from '../../src/redis/client.js';
import { resetState } from '../helpers/db.js';
import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe('POST /api/auth/register', () => {
  it('creates an active user and returns 201 {ok:true}', async () => {
    const { agent, csrfToken } = await makeCsrfAgent(app);
    const res = await agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'reg@user.com', password: 'longenough1' })
      .expect(201);
    expect(res.body).toEqual({ ok: true });

    const user = await prisma.user.findUnique({ where: { email: 'reg@user.com' } });
    expect(user).not.toBeNull();
    expect(user!.emailVerifiedAt).not.toBeNull();

    const audit = await prisma.auditLog.findFirst({ where: { event: 'register' } });
    expect(audit).not.toBeNull();
  });

  it('rejects an invalid email with 400', async () => {
    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'nope', password: 'longenough1' })
      .expect(400);
  });

  it('rejects a duplicate email with 409 generic error', async () => {
    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'dupe@user.com', password: 'longenough1' })
      .expect(201);

    const second = await makeCsrfAgent(app);
    const res = await second.agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', second.csrfToken)
      .send({ email: 'dupe@user.com', password: 'anotherlong1' })
      .expect(409);
    expect(res.body).toEqual({ error: 'registration_failed' });
  });

  it('rejects a POST with no csrf token (403)', async () => {
    await import('supertest').then(({ default: request }) =>
      request(app)
        .post('/api/auth/register')
        .set(HTTPS)
        .send({ email: 'x@y.com', password: 'longenough1' })
        .expect(403),
    );
  });
});
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/auth/register.test.ts`
Expected: PASS — 4 passed (the route + app already exist from Tasks 16–18).

- [ ] **Step 3: Commit**

```bash
git add apps/api/tests/auth/register.test.ts
git commit -m "test: add register endpoint integration tests"
```

---

## Task 21: Login integration tests

**Files:**

- Create: `apps/api/tests/auth/login.test.ts`

- [ ] **Step 1: Write the test**

```ts
// apps/api/tests/auth/login.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { app } from '../../src/app.js';
import { prisma } from '../../src/db/prisma.js';
import { redis } from '../../src/redis/client.js';
import { resetState } from '../helpers/db.js';
import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

async function registerUser(email: string, password: string) {
  const { agent, csrfToken } = await makeCsrfAgent(app);
  await agent
    .post('/api/auth/register')
    .set(HTTPS)
    .set('x-csrf-token', csrfToken)
    .send({ email, password })
    .expect(201);
}

describe('POST /api/auth/login', () => {
  it('logs in with correct credentials, sets cookie, indexes session, audits success', async () => {
    await registerUser('login@user.com', 'longenough1');
    const { agent, csrfToken } = await makeCsrfAgent(app);

    const res = await agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'login@user.com', password: 'longenough1' })
      .expect(200);

    expect(res.body.user.email).toBe('login@user.com');
    expect(res.body.user.role).toBe('USER');
    expect(typeof res.body.user.id).toBe('string');

    const setCookie = res.headers['set-cookie'] as unknown as string[];
    expect(setCookie.some((c) => c.startsWith('__Host-sid='))).toBe(true);

    // Session indexed under the per-user set.
    const members = await redis.sMembers(`user_sessions:${res.body.user.id}`);
    expect(members.length).toBe(1);

    const audit = await prisma.auditLog.findFirst({ where: { event: 'login_success' } });
    expect(audit).not.toBeNull();
  });

  it('returns 401 generic error + audits login_fail for a wrong password', async () => {
    await registerUser('login@user.com', 'longenough1');
    const { agent, csrfToken } = await makeCsrfAgent(app);

    const res = await agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'login@user.com', password: 'wrongpass1' })
      .expect(401);

    expect(res.body).toEqual({ error: 'invalid_credentials' });

    const audit = await prisma.auditLog.findFirst({ where: { event: 'login_fail' } });
    expect(audit).not.toBeNull();
  });

  it('regenerates the session id on login (anti-fixation)', async () => {
    await registerUser('fix@user.com', 'longenough1');
    const { agent, csrfToken } = await makeCsrfAgent(app);

    // Establish a pre-auth session id by hitting /api/csrf (already done by makeCsrfAgent).
    const before = await agent.get('/api/auth/me').set(HTTPS).expect(401);
    expect(before.body).toEqual({ error: 'unauthenticated' });

    await agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'fix@user.com', password: 'longenough1' })
      .expect(200);

    // After login the same agent is authenticated.
    const after = await agent.get('/api/auth/me').set(HTTPS).expect(200);
    expect(after.body.user.email).toBe('fix@user.com');
  });
});
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/auth/login.test.ts`
Expected: PASS — 3 passed.

- [ ] **Step 3: Commit**

```bash
git add apps/api/tests/auth/login.test.ts
git commit -m "test: add login endpoint integration tests"
```

---

## Task 22: Logout + /me integration tests

**Files:**

- Create: `apps/api/tests/auth/logout.test.ts`
- Create: `apps/api/tests/auth/me.test.ts`

- [ ] **Step 1: Write the logout test**

```ts
// apps/api/tests/auth/logout.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { app } from '../../src/app.js';
import { redis } from '../../src/redis/client.js';
import { resetState } from '../helpers/db.js';
import { signedInAgent, HTTPS } from '../helpers/agent.js';

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe('POST /api/auth/logout', () => {
  it('destroys the session, de-indexes it, returns 204', async () => {
    // signedInAgent registers + logs in and returns a FRESH csrf token bound to the
    // post-login (regenerated) session.
    const { agent, csrfToken, user } = await signedInAgent(app, {
      email: 'out@user.com',
      password: 'longenough1',
    });

    await agent
      .post('/api/auth/logout')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .expect(204);

    // /me is now unauthenticated for this agent.
    await agent.get('/api/auth/me').set(HTTPS).expect(401);

    // Per-user session set is empty.
    const members = await redis.sMembers(`user_sessions:${user.id}`);
    expect(members.length).toBe(0);
  });
});
```

- [ ] **Step 2: Write the /me test**

```ts
// apps/api/tests/auth/me.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import request from 'supertest';
import { app } from '../../src/app.js';
import { redis } from '../../src/redis/client.js';
import { resetState } from '../helpers/db.js';
import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe('GET /api/auth/me', () => {
  it('returns 401 when unauthenticated', async () => {
    const res = await request(app).get('/api/auth/me').set(HTTPS).expect(401);
    expect(res.body).toEqual({ error: 'unauthenticated' });
  });

  it('returns the user when authenticated', async () => {
    const reg = await makeCsrfAgent(app);
    await reg.agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', reg.csrfToken)
      .send({ email: 'me@user.com', password: 'longenough1' })
      .expect(201);

    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', csrfToken)
      .send({ email: 'me@user.com', password: 'longenough1' })
      .expect(200);

    const res = await agent.get('/api/auth/me').set(HTTPS).expect(200);
    expect(res.body.user.email).toBe('me@user.com');
    expect(res.body.user.role).toBe('USER');
  });
});
```

> Note: `/me` is exposed only at `GET /api/auth/me` (the auth router mounted at `/api/auth`). Per CONTRACTS there is **no** `/api/me` alias — the SPA's `useMe` calls `/api/auth/me` directly, so no extra mount is added in `app.ts`.

- [ ] **Step 3: Run both tests to verify they pass**

Run: `cd apps/api && npx vitest run tests/auth/logout.test.ts tests/auth/me.test.ts`
Expected: PASS — all passed.

- [ ] **Step 4: Commit**

```bash
git add apps/api/tests/auth/logout.test.ts apps/api/tests/auth/me.test.ts
git commit -m "test: add logout and me integration tests"
```

---

## Task 23: Enumeration-parity test

**Files:**

- Create: `apps/api/tests/auth/enumeration.test.ts`

Proves login responses are byte-identical whether the email exists (wrong password) or not — no enumeration leak.

- [ ] **Step 1: Write the test**

```ts
// apps/api/tests/auth/enumeration.test.ts
import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { app } from '../../src/app.js';
import { redis } from '../../src/redis/client.js';
import { resetState } from '../helpers/db.js';
import { makeCsrfAgent, HTTPS } from '../helpers/agent.js';

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe('login enumeration parity', () => {
  it('returns identical status and body for unknown email vs wrong password', async () => {
    // Register a known user.
    const reg = await makeCsrfAgent(app);
    await reg.agent
      .post('/api/auth/register')
      .set(HTTPS)
      .set('x-csrf-token', reg.csrfToken)
      .send({ email: 'known@user.com', password: 'longenough1' })
      .expect(201);

    const a = await makeCsrfAgent(app);
    const wrongPassword = await a.agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', a.csrfToken)
      .send({ email: 'known@user.com', password: 'totallywrong1' });

    const b = await makeCsrfAgent(app);
    const unknownEmail = await b.agent
      .post('/api/auth/login')
      .set(HTTPS)
      .set('x-csrf-token', b.csrfToken)
      .send({ email: 'ghost@user.com', password: 'totallywrong1' });

    expect(wrongPassword.status).toBe(unknownEmail.status);
    expect(wrongPassword.status).toBe(401);
    expect(wrongPassword.body).toEqual(unknownEmail.body);
    expect(wrongPassword.body).toEqual({ error: 'invalid_credentials' });
  });
});
```

- [ ] **Step 2: Run test to verify it passes**

Run: `cd apps/api && npx vitest run tests/auth/enumeration.test.ts`
Expected: PASS — 1 passed.

- [ ] **Step 3: Run the full API suite**

Run: `cd apps/api && npx vitest run`
Expected: PASS — every API test green.

- [ ] **Step 4: Commit**

```bash
git add apps/api/tests/auth/enumeration.test.ts
git commit -m "test: add login enumeration-parity test"
```

---

## Task 24: Web — apiClient (credentials + CSRF header)

**Files:**

- Create: `apps/web/src/lib/apiClient.ts`
- Test: `apps/web/tests/apiClient.test.ts`

Per CONTRACTS, the export is an `apiClient` **object** with `get<T>(path)` / `post<T>(path, body?)`, plus the `ApiError { status, body }` class. Callers pass the **full path including `/api`** (e.g. `apiClient.get('/api/auth/me')`, `apiClient.post('/api/auth/login', body)`). The client always sends `credentials:'include'`, **bootstraps the CSRF token internally** (lazily `GET /api/csrf` once, caches it, attaches it as the `x-csrf-token` header on mutating requests), and on a `403` CSRF failure re-fetches the token once and retries the mutation. Hooks never call a `fetchCsrf` themselves.

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/apiClient.test.ts
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { apiClient, ApiError } from '../src/lib/apiClient';

const realFetch = globalThis.fetch;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

beforeEach(() => {
  // Reset the module-level CSRF cache between tests.
  apiClient.__resetCsrfForTests?.();
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe('apiClient', () => {
  it('GET sends credentials include and returns parsed json', async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ user: { id: '1' } }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const data = await apiClient.get<{ user: { id: string } }>('/api/auth/me');
    expect(data).toEqual({ user: { id: '1' } });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/auth/me');
    expect(init?.credentials).toBe('include');
  });

  it('POST bootstraps csrf internally (GET /api/csrf) and attaches the x-csrf-token header', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/csrf') return jsonResponse({ csrfToken: 'tok123' });
      return jsonResponse({ ok: true });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await apiClient.post('/api/auth/login', { email: 'a@b.com', password: 'x' });

    // First call bootstraps the token, second is the mutation carrying it.
    expect(fetchMock.mock.calls[0][0]).toBe('/api/csrf');
    const [url, init] = fetchMock.mock.calls[1];
    expect(url).toBe('/api/auth/login');
    const headers = new Headers(init?.headers);
    expect(headers.get('x-csrf-token')).toBe('tok123');
    expect(init?.credentials).toBe('include');
    expect(init?.method).toBe('POST');
  });

  it('on a 403 csrf failure re-fetches the token once and retries the mutation', async () => {
    let mutateCalls = 0;
    let token = 'stale';
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/csrf') {
        const body = { csrfToken: token };
        token = 'fresh';
        return jsonResponse(body);
      }
      mutateCalls += 1;
      // First mutation attempt fails CSRF; the retry (with the fresh token) succeeds.
      if (mutateCalls === 1) return jsonResponse({ error: 'invalid_csrf_token' }, 403);
      return jsonResponse({ ok: true });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const res = await apiClient.post<{ ok: boolean }>('/api/auth/login', {});
    expect(res).toEqual({ ok: true });
    expect(mutateCalls).toBe(2);
  });

  it('throws an ApiError carrying the status on non-2xx', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url === '/api/csrf') return jsonResponse({ csrfToken: 'tok123' });
      return jsonResponse({ error: 'invalid_credentials' }, 401);
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    await expect(apiClient.post('/api/auth/login', {})).rejects.toBeInstanceOf(ApiError);
    await expect(apiClient.post('/api/auth/login', {})).rejects.toMatchObject({ status: 401 });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/web && npx vitest run tests/apiClient.test.ts`
Expected: FAIL — `Cannot find module '../src/lib/apiClient'`.

- [ ] **Step 3: Write minimal implementation**

```ts
// apps/web/src/lib/apiClient.ts
export class ApiError extends Error {
  constructor(
    public status: number,
    public body: unknown,
  ) {
    super(`API error ${status}`);
    this.name = 'ApiError';
  }
}

// Cached CSRF token, bootstrapped lazily via GET /api/csrf.
let csrfToken: string | null = null;

async function parse(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  const parsed = await parse(res);
  if (!res.ok) throw new ApiError(res.status, parsed);
  return parsed as T;
}

async function ensureCsrf(): Promise<string> {
  if (csrfToken) return csrfToken;
  const data = await request<{ csrfToken: string }>('GET', '/api/csrf');
  csrfToken = data.csrfToken;
  return csrfToken;
}

async function mutate<T>(method: string, path: string, body?: unknown): Promise<T> {
  const send = async (): Promise<Response> => {
    const token = await ensureCsrf();
    return fetch(path, {
      method,
      credentials: 'include',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'x-csrf-token': token,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  };

  let res = await send();
  // On a CSRF failure, drop the cached token, re-bootstrap once, and retry.
  if (res.status === 403) {
    csrfToken = null;
    res = await send();
  }
  const parsed = await parse(res);
  if (!res.ok) throw new ApiError(res.status, parsed);
  return parsed as T;
}

export const apiClient = {
  get<T>(path: string): Promise<T> {
    return request<T>('GET', path);
  },
  post<T>(path: string, body?: unknown): Promise<T> {
    return mutate<T>('POST', path, body);
  },
  // Test-only hook to clear the cached CSRF token between cases.
  __resetCsrfForTests(): void {
    csrfToken = null;
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/web && npx vitest run tests/apiClient.test.ts`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/lib/apiClient.ts apps/web/tests/apiClient.test.ts
git commit -m "feat: add web apiClient object with credentials and internal csrf bootstrap"
```

---

## Task 25: Web — queryClient

**Files:**

- Create: `apps/web/src/lib/queryClient.ts`

- [ ] **Step 1: Write the query client**

`retry:false` so a 401 `/me` is treated as "no user", not a retriable error.

```ts
// apps/web/src/lib/queryClient.ts
import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      staleTime: 60_000,
      refetchOnWindowFocus: false,
    },
  },
});
```

- [ ] **Step 2: Verify it compiles**

Run: `cd apps/web && npx tsc --noEmit`
Expected: PASS — no type errors.

- [ ] **Step 3: Commit**

```bash
git add apps/web/src/lib/queryClient.ts
git commit -m "feat: add tanstack query client with 401-safe defaults"
```

---

## Task 26: Web — auth hooks (useMe / useLogin / useRegister / useLogout)

**Files:**

- Create: `apps/web/src/features/auth/useMe.ts`
- Create: `apps/web/src/features/auth/useLogin.ts`
- Create: `apps/web/src/features/auth/useRegister.ts`
- Create: `apps/web/src/features/auth/useLogout.ts`
- Test: `apps/web/tests/useMe.test.tsx`

- [ ] **Step 1: Write the failing test for useMe**

```tsx
// apps/web/tests/useMe.test.tsx
import { describe, it, expect, beforeEach, afterEach, afterAll, beforeAll } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';
import type { ReactNode } from 'react';
import { useMe } from '../src/features/auth/useMe';

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe('useMe', () => {
  it('returns the user when /api/auth/me is 200', async () => {
    server.use(
      http.get('/api/auth/me', () =>
        HttpResponse.json({ user: { id: '1', email: 'a@b.com', role: 'USER' } }),
      ),
    );
    const { result } = renderHook(() => useMe(), { wrapper });
    await waitFor(() => expect(result.current.isPending).toBe(false));
    expect(result.current.data).toEqual({ id: '1', email: 'a@b.com', role: 'USER' });
  });

  it('returns null (not an error) when /api/auth/me is 401', async () => {
    server.use(
      http.get('/api/auth/me', () =>
        HttpResponse.json({ error: 'unauthenticated' }, { status: 401 }),
      ),
    );
    const { result } = renderHook(() => useMe(), { wrapper });
    await waitFor(() => expect(result.current.isPending).toBe(false));
    expect(result.current.data).toBeNull();
    expect(result.current.isError).toBe(false);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/web && npx vitest run tests/useMe.test.tsx`
Expected: FAIL — `Cannot find module '../src/features/auth/useMe'`.

- [ ] **Step 3: Write the four hooks**

```ts
// apps/web/src/features/auth/useMe.ts
import { useQuery } from '@tanstack/react-query';
import { apiClient, ApiError } from '../../lib/apiClient';

export interface AuthUser {
  id: string;
  email: string;
  role: 'USER' | 'ADMIN';
}

export function useMe() {
  return useQuery<AuthUser | null>({
    queryKey: ['me'],
    queryFn: async () => {
      try {
        const data = await apiClient.get<{ user: AuthUser }>('/api/auth/me');
        return data.user;
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return null;
        throw err;
      }
    },
  });
}
```

```ts
// apps/web/src/features/auth/useLogin.ts
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';
import type { AuthUser } from './useMe';

export interface LoginInput {
  email: string;
  password: string;
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation<AuthUser, Error, LoginInput>({
    mutationFn: async (creds) => {
      // apiClient bootstraps + attaches CSRF internally; no fetchCsrf call needed.
      const data = await apiClient.post<{ user: AuthUser }>('/api/auth/login', creds);
      return data.user;
    },
    onSuccess: (user) => {
      qc.setQueryData(['me'], user);
      void qc.invalidateQueries({ queryKey: ['me'] });
    },
  });
}
```

```ts
// apps/web/src/features/auth/useRegister.ts
import { useMutation } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';

export interface RegisterInput {
  email: string;
  password: string;
}

export function useRegister() {
  return useMutation<{ ok: true }, Error, RegisterInput>({
    mutationFn: (input) => apiClient.post<{ ok: true }>('/api/auth/register', input),
  });
}
```

```ts
// apps/web/src/features/auth/useLogout.ts
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../../lib/apiClient';

export function useLogout() {
  const qc = useQueryClient();
  return useMutation<void, Error, void>({
    mutationFn: async () => {
      await apiClient.post<null>('/api/auth/logout');
    },
    onSuccess: () => {
      qc.removeQueries({ queryKey: ['me'] });
    },
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/web && npx vitest run tests/useMe.test.tsx`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/features/auth/useMe.ts apps/web/src/features/auth/useLogin.ts apps/web/src/features/auth/useRegister.ts apps/web/src/features/auth/useLogout.ts apps/web/tests/useMe.test.tsx
git commit -m "feat: add web auth hooks useMe/useLogin/useRegister/useLogout"
```

---

## Task 27: Web — LoginPage (RHF + zod)

**Files:**

- Create: `apps/web/src/features/auth/LoginPage.tsx`
- Test: `apps/web/tests/LoginPage.test.tsx`

- [ ] **Step 1: Write the MSW setup + handlers (shared by web tests)**

```ts
// apps/web/tests/mocks/handlers.ts
import { http, HttpResponse } from 'msw';

export const handlers = [
  http.get('/api/csrf', () => HttpResponse.json({ csrfToken: 'tok123' })),
];
```

```ts
// apps/web/tests/mocks/server.ts
import { setupServer } from 'msw/node';
import { handlers } from './handlers';

export const server = setupServer(...handlers);
```

```ts
// apps/web/tests/setup.ts
import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll } from 'vitest';
import { server } from './mocks/server';

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());
```

> Ensure `apps/web/vitest.config.ts` (created by Plan 00) has `test.environment: 'jsdom'` and `test.setupFiles: ['./tests/setup.ts']`. If not present, add those two keys now.

- [ ] **Step 2: Write the failing LoginPage test**

```tsx
// apps/web/tests/LoginPage.test.tsx
import { describe, it, expect } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { server } from './mocks/server';
import { LoginPage } from '../src/features/auth/LoginPage';

function renderLogin() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/login']}>
        <LoginPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('LoginPage', () => {
  it('shows a validation error for an invalid email and does not submit', async () => {
    renderLogin();
    await userEvent.type(screen.getByLabelText(/email/i), 'not-an-email');
    await userEvent.type(screen.getByLabelText(/password/i), 'longenough1');
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));
    expect(await screen.findByText(/invalid email/i)).toBeInTheDocument();
  });

  it('shows an error message when login returns 401', async () => {
    server.use(
      http.post('/api/auth/login', () =>
        HttpResponse.json({ error: 'invalid_credentials' }, { status: 401 }),
      ),
    );
    renderLogin();
    await userEvent.type(screen.getByLabelText(/email/i), 'a@b.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'longenough1');
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));
    expect(await screen.findByText(/invalid credentials/i)).toBeInTheDocument();
  });

  it('calls /api/auth/login on a valid submit', async () => {
    let received: unknown = null;
    server.use(
      http.post('/api/auth/login', async ({ request }) => {
        received = await request.json();
        return HttpResponse.json({ user: { id: '1', email: 'a@b.com', role: 'USER' } });
      }),
    );
    renderLogin();
    await userEvent.type(screen.getByLabelText(/email/i), 'a@b.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'longenough1');
    await userEvent.click(screen.getByRole('button', { name: /log in/i }));
    await waitFor(() => expect(received).toEqual({ email: 'a@b.com', password: 'longenough1' }));
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd apps/web && npx vitest run tests/LoginPage.test.tsx`
Expected: FAIL — `Cannot find module '../src/features/auth/LoginPage'`.

- [ ] **Step 4: Write LoginPage**

```tsx
// apps/web/src/features/auth/LoginPage.tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useNavigate, useLocation } from 'react-router';
import { useLogin } from './useLogin';

const schema = z.object({
  email: z.email('Invalid email'),
  password: z.string().min(8, 'Min 8 chars'),
});
type FormValues = z.infer<typeof schema>;

export function LoginPage() {
  const login = useLogin();
  const navigate = useNavigate();
  const location = useLocation() as { state?: { from?: { pathname?: string } } };
  const from = location.state?.from?.pathname ?? '/';

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });

  const onSubmit = handleSubmit(async (values) => {
    try {
      await login.mutateAsync(values);
      navigate(from, { replace: true });
    } catch {
      setError('root', { message: 'Invalid credentials' });
    }
  });

  return (
    <form onSubmit={onSubmit} aria-label="login form">
      <h1>Log in</h1>

      <label htmlFor="email">Email</label>
      <input id="email" type="email" autoComplete="username" {...register('email')} />
      {errors.email && <span role="alert">{errors.email.message}</span>}

      <label htmlFor="password">Password</label>
      <input
        id="password"
        type="password"
        autoComplete="current-password"
        {...register('password')}
      />
      {errors.password && <span role="alert">{errors.password.message}</span>}

      {errors.root && <span role="alert">{errors.root.message}</span>}

      <button type="submit" disabled={isSubmitting}>
        Log in
      </button>
    </form>
  );
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd apps/web && npx vitest run tests/LoginPage.test.tsx`
Expected: PASS — 3 passed.

- [ ] **Step 6: Commit**

```bash
git add apps/web/tests/mocks/handlers.ts apps/web/tests/mocks/server.ts apps/web/tests/setup.ts apps/web/src/features/auth/LoginPage.tsx apps/web/tests/LoginPage.test.tsx
git commit -m "feat: add LoginPage with react-hook-form + zod and MSW tests"
```

---

## Task 28: Web — RegisterPage (RHF + zod)

**Files:**

- Create: `apps/web/src/features/auth/RegisterPage.tsx`
- Test: `apps/web/tests/RegisterPage.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
// apps/web/tests/RegisterPage.test.tsx
import { describe, it, expect, waitFor } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router';
import { server } from './mocks/server';
import { RegisterPage } from '../src/features/auth/RegisterPage';

function renderRegister() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/register']}>
        <RegisterPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('RegisterPage', () => {
  it('submits a valid registration to /api/auth/register', async () => {
    let received: unknown = null;
    server.use(
      http.post('/api/auth/register', async ({ request }) => {
        received = await request.json();
        return HttpResponse.json({ ok: true }, { status: 201 });
      }),
    );
    renderRegister();
    await userEvent.type(screen.getByLabelText(/email/i), 'new@user.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'longenough1');
    await userEvent.click(screen.getByRole('button', { name: /create account/i }));
    await waitFor(() =>
      expect(received).toEqual({ email: 'new@user.com', password: 'longenough1' }),
    );
    expect(await screen.findByText(/account created/i)).toBeInTheDocument();
  });

  it('shows a generic error when register returns 409', async () => {
    server.use(
      http.post('/api/auth/register', () =>
        HttpResponse.json({ error: 'registration_failed' }, { status: 409 }),
      ),
    );
    renderRegister();
    await userEvent.type(screen.getByLabelText(/email/i), 'dupe@user.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'longenough1');
    await userEvent.click(screen.getByRole('button', { name: /create account/i }));
    expect(await screen.findByText(/could not create account/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/web && npx vitest run tests/RegisterPage.test.tsx`
Expected: FAIL — `Cannot find module '../src/features/auth/RegisterPage'`.

- [ ] **Step 3: Write RegisterPage**

```tsx
// apps/web/src/features/auth/RegisterPage.tsx
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useRegister } from './useRegister';

const schema = z.object({
  email: z.email('Invalid email'),
  password: z.string().min(8, 'Min 8 chars'),
});
type FormValues = z.infer<typeof schema>;

export function RegisterPage() {
  const registerMutation = useRegister();
  const [done, setDone] = useState(false);

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema) });

  const onSubmit = handleSubmit(async (values) => {
    try {
      await registerMutation.mutateAsync(values);
      setDone(true);
    } catch {
      setError('root', { message: 'Could not create account' });
    }
  });

  if (done) return <p>Account created. You can now log in.</p>;

  return (
    <form onSubmit={onSubmit} aria-label="register form">
      <h1>Create account</h1>

      <label htmlFor="email">Email</label>
      <input id="email" type="email" autoComplete="username" {...register('email')} />
      {errors.email && <span role="alert">{errors.email.message}</span>}

      <label htmlFor="password">Password</label>
      <input
        id="password"
        type="password"
        autoComplete="new-password"
        {...register('password')}
      />
      {errors.password && <span role="alert">{errors.password.message}</span>}

      {errors.root && <span role="alert">{errors.root.message}</span>}

      <button type="submit" disabled={isSubmitting}>
        Create account
      </button>
    </form>
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/web && npx vitest run tests/RegisterPage.test.tsx`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/features/auth/RegisterPage.tsx apps/web/tests/RegisterPage.test.tsx
git commit -m "feat: add RegisterPage with react-hook-form + zod"
```

---

## Task 29: Web — Dashboard

**Files:**

- Create: `apps/web/src/features/dashboard/Dashboard.tsx`

Shows the signed-in user (from `useMe`) and a logout button. No new test here; it's exercised by the ProtectedRoute test in Task 30.

- [ ] **Step 1: Write the Dashboard**

```tsx
// apps/web/src/features/dashboard/Dashboard.tsx
import { useMe } from '../auth/useMe';
import { useLogout } from '../auth/useLogout';

export function Dashboard() {
  const { data: user } = useMe();
  const logout = useLogout();

  return (
    <main>
      <h1>Dashboard</h1>
      {user ? (
        <p>
          Signed in as <strong>{user.email}</strong> ({user.role})
        </p>
      ) : null}
      <button type="button" onClick={() => logout.mutate()} disabled={logout.isPending}>
        Log out
      </button>
    </main>
  );
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd apps/web && npx tsc --noEmit`
Expected: PASS — no type errors.

- [ ] **Step 3: Commit**

```bash
git add apps/web/src/features/dashboard/Dashboard.tsx
git commit -m "feat: add Dashboard showing the signed-in user"
```

---

## Task 30: Web — ProtectedRoute

**Files:**

- Create: `apps/web/src/routes/ProtectedRoute.tsx`
- Test: `apps/web/tests/ProtectedRoute.test.tsx`

Renders a spinner while `useMe` is pending, redirects to `/login` (preserving intended destination) when unauthenticated, and renders the nested route via `<Outlet/>` when authenticated.

- [ ] **Step 1: Write the failing test**

```tsx
// apps/web/tests/ProtectedRoute.test.tsx
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Routes, Route } from 'react-router';
import { server } from './mocks/server';
import { ProtectedRoute } from '../src/routes/ProtectedRoute';

function renderAt(initial: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route path="/login" element={<div>Login Screen</div>} />
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<div>Secret Dashboard</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('ProtectedRoute', () => {
  it('redirects to /login when unauthenticated (401)', async () => {
    server.use(
      http.get('/api/auth/me', () =>
        HttpResponse.json({ error: 'unauthenticated' }, { status: 401 }),
      ),
    );
    renderAt('/');
    expect(await screen.findByText('Login Screen')).toBeInTheDocument();
    expect(screen.queryByText('Secret Dashboard')).not.toBeInTheDocument();
  });

  it('renders the protected content when authenticated', async () => {
    server.use(
      http.get('/api/auth/me', () =>
        HttpResponse.json({ user: { id: '1', email: 'a@b.com', role: 'USER' } }),
      ),
    );
    renderAt('/');
    expect(await screen.findByText('Secret Dashboard')).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd apps/web && npx vitest run tests/ProtectedRoute.test.tsx`
Expected: FAIL — `Cannot find module '../src/routes/ProtectedRoute'`.

- [ ] **Step 3: Write ProtectedRoute**

```tsx
// apps/web/src/routes/ProtectedRoute.tsx
import { Navigate, Outlet, useLocation } from 'react-router';
import { useMe } from '../features/auth/useMe';

export function ProtectedRoute() {
  const { data: user, isPending } = useMe();
  const location = useLocation();

  if (isPending) return <p role="status">Loading…</p>;
  if (!user) return <Navigate to="/login" state={{ from: location }} replace />;
  return <Outlet />;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd apps/web && npx vitest run tests/ProtectedRoute.test.tsx`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/routes/ProtectedRoute.tsx apps/web/tests/ProtectedRoute.test.tsx
git commit -m "feat: add ProtectedRoute guard wired to useMe"
```

---

## Task 31: Web — router + App + main wiring

**Files:**

- Create: `apps/web/src/routes/router.tsx`
- Modify: `apps/web/src/App.tsx`
- Modify: `apps/web/src/main.tsx`

Wire public routes (`/login`, `/register`) and protected routes (`/` dashboard) using React Router v7 (`createBrowserRouter`) and provide the QueryClient at the root.

- [ ] **Step 1: Write the router**

```tsx
// apps/web/src/routes/router.tsx
import { createBrowserRouter, Navigate } from 'react-router';
import { LoginPage } from '../features/auth/LoginPage';
import { RegisterPage } from '../features/auth/RegisterPage';
import { Dashboard } from '../features/dashboard/Dashboard';
import { ProtectedRoute } from './ProtectedRoute';

export const router = createBrowserRouter([
  { path: '/login', element: <LoginPage /> },
  { path: '/register', element: <RegisterPage /> },
  {
    element: <ProtectedRoute />,
    children: [{ path: '/', element: <Dashboard /> }],
  },
  { path: '*', element: <Navigate to="/" replace /> },
]);
```

- [ ] **Step 2: Write App**

```tsx
// apps/web/src/App.tsx
import { RouterProvider } from 'react-router';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from './lib/queryClient';
import { router } from './routes/router';

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

export default App;
```

- [ ] **Step 3: Write main**

```tsx
// apps/web/src/main.tsx
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const rootEl = document.getElementById('root');
if (!rootEl) throw new Error('#root element not found');

createRoot(rootEl).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

- [ ] **Step 4: Verify it compiles and the full web suite is green**

Run: `cd apps/web && npx tsc --noEmit && npx vitest run`
Expected: PASS — `tsc` clean, every web test green.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/routes/router.tsx apps/web/src/App.tsx apps/web/src/main.tsx
git commit -m "feat: wire router, App and main with protected dashboard"
```

---

## Task 32: Full-stack smoke run

**Files:** none created; this validates the whole slice in Docker.

- [ ] **Step 1: Bring the stack up**

Run: `docker compose up -d --build`
Expected: all 6 services (caddy, web, api, db, redis, mailpit) reach healthy/running; `api` ran `prisma migrate deploy` on start.

- [ ] **Step 2: Verify health**

Run: `curl -k https://localhost/api/health`
Expected: `{"status":"ok"}`

- [ ] **Step 3: Manual register + login + me round-trip via curl**

Run:

```bash
# 1) get a CSRF token + cookie jar
curl -k -c /tmp/jar.txt https://localhost/api/csrf
# copy the csrfToken value from the JSON, export it:
TOKEN="<paste csrfToken>"

# 2) register
curl -k -b /tmp/jar.txt -c /tmp/jar.txt \
  -H "Content-Type: application/json" -H "x-csrf-token: $TOKEN" \
  -d '{"email":"smoke@user.com","password":"longenough1"}' \
  https://localhost/api/auth/register

# 3) login
curl -k -b /tmp/jar.txt -c /tmp/jar.txt \
  -H "Content-Type: application/json" -H "x-csrf-token: $TOKEN" \
  -d '{"email":"smoke@user.com","password":"longenough1"}' \
  https://localhost/api/auth/login

# 4) me
curl -k -b /tmp/jar.txt https://localhost/api/auth/me
```

Expected: step 2 -> `{"ok":true}` (201); step 3 -> `{"user":{...}}` (200) with a `__Host-sid` Set-Cookie; step 4 -> `{"user":{"email":"smoke@user.com","role":"USER"}}`.

- [ ] **Step 4: Verify the SPA loads and the protected redirect works**

Open `https://localhost/` in a browser (trust Caddy's local CA once). Expected: redirected to `/login` when not signed in; after logging in with the smoke user you land on the Dashboard showing `smoke@user.com (USER)`; the Log out button returns you to `/login`.

- [ ] **Step 5: Tear down**

Run: `docker compose down`
Expected: services stopped.

> No commit — this task is a verification gate. If any step fails, return to the relevant earlier task, fix, and re-run its unit/integration test before re-running this smoke test.

---

## Self-Review Notes (for the executing engineer)

- **Spec coverage:** config/env (T1), prisma (T3) + redis (T2) singletons, password (T4), audit (T5), sessionStore (T6), session middleware (T8), csrf + GET /api/csrf (T9, T18), security helmet+cors (T10), rateLimit on auth (T11, T18), requireAuth (T12), errorHandler (T13), auth schema (T14), service createUser/verifyCredentials (T15), routes register/login/logout/me (T16, T18, T22), anti-enumeration generic errors (T15, T23). WEB: apiClient (T24), queryClient (T25), useMe/useLogin/useRegister/useLogout (T26), LoginPage (T27) + RegisterPage (T28), ProtectedRoute (T30) + router (T31), Dashboard (T29). Tests: supertest happy/failure/unauthenticated for every endpoint (T20–T22), enumeration-parity (T23), RTL+MSW login form (T27) + protected redirect (T30). All scope items covered.
- **Naming consistency:** cookie `__Host-sid` (T8, T16, T22); session prefix `app:sess:` shared by `SESSION_PREFIX` (T6) and the store (T8); per-user set key `user_sessions:<id>` (T6, T21, T22); `HttpError` used by service (T15) + handler (T13); `addUserSession`/`removeUserSession`/`destroyAllUserSessions` (T6) consumed by routes (T16); endpoints under `/api` with `/api/auth/...` (including `/api/auth/me`), `/api/csrf`, `/api/health` per CONTRACTS (no `/api/me` alias).
- **Plan-evolution alignment:** register sets `emailVerifiedAt = now()` (active immediately) and sends NO email; login does NOT check verification — both correct for Plan 01. `sessionStore.ts` and `audit.ts` are introduced here for later plans to reuse.

**Plan complete.** Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task with review between tasks.
2. **Inline Execution** — execute tasks in this session with checkpoints.
