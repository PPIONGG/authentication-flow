# Shared Contracts (authoritative)

> The 6 plans were drafted in parallel and each invented slightly different versions of the
> shared interfaces they hand off to one another. This file is the **single source of truth**
> for those boundaries. Where any plan's code disagrees with this file, **this file wins** — and
> the plans have been patched to conform. Read this before executing any plan.

## File ownership (who CREATES vs MODIFIES)

| File | Owner (creates) | Others |
|------|-----------------|--------|
| `apps/api/src/config/env.ts` | **Plan 00** | import `env` |
| `apps/api/src/db/prisma.ts` | **Plan 00** | import `prisma` |
| `apps/api/src/redis/client.ts` | **Plan 00** | import `redis` |
| `apps/api/src/server.ts` | **Plan 00** | — |
| `apps/api/src/app.ts` | **Plan 00** (health + base middleware) | Plans 01–04 **modify** (add middleware/routers) |
| `apps/api/src/lib/audit.ts` | **Plan 01** | import `writeAudit` |
| `apps/api/src/lib/sessionStore.ts` | **Plan 01** | reused by 02/03 |
| `apps/api/src/lib/password.ts` | **Plan 01** | reused everywhere |
| `apps/api/src/lib/tokens.ts` | **Plan 02** | reused by 03 |
| `apps/api/src/lib/mailer.ts` | **Plan 02** | reused by 03 |
| `apps/web/src/lib/apiClient.ts` | **Plan 01** | used by 02/03/04 |
| `apps/api/tests/helpers/db.ts` | **Plan 01** | all API tests |
| `apps/api/tests/helpers/agent.ts` | **Plan 01** | all API tests |
| `apps/api/tests/helpers/mailpit.ts` | **Plan 02** | 02/03 tests |

A plan must **never re-`Create`** a file another plan owns — it `Modify`s it or imports from it.

## Backend singletons (Plan 00 owns)

```ts
// src/config/env.ts
export const env: Readonly<{
  NODE_ENV: string; PORT: number;
  DATABASE_URL: string; REDIS_URL: string;
  SESSION_SECRET: string; CSRF_SECRET: string;
  SMTP_HOST: string; SMTP_PORT: number; MAIL_FROM: string;
  APP_URL: string;
}>; // zod-validated; on failure logs + process.exit(1)

// src/db/prisma.ts
export const prisma: PrismaClient;

// src/redis/client.ts  — canonical export name is `redis` (NOT redisClient)
export const redis: RedisClientType;        // node-redis client (created, not yet connected)
export async function connectRedis(): Promise<void>;
export async function disconnectRedis(): Promise<void>;

// src/server.ts  — await connectRedis() THEN app.listen(env.PORT)
```

## Audit helper (Plan 01 owns)

```ts
// src/lib/audit.ts
export type AuditEvent =
  | 'register' | 'login_success' | 'login_fail' | 'logout' | 'logout_all'
  | 'password_reset' | 'password_change' | 'email_change' | 'email_verified';

export async function writeAudit(input: {
  event: AuditEvent;
  userId?: string;
  ip?: string;
  userAgent?: string;
}): Promise<void>;
```

**Always** the object form. Canonical event strings only. Examples:
`writeAudit({ event: 'login_fail', ip: req.ip, userAgent: req.get('user-agent') })`,
`writeAudit({ event: 'password_change', userId, ip: req.ip, userAgent: req.get('user-agent') })`.
There is **no** `audit(...)` function and **no** `(req, userId, event)` positional form. The
change-password event is `'password_change'` (Plan 03 writes it, Plan 04 asserts it).

## Credentials + login gate (Plan 01 + Plan 02)

```ts
// src/modules/auth/auth.service.ts (Plan 01)
// On unknown email, STILL run argon2.verify against a constant decoy hash to equalize timing
// (anti-enumeration), then throw. On success, RETURN the user.
export async function verifyCredentials(email: string, password: string): Promise<User>; // throws HttpError(401) on bad creds
```

- The decoy-hash verify is implemented in Plan 01, so Plan 05's `SECURITY.md` anti-enumeration
  timing claim is accurate.
- The **email-verified gate lives in the login route** (Plan 02): after `verifyCredentials`
  succeeds, if `user.emailVerifiedAt` is `null`, respond `403 { error: 'EMAIL_NOT_VERIFIED' }`
  and do **not** create a session.

## Tokens (Plan 02 owns)

```ts
// src/lib/tokens.ts  — both functions take/return OBJECTS
export async function createToken(input: {
  userId: string; type: TokenType; newEmail?: string;
}): Promise<{ token: string; tokenHash: string; expiresAt: Date }>;

export async function consumeToken(input: {
  token: string; type: TokenType;
}): Promise<{ userId: string; newEmail: string | null } | null>; // single-use, expiry-checked, timing-safe
```

Callers destructure: `const { token } = await createToken({ userId, type: 'EMAIL_CHANGE', newEmail })`
and `const rec = await consumeToken({ token, type: 'EMAIL_CHANGE' })`.

## Mailer (Plan 02 owns)

```ts
// src/lib/mailer.ts
export const mailer; // nodemailer transport -> Mailpit
export async function sendVerificationEmail(to: string, token: string): Promise<void>;
export async function sendPasswordResetEmail(to: string, token: string): Promise<void>;
export async function sendEmailChangeEmail(to: string, token: string): Promise<void>; // used by Plan 03
```

There is **no** generic `sendMail(...)` — use the named functions.

## Web API client (Plan 01 owns)

```ts
// src/lib/apiClient.ts
export class ApiError extends Error { status: number; body: unknown; }
export const apiClient: {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
};
```

- **Path convention:** callers pass the **full path including `/api`**, e.g.
  `apiClient.post('/api/auth/login', body)`, `apiClient.get('/api/auth/me')`.
- The client always sets `credentials: 'include'`, bootstraps the CSRF token internally
  (GET `/api/csrf` once, cache it, attach header `x-csrf-token` on mutating requests), and on a
  `403` CSRF failure re-fetches the token once and retries. Hooks do **not** call `fetchCsrf`
  themselves.
- `useMe` calls **`/api/auth/me`** (there is no `/api/me` alias).

## CSRF (Plan 01 owns) + test agents

- `csrf-csrf` is configured with `cookieName: 'x-csrf-token'` — the CSRF cookie is literally
  named `x-csrf-token` (not the library default `__Host-psifi.x-csrf-token`).
- `app.use(csrfProtection)` is mounted **globally before** the routers, so **every mutating
  request in every API test must carry a CSRF token**.
- The token is bound to the **session id**; after login (which regenerates the session) a fresh
  CSRF token must be fetched.

```ts
// tests/helpers/agent.ts (Plan 01 owns)
export async function makeCsrfAgent(app): Promise<{ agent; csrfToken: string }>; // supertest agent w/ csrf cookie
export async function signedInAgent(app, creds: { email: string; password: string }):
  Promise<{ agent; user; csrfToken: string }>; // registers+verifies+logs in, returns authed agent + FRESH csrf
export async function signInExistingUser(app, agent, creds: { email: string; password: string }):
  Promise<{ csrfToken: string }>;

// tests/helpers/db.ts (Plan 01) -> export async function resetState(): Promise<void>;  // truncate tables + flush test redis
// tests/helpers/mailpit.ts (Plan 02) -> export async function latestMessageTo(email): Promise<...>;
```

Every API integration test imports these from `tests/helpers/agent.js` / `db.js` / `mailpit.js`
(there is no single-file `tests/helpers.ts`). Plan 05's rate-limit 429 test must bootstrap CSRF
per attempt and send `Cookie` + `x-csrf-token`.
