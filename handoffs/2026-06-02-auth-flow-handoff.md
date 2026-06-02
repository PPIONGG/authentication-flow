# Handoff — authentication-flow (2026-06-02)

> **TL;DR (ไทย):** Plan 00 (scaffold+Docker) และ Plan 01 ฝั่ง **API** เสร็จและพิสูจน์แล้ว (47 เทสต์เขียว + curl จริงผ่าน Caddy). หยุดไว้ก่อน **หน้า React ของ Plan 01 (Task 24+)**. งานที่เหลือ: หน้า React → Plan 02-05. รันเทส API ต้องรัน **ในสแตก Docker** เท่านั้น. ยึด `docs/superpowers/plans/CONTRACTS.md` เป็นสัญญากลาง.

This project is a self-hosted, full-stack auth reference (learning project). It is built by
executing a set of reviewed-and-verified plans task-by-task with TDD and frequent commits.

- **Repo:** <https://github.com/PPIONGG/authentication-flow> (`main`, ~39 commits, in sync)
- **Stack:** Vite+React+TS SPA · Express 5+TS API · Postgres+Prisma 7 · Redis sessions · Caddy
  (single origin, `tls internal`) · Mailpit · argon2id · Docker Compose. Server-side **opaque
  sessions in `__Host-sid` httpOnly cookies (NOT JWT)**.

## Read these first (do not duplicate — they are the source of truth)

- `CONTEXT.md` — domain glossary (User, Session, Credential, Reset vs Change pw, Verification token)
- `docs/ROADMAP.md` — ✅ chosen / 🔜 deferred, per topic (10 topics)
- `docs/adr/0001-0003` — why in-house auth · sessions-not-JWT · single-origin reverse proxy
- `docs/superpowers/plans/README.md` — the 6 plans + build order
- `docs/superpowers/plans/CONTRACTS.md` — **AUTHORITATIVE** shared interfaces (apiClient shape,
  `/api`-prefixed paths, `writeAudit` signature + event vocabulary, token/mailer exports, the
  CSRF-aware test agent). **If a plan's code disagrees with CONTRACTS, CONTRACTS wins.**

## Done & verified

- **Plan 00** (`...-00-scaffold-and-docker.md`) — fully built. `docker compose up -d` → 6 services
  healthy; `https://localhost/api/health` + hello page + migrations confirmed.
- **Plan 01 API side, Tasks 1-23** (`...-01-core-auth-sessions.md`) — register/login/logout/me,
  Redis sessions, CSRF (csrf-csrf), helmet/cors, rate-limit, argon2id, audit, anti-enumeration.
  **47 tests green** (21 files) + proven live end-to-end via curl→Caddy (register→login→me→logout,
  wrong-pw→generic 401, audit rows written). See git log (commits tagged "Plan 01 T1..T23").

## Remaining work (in order)

1. **Plan 01 web side — Tasks 24+** (NOT STARTED): `apps/web` apiClient (object form per CONTRACTS),
   `useMe/useLogin/useRegister/useLogout`, `LoginPage`/`RegisterPage`/`Dashboard`, `ProtectedRoute`,
   router wiring, and RTL+MSW tests. Resume by opening
   `docs/superpowers/plans/2026-06-01-01-core-auth-sessions.md` at **Task 24** (≈ line 2175).
   ⛔ **FIRST install the web deps the web tasks need but `apps/web/package.json` is missing**
   (the Plan lists them only in its prose Tech-Stack line — there is NO install step in the web
   tasks): `npm --prefix apps/web install react-hook-form @hookform/resolvers zod` and
   `npm --prefix apps/web install -D msw`. Skip this and the first web test dies with
   module-not-found. (`npm outdated` will NOT surface absent packages.)
2. **Plan 02** — email verification + password reset (Mailpit, tokens; gates login on verified email).
3. **Plan 03** — account mgmt (change pw/email, logout-all).
4. **Plan 04** — RBAC + admin routes + audit viewer.
5. **Plan 05** — security hardening pass (regression tests + `docs/SECURITY.md`).
6. **Deferred (🔜 in ROADMAP):** social login, magic link, passkey/WebAuthn, 2FA, HIBP check,
   CAPTCHA, prod docker compose, CI/CD. Pick up only after fundamentals.

## Gotchas / what tripped us up (READ — saves hours)

- **Run API tests INSIDE the stack:** `docker compose exec api npm test`. Host runs FAIL — the
  `DATABASE_URL`/`REDIS_URL` use docker hostnames (`db`,`redis`) that only resolve in the compose
  network. (Pure-unit tests with no DB/redis can run on host, but just always use the container.)
- **CSRF ⇄ session coupling:** csrf-csrf binds the token to `req.session.id`. With
  `saveUninitialized:false`, an *untouched* session never sends a cookie, so the token's binding
  breaks. Fix already applied: `GET /api/csrf` sets `req.session.bootstrappedAt` to force a stable
  `__Host-sid`. The `makeCsrfAgent`/`signedInAgent` test helpers **re-fetch CSRF after login**
  (login regenerates the session id). Web `apiClient` must do the same (bootstrap CSRF, retry once
  on 403).
- **Cookies `Secure` in dev/prod, relaxed only when `NODE_ENV=test`** (supertest is http and
  superagent won't resend Secure cookies). The API `npm test` script sets `NODE_ENV=test`.
- **express-rate-limit / rate-limit-redis print benign init warnings** to stderr during tests —
  they are NOT failures. Auth limiter is intentionally high in test mode.

## Plan-doc drift (un-synced — user deferred syncing)

These 4 fixes are in committed CODE but the **Plan 01 doc still shows the pre-fix versions**. A
next agent following the Plan 01 doc verbatim should prefer the code + CONTRACTS:

1. `env.ts` exports a testable `parseEnv()` (throws) + `env`.
2. Test infra added: `apps/api/tests/setup.ts` (connects Redis), vitest `setupFiles`,
   `NODE_ENV=test` in the test script, `secure` cookie relaxed in tests (session.ts + csrf.ts).
3. `app.ts` `/api/csrf` sets `req.session.bootstrappedAt` (+ field in `src/types/session.d.ts`).
4. `authLimiter` test-mode limit raised to 100 + a dedicated rate-limit unit test (so multi-step
   integration flows aren't throttled).
(Plan 00 doc IS synced: `@vitejs/plugin-react@^5.2.0` for Vite 8; web build `tsc -p` not `tsc -b`;
Dockerfile passes a throwaway `DATABASE_URL` to `prisma generate`; gitignored `apps/api/.env`.)

Optional task: "sync the Plan 01 doc with these 4 deviations."

## How to run / resume

```bash
cd authentication-flow
cp .env.example .env                 # local env (gitignored); placeholder secrets are fine for dev
docker compose up -d                 # 6 services; wait until `docker compose ps` shows healthy
curl -k https://localhost/api/health # {"status":"ok"}
docker compose exec api npm test     # 47 API tests, all green
# web tests run on the HOST (jsdom, no DB/Redis): npm --prefix apps/web test  (once web exists)
```

Notes:

- **API tests run in the container; web tests run on the host** (jsdom + MSW, no DB/Redis needed).
- The **root `.env`** (read by compose via `env_file`) is authoritative. The untracked
  `apps/api/.env` is only a local convenience for host-run tooling (e.g. `prisma generate`) and
  can be ignored — both hold the same dev values.
- **Git convention:** commit straight to `main` and `git push origin main` (no feature-branch
  convention in this repo). `gh` CLI is NOT installed; plain `git` works (GitHub creds are cached).

## Suggested skills for the next session

- **superpowers:executing-plans** — to continue Plan 01 web (Task 24+) and Plans 02-05 task-by-task.
  (Or **superpowers:subagent-driven-development** for faster, isolated per-task execution.)
- **superpowers:test-driven-development** — honor the red→green→commit loop each task.
- **superpowers:verification-before-completion** — run the suite + a live curl before claiming done.
- Consult **context7** MCP for current library APIs before writing new framework code (the plans
  were written against mid-2026 versions; run `npm outdated` and re-check React Router / TanStack
  Query / @hookform/resolvers for the web tasks).
</content>
