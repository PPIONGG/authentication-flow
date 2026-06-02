# Scaffold & Docker Compose Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Stand up the authentication-flow monorepo skeleton and a fully working dev Docker stack where `docker compose up` brings all six services healthy, `curl -k https://localhost/api/health` returns `{"status":"ok"}`, and `https://localhost` serves the React hello page.

**Architecture:** A single Caddy origin (`https://localhost`, `tls internal`) reverse-proxies `/api/*` to an Express/TypeScript API (port 3000) and everything else to the Vite dev server (port 5173, with HMR websocket upgrade). The API uses Prisma 7 (driver-adapter Postgres) for the data layer and node-redis for sessions/rate-limiting, all run as Docker services (caddy, web, api, db, redis, mailpit) wired with healthchecks and `depends_on: service_healthy`.

**Tech Stack:** Express 5 + TypeScript (ESM, strict), Prisma 7.8 (`prisma-client` generator + `@prisma/adapter-pg`), node-redis 6, Vite 8 + React + React Router 7 + TanStack Query 5, Caddy 2.10, Docker Compose, Vitest 4 + Supertest 7 (API) / Vitest 4 + RTL (web), Zod 4.

---

## Files Overview

**Root**

- `docker-compose.yml` — 6 services + healthchecks + depends_on
- `Caddyfile` — single origin, tls internal, `/api/*` proxy, Vite HMR, SPA fallback
- `.env.example` — all config keys
- `.env` — local copy (gitignored)
- `.gitignore`

**apps/api/** (Express + TS ESM)

- `package.json`, `tsconfig.json`, `vitest.config.ts`, `Dockerfile`, `docker-entrypoint.sh`
- `prisma.config.ts`, `prisma/schema.prisma`, `prisma/migrations/**`
- `src/config/env.ts`, `src/db/prisma.ts`, `src/redis/client.ts`
- `src/app.ts`, `src/server.ts`
- `tests/health.test.ts`

**apps/web/** (Vite + React + TS)

- `package.json`, `tsconfig.json`, `tsconfig.node.json`, `vite.config.ts`, `vitest.config.ts`, `Dockerfile`
- `index.html`, `src/main.tsx`, `src/App.tsx`, `src/vite-env.d.ts`
- `src/lib/queryClient.ts`, `src/routes/router.tsx`
- `tests/setup.ts`, `tests/App.test.tsx`

---

## Task 1: Root scaffolding (.gitignore + .env.example)

**Files**

- Create: `.gitignore`
- Create: `.env.example`

- [ ] **Step 1: Create `.gitignore` at repo root.**

  ```gitignore
  # dependencies
  node_modules/

  # env
  .env

  # build output
  dist/
  apps/api/dist/
  apps/web/dist/

  # prisma generated client (regenerated in build / locally)
  apps/api/src/generated/

  # logs / os
  *.log
  .DS_Store

  # caddy local CA data (mounted volume)
  caddy_data/
  caddy_config/
  ```

- [ ] **Step 2: Create `.env.example` at repo root.** These keys match FOUNDATION's ENV list. The hostnames (`db`, `redis`, `mailpit`) are Docker service names.

  ```dotenv
  # Postgres connection used by Prisma (service name "db" inside the compose network)
  DATABASE_URL=postgresql://app:app@db:5432/app?schema=public

  # Redis connection used by sessions + rate limiting (service name "redis")
  REDIS_URL=redis://redis:6379

  # Session signing secret (>= 32 bytes of entropy). Generate with: openssl rand -base64 48
  SESSION_SECRET=change-me-to-a-long-random-string-at-least-32-bytes

  # CSRF HMAC secret (>= 32 bytes). Generate with: openssl rand -base64 48
  CSRF_SECRET=change-me-to-a-different-long-random-string

  # Mail (Mailpit) — service name "mailpit", SMTP plaintext on 1025
  SMTP_HOST=mailpit
  SMTP_PORT=1025
  MAIL_FROM=no-reply@authentication-flow.local

  # Public origin served by Caddy
  APP_URL=https://localhost

  # Node environment
  NODE_ENV=development
  ```

- [ ] **Step 3: Create the local `.env` from the example and verify.**

  ```bash
  cp /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/.env.example \
     /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/.env
  ls -la /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/.env
  ```

  Expected: the `.env` file exists. (It is gitignored, so it will not be committed.)

- [ ] **Step 4: Initialize the git repo and commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow init
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add .gitignore .env.example
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: add root gitignore and env example"
  ```

  Expected: one commit created; `git status` shows `.env` as untracked/ignored (it will not appear because `node_modules`/`.env` are ignored).

---

## Task 2: API package scaffolding (package.json, tsconfig, vitest config)

**Files**

- Create: `apps/api/package.json`
- Create: `apps/api/tsconfig.json`
- Create: `apps/api/vitest.config.ts`

- [ ] **Step 1: Create `apps/api/package.json`.** ESM (`"type": "module"`), pinned versions per FOUNDATION's verified library reference.

  ```json
  {
    "name": "@authentication-flow/api",
    "version": "0.0.0",
    "private": true,
    "type": "module",
    "scripts": {
      "dev": "tsx watch src/server.ts",
      "build": "tsc -p tsconfig.json",
      "start": "node dist/server.js",
      "test": "vitest run",
      "prisma:generate": "prisma generate",
      "prisma:deploy": "prisma migrate deploy"
    },
    "dependencies": {
      "@prisma/adapter-pg": "7.8.0",
      "argon2": "^0.43.0",
      "connect-redis": "9.0.0",
      "cookie-parser": "^1.4.7",
      "cors": "^2.8.5",
      "csrf-csrf": "4.0.3",
      "dotenv": "^17.0.0",
      "express": "5.2.1",
      "express-rate-limit": "8.5.2",
      "express-session": "1.19.0",
      "helmet": "8.2.0",
      "nodemailer": "8.0.10",
      "pg": "8.21.0",
      "rate-limit-redis": "5.0.0",
      "redis": "6.0.0",
      "zod": "^4.4.0"
    },
    "devDependencies": {
      "@prisma/client": "7.8.0",
      "@types/cookie-parser": "^1.4.8",
      "@types/cors": "^2.8.17",
      "@types/express": "^5.0.0",
      "@types/express-session": "^1.18.0",
      "@types/node": "^22.0.0",
      "@types/nodemailer": "^6.4.17",
      "@types/supertest": "7.2.0",
      "prisma": "7.8.0",
      "supertest": "7.2.2",
      "tsx": "^4.19.0",
      "typescript": "^5.6.0",
      "vitest": "4.1.8"
    }
  }
  ```

- [ ] **Step 2: Create `apps/api/tsconfig.json`.** Strict + ESM + NodeNext resolution.

  ```json
  {
    "compilerOptions": {
      "target": "ES2022",
      "module": "NodeNext",
      "moduleResolution": "NodeNext",
      "lib": ["ES2022"],
      "outDir": "dist",
      "rootDir": "src",
      "strict": true,
      "esModuleInterop": true,
      "forceConsistentCasingInFileNames": true,
      "skipLibCheck": true,
      "resolveJsonModule": true,
      "declaration": false,
      "sourceMap": true,
      "types": ["node"]
    },
    "include": ["src/**/*.ts"],
    "exclude": ["node_modules", "dist", "tests"]
  }
  ```

- [ ] **Step 3: Create `apps/api/vitest.config.ts`.** Serialize files (single throwaway DB later) and use the forks pool, per FOUNDATION test infra guidance.

  ```ts
  import { defineConfig } from "vitest/config";

  export default defineConfig({
    test: {
      include: ["tests/**/*.test.ts"],
      environment: "node",
      pool: "forks",
      fileParallelism: false,
      globals: false,
    },
  });
  ```

- [ ] **Step 4: Install dependencies and confirm the toolchain resolves.**

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api install
  npx --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api tsc --version
  ```

  Expected: install completes; `tsc` prints a `Version 5.x` line.

- [ ] **Step 5: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/package.json apps/api/tsconfig.json apps/api/vitest.config.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: scaffold api package, tsconfig and vitest config"
  ```

---

## Task 3: Prisma schema, config, and PrismaClient singleton

**Files**

- Create: `apps/api/prisma/schema.prisma`
- Create: `apps/api/prisma.config.ts`
- Create: `apps/api/src/db/prisma.ts`

- [ ] **Step 1: Create `apps/api/prisma/schema.prisma`** with the FULL data model from FOUNDATION (all enums + models). Uses the Prisma 7 `prisma-client` generator emitting ESM into `src/generated/prisma`; no `url` in the schema (it lives in `prisma.config.ts`).

  ```prisma
  generator client {
    provider     = "prisma-client"
    output       = "../src/generated/prisma"
    moduleFormat = "esm"
  }

  datasource db {
    provider = "postgresql"
  }

  enum Role {
    USER
    ADMIN
  }

  enum TokenType {
    EMAIL_VERIFY
    PASSWORD_RESET
    EMAIL_CHANGE
  }

  model User {
    id              String    @id @default(cuid())
    email           String    @unique
    emailVerifiedAt DateTime?
    passwordHash    String
    role            Role      @default(USER)
    createdAt       DateTime  @default(now())
    updatedAt       DateTime  @updatedAt
    tokens          VerificationToken[]
    auditLogs       AuditLog[]
  }

  model VerificationToken {
    id         String     @id @default(cuid())
    userId     String
    user       User       @relation(fields: [userId], references: [id], onDelete: Cascade)
    tokenHash  String     @unique
    type       TokenType
    newEmail   String?
    expiresAt  DateTime
    consumedAt DateTime?
    createdAt  DateTime   @default(now())

    @@index([userId])
  }

  model AuditLog {
    id        String   @id @default(cuid())
    userId    String?
    user      User?    @relation(fields: [userId], references: [id], onDelete: SetNull)
    event     String
    ip        String?
    userAgent String?
    createdAt DateTime @default(now())

    @@index([userId])
  }
  ```

- [ ] **Step 2: Create `apps/api/prisma.config.ts`.** Prisma 7 no longer auto-loads `.env`, so `import "dotenv/config"` is required; the datasource URL is supplied here.

  ```ts
  import "dotenv/config";
  import { defineConfig, env } from "prisma/config";

  type Env = { DATABASE_URL: string };

  export default defineConfig({
    schema: "prisma/schema.prisma",
    migrations: {
      path: "prisma/migrations",
    },
    datasource: {
      url: env<Env>("DATABASE_URL"),
    },
  });
  ```

- [ ] **Step 3: Generate the Prisma client locally.** This emits plain-TS client code into `apps/api/src/generated/prisma`.

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api run prisma:generate
  ls /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/src/generated/prisma
  ```

  Expected: generation succeeds; the `src/generated/prisma` directory contains a `client.ts` (and supporting files).

- [ ] **Step 4: Create `apps/api/src/db/prisma.ts`** — the PrismaClient singleton using the Prisma 7 Postgres driver adapter. Import path is the generated output dir, NOT `@prisma/client`.

  ```ts
  import { PrismaClient } from "./../generated/prisma/client.js";
  import { PrismaPg } from "@prisma/adapter-pg";
  import { env } from "../config/env.js";

  const adapter = new PrismaPg({ connectionString: env.DATABASE_URL });

  const globalForPrisma = globalThis as unknown as { prisma?: PrismaClient };

  export const prisma =
    globalForPrisma.prisma ??
    new PrismaClient({ adapter, log: ["warn", "error"] });

  if (env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
  ```

  Note: `src/config/env.ts` is created in Task 4. This import will only resolve once Task 4 is complete; the file is committed now and verified end-to-end in Task 4.

- [ ] **Step 5: Create the initial migration against a throwaway local Postgres.** Start a disposable container, point `DATABASE_URL` at it for the duration of the command, and run `migrate dev` to author `prisma/migrations`.

  ```bash
  docker run --rm -d --name afm-pg-tmp -e POSTGRES_USER=app -e POSTGRES_PASSWORD=app -e POSTGRES_DB=app -p 55432:5432 postgres:17-alpine
  ```

  Wait for readiness, then create the migration:

  ```bash
  until docker exec afm-pg-tmp pg_isready -U app -d app >/dev/null 2>&1; do :; done
  DATABASE_URL="postgresql://app:app@localhost:55432/app?schema=public" \
    npx --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api \
    prisma migrate dev --name init
  docker rm -f afm-pg-tmp
  ls /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/prisma/migrations
  ```

  Expected: a timestamped migration folder (e.g. `20260601_init/`) containing `migration.sql` with `CREATE TABLE "User"`, `"VerificationToken"`, `"AuditLog"` and the two enums; the temp container is removed.

- [ ] **Step 6: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/prisma/schema.prisma apps/api/prisma.config.ts apps/api/prisma/migrations apps/api/src/db/prisma.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "feat: add full prisma schema, config, initial migration and client singleton"
  ```

---

## Task 4: Zod-validated env config

**Files**

- Create: `apps/api/src/config/env.ts`

- [ ] **Step 1: Create `apps/api/src/config/env.ts`.** Zod 4 schema validates `process.env` at startup; exports a typed, frozen `env` object. `dotenv/config` loads `.env` for local (non-Docker) runs.

  ```ts
  import "dotenv/config";
  import { z } from "zod";

  const EnvSchema = z.object({
    DATABASE_URL: z.string().min(1),
    REDIS_URL: z.string().min(1),
    SESSION_SECRET: z.string().min(32),
    CSRF_SECRET: z.string().min(32),
    SMTP_HOST: z.string().min(1),
    SMTP_PORT: z.coerce.number().int().positive(),
    MAIL_FROM: z.email(),
    APP_URL: z.url(),
    NODE_ENV: z
      .enum(["development", "test", "production"])
      .default("development"),
    PORT: z.coerce.number().int().positive().default(3000),
  });

  const parsed = EnvSchema.safeParse(process.env);

  if (!parsed.success) {
    console.error(
      "Invalid environment configuration:\n" + z.prettifyError(parsed.error),
    );
    process.exit(1);
  }

  export const env = Object.freeze(parsed.data);
  export type Env = typeof env;
  ```

- [ ] **Step 2: Type-check the API source so far.** Confirms `env.ts`, `prisma.ts`, and the generated client all compile under strict ESM.

  ```bash
  npx --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api tsc --noEmit -p /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/tsconfig.json
  ```

  Expected: no output (exit code 0). If `src/generated/prisma` is reported missing, re-run `npm --prefix apps/api run prisma:generate` (Task 3, Step 3).

- [ ] **Step 3: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/src/config/env.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "feat: add zod-validated env config"
  ```

---

## Task 5: Redis client singleton

**Files**

- Create: `apps/api/src/redis/client.ts`

- [ ] **Step 1: Create `apps/api/src/redis/client.ts`.** node-redis 6 `createClient` (must call `connect()` — v4+ does not auto-connect). Exposes a lazy `connectRedis()` the server bootstrap awaits before listening; later plans pass `redis` to connect-redis and rate-limit-redis. The canonical singleton export name is `redis` (NOT `redisClient`).

  ```ts
  import { createClient } from "redis";
  import { env } from "../config/env.js";

  export const redis = createClient({ url: env.REDIS_URL });

  redis.on("error", (err) => {
    console.error("[redis] client error:", err);
  });

  let connected = false;

  export async function connectRedis(): Promise<void> {
    if (connected) return;
    await redis.connect();
    connected = true;
  }

  export async function disconnectRedis(): Promise<void> {
    if (!connected) return;
    await redis.quit();
    connected = false;
  }
  ```

- [ ] **Step 2: Type-check.**

  ```bash
  npx --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api tsc --noEmit -p /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/tsconfig.json
  ```

  Expected: no output (exit code 0).

- [ ] **Step 3: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/src/redis/client.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "feat: add redis client singleton"
  ```

---

## Task 6: Express app skeleton + /api/health (TDD)

**Files**

- Create: `apps/api/tests/health.test.ts`
- Create: `apps/api/src/app.ts`

- [ ] **Step 1: Write the failing integration test `apps/api/tests/health.test.ts`.** It imports the not-yet-existing `app` and asserts `GET /api/health` returns `200 {status:"ok"}`. Supertest binds an ephemeral port — never call `app.listen()` in the app module.

  ```ts
  import request from "supertest";
  import { describe, it, expect } from "vitest";
  import { app } from "../src/app.js";

  describe("GET /api/health", () => {
    it("returns 200 with status ok", async () => {
      const res = await request(app).get("/api/health");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "ok" });
    });
  });
  ```

- [ ] **Step 2: Run the test and watch it FAIL.**

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api test
  ```

  Expected: FAIL — Vitest reports it cannot resolve `../src/app.js` (module not found), because `app.ts` does not exist yet.

- [ ] **Step 3: Create `apps/api/src/app.ts`** — the Express 5 app with the middleware-order skeleton described in FOUNDATION (security headers, CORS, body parsing, cookie parsing) and the public `/api/health` route. Heavier middleware (session, csrf, rate-limit, auth, error handler) is wired in later plans; the skeleton documents the order without behavior that would block this slice.

  ```ts
  import express from "express";
  import helmet from "helmet";
  import cors from "cors";
  import cookieParser from "cookie-parser";
  import { env } from "./config/env.js";

  export const app = express();

  // Behind Caddy (reverse proxy): trust the proxy so Secure cookies are emitted.
  app.set("trust proxy", 1);

  // --- Security headers (helmet: CSP + HSTS) ---
  app.use(helmet());

  // --- CORS locked to the single origin, credentials enabled ---
  app.use(
    cors({
      origin: env.APP_URL,
      credentials: true,
    }),
  );

  // --- Body + cookie parsing (cookie-parser must precede csrf in later plans) ---
  app.use(express.json());
  app.use(cookieParser());

  // === API routes are mounted under /api ===
  const api = express.Router();

  // Public health check (no auth) — Plan 00.
  api.get("/health", (_req, res) => {
    res.status(200).json({ status: "ok" });
  });

  // Future routers mounted here in later plans:
  //   api.use("/auth", authRoutes)
  //   api.use("/account", accountRoutes)
  //   api.use("/admin", adminRoutes)
  //   api.get("/csrf", ...)

  app.use("/api", api);

  // Central error handler is added in a later plan (errorHandler.ts).
  ```

- [ ] **Step 4: Run the test and watch it PASS.**

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api test
  ```

  Expected: PASS — `1 passed (1)`; the health test returns `{ status: "ok" }`.

- [ ] **Step 5: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/tests/health.test.ts apps/api/src/app.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "feat: add express app skeleton and /api/health endpoint"
  ```

---

## Task 7: API server bootstrap

**Files**

- Create: `apps/api/src/server.ts`

- [ ] **Step 1: Create `apps/api/src/server.ts`.** Connects Redis, then starts the HTTP listener on `env.PORT` (3000). Kept separate from `app.ts` so tests import `app` without a live server.

  ```ts
  import { app } from "./app.js";
  import { env } from "./config/env.js";
  import { connectRedis } from "./redis/client.js";

  async function main(): Promise<void> {
    await connectRedis();
    app.listen(env.PORT, () => {
      console.log(`[api] listening on http://0.0.0.0:${env.PORT}`);
    });
  }

  main().catch((err) => {
    console.error("[api] fatal startup error:", err);
    process.exit(1);
  });
  ```

- [ ] **Step 2: Build the API to confirm the production entrypoint compiles.**

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api run build
  ls /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/dist/server.js
  ```

  Expected: build succeeds; `dist/server.js` exists.

- [ ] **Step 3: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/src/server.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "feat: add api server bootstrap with redis connect"
  ```

---

## Task 8: API Dockerfile + entrypoint

**Files**

- Create: `apps/api/Dockerfile`
- Create: `apps/api/docker-entrypoint.sh`
- Create: `apps/api/.dockerignore`

- [ ] **Step 1: Create `apps/api/.dockerignore`.** Keep the build context small and avoid copying host artifacts.

  ```dockerignore
  node_modules
  dist
  src/generated
  npm-debug.log
  .git
  ```

- [ ] **Step 2: Create `apps/api/Dockerfile`.** Node 22 (required by Prisma 7), installs deps, generates the Prisma client at build time, and runs in dev via `tsx watch`. `prisma migrate deploy` runs at container start (entrypoint), never at build (DB unreachable during build). OpenSSL is installed for Prisma.

  ```dockerfile
  FROM node:22-slim

  WORKDIR /app

  RUN apt-get update \
      && apt-get install -y --no-install-recommends openssl ca-certificates \
      && rm -rf /var/lib/apt/lists/*

  # Install dependencies first (better layer caching)
  COPY package.json package-lock.json* ./
  RUN npm install

  # Copy prisma schema + config, then generate the client into src/generated/prisma
  COPY prisma ./prisma
  COPY prisma.config.ts ./
  RUN npx prisma generate

  # Copy the rest of the source
  COPY . .

  RUN chmod +x docker-entrypoint.sh

  EXPOSE 3000

  ENTRYPOINT ["./docker-entrypoint.sh"]
  ```

- [ ] **Step 3: Create `apps/api/docker-entrypoint.sh`.** Applies pending migrations non-interactively, then starts the dev watcher (FOUNDATION: "api entrypoint runs `prisma migrate deploy` then `tsx watch`").

  ```sh
  #!/bin/sh
  set -e

  echo "[entrypoint] applying database migrations..."
  npx prisma migrate deploy

  echo "[entrypoint] starting api (tsx watch)..."
  exec npx tsx watch src/server.ts
  ```

- [ ] **Step 4: Make the entrypoint executable on disk (so the committed file carries the exec bit).**

  ```bash
  chmod +x /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/api/docker-entrypoint.sh
  ```

  Expected: no output (success).

- [ ] **Step 5: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/api/Dockerfile apps/api/docker-entrypoint.sh apps/api/.dockerignore
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: add api dockerfile and migrate-deploy entrypoint"
  ```

---

## Task 9: Web package scaffolding (package.json, tsconfig, vite/vitest config)

**Files**

- Create: `apps/web/package.json`
- Create: `apps/web/tsconfig.json`
- Create: `apps/web/tsconfig.node.json`
- Create: `apps/web/vite.config.ts`
- Create: `apps/web/vitest.config.ts`

- [ ] **Step 1: Create `apps/web/package.json`.** Pinned versions per FOUNDATION's frontend reference (React Router 7, TanStack Query 5, Vite 8, Vitest 4 + RTL + jsdom).

  ```json
  {
    "name": "@authentication-flow/web",
    "version": "0.0.0",
    "private": true,
    "type": "module",
    "scripts": {
      "dev": "vite",
      "build": "tsc -p tsconfig.json && vite build",
      "preview": "vite preview",
      "test": "vitest run"
    },
    "dependencies": {
      "@tanstack/react-query": "5.100.14",
      "react": "^19.0.0",
      "react-dom": "^19.0.0",
      "react-router": "7.16.0"
    },
    "devDependencies": {
      "@testing-library/jest-dom": "^6.6.0",
      "@testing-library/react": "^16.1.0",
      "@types/react": "^19.0.0",
      "@types/react-dom": "^19.0.0",
      "@vitejs/plugin-react": "^5.2.0",
      "jsdom": "^25.0.0",
      "typescript": "^5.6.0",
      "vite": "8.0.16",
      "vitest": "4.1.8"
    }
  }
  ```

- [ ] **Step 2: Create `apps/web/tsconfig.json`.** Strict, bundler resolution, JSX for React 19.

  ```json
  {
    "compilerOptions": {
      "target": "ES2022",
      "lib": ["ES2022", "DOM", "DOM.Iterable"],
      "module": "ESNext",
      "moduleResolution": "Bundler",
      "jsx": "react-jsx",
      "strict": true,
      "noEmit": true,
      "esModuleInterop": true,
      "skipLibCheck": true,
      "forceConsistentCasingInFileNames": true,
      "resolveJsonModule": true,
      "isolatedModules": true,
      "useDefineForClassFields": true,
      "types": ["vite/client", "vitest/globals", "@testing-library/jest-dom"]
    },
    "include": ["src", "tests"]
  }
  ```

- [ ] **Step 3: Create `apps/web/tsconfig.node.json`** (for the Vite config file itself).

  ```json
  {
    "compilerOptions": {
      "target": "ES2022",
      "lib": ["ES2022"],
      "module": "ESNext",
      "moduleResolution": "Bundler",
      "composite": true,
      "strict": true,
      "skipLibCheck": true,
      "noEmit": true
    },
    "include": ["vite.config.ts", "vitest.config.ts"]
  }
  ```

- [ ] **Step 4: Create `apps/web/vite.config.ts`.** Binds to all interfaces (needed inside Docker), and configures HMR to connect back over `wss` on 443 because the page is served via Caddy HTTPS (avoids the insecure-ws / redirect-loop gotcha). `allowedHosts` permits the Caddy `localhost` host.

  ```ts
  import { defineConfig } from "vite";
  import react from "@vitejs/plugin-react";

  export default defineConfig({
    plugins: [react()],
    server: {
      host: "0.0.0.0",
      port: 5173,
      strictPort: true,
      allowedHosts: ["localhost"],
      // Page is served at https://localhost via Caddy (port 443),
      // so HMR must connect back over wss on 443, not http on 5173.
      hmr: {
        host: "localhost",
        clientPort: 443,
        protocol: "wss",
      },
    },
  });
  ```

- [ ] **Step 5: Create `apps/web/vitest.config.ts`.** jsdom environment, global test APIs, and a setup file (created in Task 11) that wires jest-dom matchers.

  ```ts
  import { defineConfig } from "vitest/config";
  import react from "@vitejs/plugin-react";

  export default defineConfig({
    plugins: [react()],
    test: {
      include: ["tests/**/*.test.tsx"],
      environment: "jsdom",
      globals: true,
      setupFiles: ["./tests/setup.ts"],
    },
  });
  ```

- [ ] **Step 6: Install dependencies.**

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web install
  ```

  Expected: install completes without peer-dependency errors.

- [ ] **Step 7: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/web/package.json apps/web/tsconfig.json apps/web/tsconfig.node.json apps/web/vite.config.ts apps/web/vitest.config.ts
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: scaffold web package, tsconfig, vite and vitest config"
  ```

---

## Task 10: Web app source (entry, App, router skeleton, query client, hello page)

**Files**

- Create: `apps/web/index.html`
- Create: `apps/web/src/vite-env.d.ts`
- Create: `apps/web/src/lib/queryClient.ts`
- Create: `apps/web/src/routes/router.tsx`
- Create: `apps/web/src/App.tsx`
- Create: `apps/web/src/main.tsx`

- [ ] **Step 1: Create `apps/web/index.html`** — the Vite entry HTML.

  ```html
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>authentication-flow</title>
    </head>
    <body>
      <div id="root"></div>
      <script type="module" src="/src/main.tsx"></script>
    </body>
  </html>
  ```

- [ ] **Step 2: Create `apps/web/src/vite-env.d.ts`** — Vite client types + typed env (per FOUNDATION frontend reference).

  ```ts
  /// <reference types="vite/client" />

  interface ImportMetaEnv {
    readonly VITE_API_URL: string;
  }

  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
  ```

- [ ] **Step 3: Create `apps/web/src/lib/queryClient.ts`** — TanStack Query client with a 401-aware default (no retry), per FOUNDATION.

  ```ts
  import { QueryClient } from "@tanstack/react-query";

  export const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        staleTime: 60_000,
      },
    },
  });
  ```

- [ ] **Step 4: Create `apps/web/src/routes/router.tsx`** — declarative React Router 7 skeleton. All imports come from `react-router` (NOT `react-router-dom`). A single public hello route now; protected/role routes are added in later plans.

  ```tsx
  import { BrowserRouter, Routes, Route } from "react-router";
  import { HelloPage } from "../App";

  export function AppRouter() {
    return (
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<HelloPage />} />
          {/* Public routes (later plans): /login /register /verify-email
              /forgot-password /reset-password */}
          {/* Protected routes (later plans): / (dashboard) /account */}
          {/* ADMIN-only (later plans): /admin */}
        </Routes>
      </BrowserRouter>
    );
  }
  ```

- [ ] **Step 5: Create `apps/web/src/App.tsx`** — the hello page component asserted by the smoke test and served through Caddy.

  ```tsx
  export function HelloPage() {
    return (
      <main>
        <h1>authentication-flow</h1>
        <p>Hello from the web app.</p>
      </main>
    );
  }
  ```

- [ ] **Step 6: Create `apps/web/src/main.tsx`** — React entry wiring the QueryClientProvider around the router.

  ```tsx
  import { StrictMode } from "react";
  import { createRoot } from "react-dom/client";
  import { QueryClientProvider } from "@tanstack/react-query";
  import { queryClient } from "./lib/queryClient";
  import { AppRouter } from "./routes/router";

  const rootEl = document.getElementById("root");
  if (!rootEl) throw new Error("Root element #root not found");

  createRoot(rootEl).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <AppRouter />
      </QueryClientProvider>
    </StrictMode>,
  );
  ```

- [ ] **Step 7: Type-check + production build to confirm the SPA compiles.**

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web run build
  ```

  Expected: `tsc -b` passes and `vite build` writes `apps/web/dist/` without errors.

- [ ] **Step 8: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/web/index.html apps/web/src
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "feat: add web entry, hello page, router skeleton and query client"
  ```

---

## Task 11: Web smoke test (TDD)

**Files**

- Create: `apps/web/tests/setup.ts`
- Create: `apps/web/tests/App.test.tsx`

- [ ] **Step 1: Create `apps/web/tests/setup.ts`** — registers jest-dom matchers for every test file.

  ```ts
  import "@testing-library/jest-dom/vitest";
  ```

- [ ] **Step 2: Write the smoke test `apps/web/tests/App.test.tsx`** that renders the hello page and asserts its heading.

  ```tsx
  import { render, screen } from "@testing-library/react";
  import { describe, it, expect } from "vitest";
  import { HelloPage } from "../src/App";

  describe("HelloPage", () => {
    it("renders the app heading", () => {
      render(<HelloPage />);
      expect(
        screen.getByRole("heading", { name: /authentication-flow/i }),
      ).toBeInTheDocument();
    });
  });
  ```

- [ ] **Step 3: Run the web test suite and watch it PASS** (the component already exists from Task 10, so this confirms the Vitest + RTL + jsdom wiring is correct).

  ```bash
  npm --prefix /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/apps/web test
  ```

  Expected: PASS — `1 passed (1)`; the heading is found.

  To prove the test is real (red-green discipline), temporarily change the heading text in `apps/web/src/App.tsx` from `authentication-flow` to `broken`, re-run the command above, observe FAIL (`Unable to find an accessible element with the role "heading" and name /authentication-flow/i`), then revert the change and re-run to confirm PASS again.

- [ ] **Step 4: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/web/tests/setup.ts apps/web/tests/App.test.tsx
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "test: add web smoke test for hello page"
  ```

---

## Task 12: Web Dockerfile

**Files**

- Create: `apps/web/Dockerfile`
- Create: `apps/web/.dockerignore`

- [ ] **Step 1: Create `apps/web/.dockerignore`.**

  ```dockerignore
  node_modules
  dist
  npm-debug.log
  .git
  ```

- [ ] **Step 2: Create `apps/web/Dockerfile`.** Dev image runs the Vite dev server (HMR) bound to all interfaces on 5173; Caddy proxies to it. Production static-serving is out of scope for this dev stack.

  ```dockerfile
  FROM node:22-slim

  WORKDIR /app

  COPY package.json package-lock.json* ./
  RUN npm install

  COPY . .

  EXPOSE 5173

  CMD ["npx", "vite", "--host", "0.0.0.0", "--port", "5173"]
  ```

- [ ] **Step 3: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add apps/web/Dockerfile apps/web/.dockerignore
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: add web dockerfile running vite dev server"
  ```

---

## Task 13: Caddyfile (single origin, tls internal, /api proxy, Vite HMR, SPA fallback)

**Files**

- Create: `Caddyfile`

- [ ] **Step 1: Create `Caddyfile` at repo root.** Single `localhost` origin with `tls internal` (so Secure cookies work in dev). A `route { }` block forces literal directive order so `/api/*` is proxied to the `api` service BEFORE the catch-all SPA proxy. The catch-all `reverse_proxy` targets the Vite dev server (`web:5173`), which serves `index.html`, performs its own SPA history handling, and upgrades the HMR websocket transparently. Hostnames are Docker service names.

  ```caddyfile
  {
  	# In a container Caddy cannot install its root CA into a host trust store.
  	skip_install_trust
  }

  localhost {
  	tls internal

  	route {
  		# API first — never let the SPA proxy catch /api/*.
  		# Backend already expects the /api prefix, so do NOT strip it.
  		reverse_proxy /api/* api:3000

  		# Everything else -> Vite dev server (serves index.html + HMR ws).
  		# Caddy upgrades the websocket transparently; no special flag needed.
  		reverse_proxy web:5173
  	}
  }
  ```

- [ ] **Step 2: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add Caddyfile
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: add caddyfile with tls internal, api proxy and vite hmr"
  ```

---

## Task 14: docker-compose.yml (6 services + healthchecks + depends_on)

**Files**

- Create: `docker-compose.yml`

- [ ] **Step 1: Create `docker-compose.yml` at repo root.** Six services per FOUNDATION: `caddy` (80/443), `web` (5173 internal), `api` (3000 internal), `db` (postgres + `pgdata` volume), `redis`, `mailpit` (1025 + 8025). The obsolete top-level `version:` key is omitted. `api` waits for `db`, `redis`, and `mailpit` to be healthy. Source is bind-mounted for dev hot-reload; `node_modules`/generated dirs are masked with anonymous volumes so host artifacts don't clobber the in-image installs.

  ```yaml
  services:
    db:
      image: postgres:17-alpine
      environment:
        POSTGRES_USER: app
        POSTGRES_PASSWORD: app
        POSTGRES_DB: app
      volumes:
        - pgdata:/var/lib/postgresql/data
      healthcheck:
        test: ["CMD-SHELL", "pg_isready -U app -d app"]
        interval: 5s
        timeout: 5s
        retries: 10
        start_period: 15s

    redis:
      image: redis:7-alpine
      healthcheck:
        test: ["CMD", "redis-cli", "ping"]
        interval: 5s
        timeout: 3s
        retries: 10
        start_period: 5s

    mailpit:
      image: axllent/mailpit:latest
      ports:
        - "8025:8025"
      healthcheck:
        test: ["CMD", "/mailpit", "readyz"]
        interval: 10s
        timeout: 5s
        retries: 5
        start_period: 5s

    api:
      build:
        context: ./apps/api
        dockerfile: Dockerfile
      env_file:
        - .env
      environment:
        DATABASE_URL: postgresql://app:app@db:5432/app?schema=public
        REDIS_URL: redis://redis:6379
        SMTP_HOST: mailpit
        SMTP_PORT: "1025"
        NODE_ENV: development
        PORT: "3000"
      volumes:
        - ./apps/api:/app
        - api_node_modules:/app/node_modules
        - api_generated:/app/src/generated
      depends_on:
        db:
          condition: service_healthy
        redis:
          condition: service_healthy
        mailpit:
          condition: service_healthy
      healthcheck:
        test:
          [
            "CMD-SHELL",
            "node -e \"fetch('http://localhost:3000/api/health').then(r=>{if(r.status!==200)process.exit(1)}).catch(()=>process.exit(1))\"",
          ]
        interval: 10s
        timeout: 5s
        retries: 10
        start_period: 40s

    web:
      build:
        context: ./apps/web
        dockerfile: Dockerfile
      environment:
        VITE_API_URL: /api
      volumes:
        - ./apps/web:/app
        - web_node_modules:/app/node_modules
      depends_on:
        - api
      healthcheck:
        test:
          [
            "CMD-SHELL",
            "node -e \"fetch('http://localhost:5173/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))\"",
          ]
        interval: 10s
        timeout: 5s
        retries: 10
        start_period: 20s

    caddy:
      image: caddy:2.10-alpine
      ports:
        - "80:80"
        - "443:443"
      volumes:
        - ./Caddyfile:/etc/caddy/Caddyfile:ro
        - caddy_data:/data
        - caddy_config:/config
      depends_on:
        api:
          condition: service_healthy
        web:
          condition: service_healthy

  volumes:
    pgdata:
    api_node_modules:
    api_generated:
    web_node_modules:
    caddy_data:
    caddy_config:
  ```

- [ ] **Step 2: Validate the compose file parses.**

  ```bash
  docker compose -f /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/docker-compose.yml config >/dev/null && echo "compose OK"
  ```

  Expected: prints `compose OK` (no parse/interpolation errors). If it complains about a missing `.env`, confirm Task 1 Step 3 created `/Users/thammasornlueadtaharn/Desktop/project/authentication-flow/.env`.

- [ ] **Step 3: Commit.**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow add docker-compose.yml
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit -m "chore: add docker-compose with six services and healthchecks"
  ```

---

## Task 15: Full-stack acceptance (bring the stack up and verify)

**Files**

- (No new files — this task verifies the whole slice against FOUNDATION's acceptance criteria.)

- [ ] **Step 1: Build and start the entire stack in the background.**

  ```bash
  docker compose -f /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/docker-compose.yml up -d --build
  ```

  Expected: images build; containers `db`, `redis`, `mailpit`, `api`, `web`, `caddy` all start.

- [ ] **Step 2: Wait until every service reports healthy.** Poll the compose status until no container is still `starting`.

  ```bash
  until ! docker compose -f /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/docker-compose.yml ps --format '{{.Health}}' | grep -q starting; do :; done
  docker compose -f /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/docker-compose.yml ps
  ```

  Expected: `db`, `redis`, `mailpit`, `api`, `web` all show `healthy`; `caddy` shows `running` (it has no healthcheck). If any service shows `unhealthy`, inspect logs (e.g. `docker compose ... logs api`) before proceeding.

- [ ] **Step 3: Verify the API health endpoint through Caddy (HTTPS).** `-k` accepts the `tls internal` self-signed cert.

  ```bash
  curl -k -s https://localhost/api/health
  ```

  Expected: exactly `{"status":"ok"}`.

- [ ] **Step 4: Verify the web hello page is served through Caddy.**

  ```bash
  curl -k -s https://localhost/ | grep -o '<div id="root"></div>'
  ```

  Expected: prints `<div id="root"></div>` — confirming Vite's `index.html` is being proxied (React then mounts the HelloPage client-side).

- [ ] **Step 5: Confirm migrations were applied inside the running DB.**

  ```bash
  docker compose -f /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/docker-compose.yml exec -T db \
    psql -U app -d app -c "\dt"
  ```

  Expected: the table list includes `User`, `VerificationToken`, `AuditLog`, and `_prisma_migrations` (created by `prisma migrate deploy` in the api entrypoint).

- [ ] **Step 6: Tear the stack down (keep this clean for the next plan).**

  ```bash
  docker compose -f /Users/thammasornlueadtaharn/Desktop/project/authentication-flow/docker-compose.yml down
  ```

  Expected: all six containers stop and are removed; named volumes persist.

- [ ] **Step 7: Final commit (acceptance verified — no code change, record the milestone).**

  ```bash
  git -C /Users/thammasornlueadtaharn/Desktop/project/authentication-flow commit --allow-empty -m "chore: verify dev docker stack acceptance (health + hello page)"
  ```

---

## Done — Slice Complete

At this point: `docker compose up` brings all six services healthy; `curl -k https://localhost/api/health` returns `{"status":"ok"}`; `https://localhost` serves the React hello page; the full Prisma schema (User, VerificationToken, AuditLog, Role, TokenType) and its initial migration exist and are applied; both apps have a passing smoke test. Plan 01 can now build on `app.ts` (route mounting), `prisma.ts`, `redis/client.ts`, and the web router skeleton without adding new migrations.
