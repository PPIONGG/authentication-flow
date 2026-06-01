import { describe, it, expect, afterAll } from "vitest";
import express from "express";
import cookieParser from "cookie-parser";
import request from "supertest";
import { sessionMiddleware } from "../../src/middleware/session.js";
import { csrfProtection, issueCsrfToken } from "../../src/middleware/csrf.js";
import { redis } from "../../src/redis/client.js";

function buildApp() {
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(cookieParser());
  app.use(sessionMiddleware);
  app.get("/csrf", (req, res) => {
    // Modify the session so express-session issues a stable __Host-sid cookie
    // (saveUninitialized:false won't send a cookie for an untouched session).
    req.session.bootstrappedAt = Date.now();
    res.json({ csrfToken: issueCsrfToken(req, res) });
  });
  app.use(csrfProtection);
  app.post("/mutate", (_req, res) => res.json({ ok: true }));
  return app;
}

afterAll(async () => {
  await redis.quit();
});

describe("csrf middleware", () => {
  it("rejects a POST without a csrf token (403)", async () => {
    const agent = request.agent(buildApp());
    await agent
      .post("/mutate")
      .set("X-Forwarded-Proto", "https")
      .send({})
      .expect(403);
  });

  it("accepts a POST that echoes the issued token in x-csrf-token", async () => {
    const agent = request.agent(buildApp());
    const csrfRes = await agent
      .get("/csrf")
      .set("X-Forwarded-Proto", "https")
      .expect(200);
    const token = csrfRes.body.csrfToken as string;
    await agent
      .post("/mutate")
      .set("X-Forwarded-Proto", "https")
      .set("x-csrf-token", token)
      .send({})
      .expect(200);
  });
});
