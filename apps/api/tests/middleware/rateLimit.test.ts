import { describe, it, expect, beforeEach, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { authLimiter } from "../../src/middleware/rateLimit.js";
import { redis } from "../../src/redis/client.js";

function buildApp() {
  const app = express();
  app.use("/auth", authLimiter);
  app.post("/auth/login", (_req, res) => res.json({ ok: true }));
  return app;
}

beforeEach(async () => {
  await redis.flushDb();
});

afterAll(async () => {
  await redis.quit();
});

describe("authLimiter", () => {
  it("returns 429 after exceeding the auth limit", async () => {
    const app = buildApp();
    for (let i = 0; i < 10; i++) {
      const res = await request(app).post("/auth/login").send({});
      if (res.status === 429) {
        expect(res.status).toBe(429);
        return;
      }
    }
    throw new Error("expected a 429 within 10 requests");
  });
});
