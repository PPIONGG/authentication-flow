import { describe, it, expect, beforeEach, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { rateLimit } from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../../src/redis/client.js";

// A dedicated tiny limiter proves the express-rate-limit + rate-limit-redis wiring
// returns 429 after the limit. The production authLimiter uses the same mechanism but
// a higher limit in tests so multi-step integration flows are not throttled.
function buildApp() {
  const limiter = rateLimit({
    windowMs: 60_000,
    limit: 2,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    store: new RedisStore({
      prefix: "rl:test:",
      sendCommand: (...args: string[]) => redis.sendCommand(args),
    }),
  });
  const app = express();
  app.use("/auth", limiter);
  app.post("/auth/login", (_req, res) => res.json({ ok: true }));
  return app;
}

beforeEach(async () => {
  await redis.flushDb();
});

afterAll(async () => {
  await redis.quit();
});

describe("rate limiter", () => {
  it("returns 429 after exceeding the limit", async () => {
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
