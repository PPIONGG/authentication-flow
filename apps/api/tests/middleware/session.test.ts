import { describe, it, expect, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { sessionMiddleware } from "../../src/middleware/session.js";
import { redis } from "../../src/redis/client.js";

function buildApp() {
  const app = express();
  app.set("trust proxy", 1);
  app.use(sessionMiddleware);
  app.post("/set", (req, res) => {
    req.session.userId = "u123";
    res.json({ ok: true });
  });
  app.get("/get", (req, res) => {
    res.json({ userId: req.session.userId ?? null });
  });
  return app;
}

afterAll(async () => {
  await redis.quit();
});

describe("sessionMiddleware", () => {
  it("issues a __Host-sid cookie and persists session data in redis", async () => {
    const app = buildApp();
    const agent = request.agent(app);

    const setRes = await agent
      .post("/set")
      .set("X-Forwarded-Proto", "https")
      .expect(200);
    const cookies = setRes.headers["set-cookie"];
    expect(cookies.some((c: string) => c.startsWith("__Host-sid="))).toBe(true);

    const getRes = await agent
      .get("/get")
      .set("X-Forwarded-Proto", "https")
      .expect(200);
    expect(getRes.body.userId).toBe("u123");
  });
});
