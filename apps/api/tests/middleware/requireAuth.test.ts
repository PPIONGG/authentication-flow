import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { requireAuth } from "../../src/middleware/requireAuth.js";

function buildApp(seedUserId?: string) {
  const app = express();
  app.use((req, _res, next) => {
    // Fake a session object for the test.
    (req as unknown as { session: { userId?: string } }).session = {
      userId: seedUserId,
    };
    next();
  });
  app.get("/protected", requireAuth, (_req, res) => res.json({ ok: true }));
  return app;
}

describe("requireAuth", () => {
  it("returns 401 when there is no session user", async () => {
    await request(buildApp(undefined)).get("/protected").expect(401);
  });

  it("calls next when a session user exists", async () => {
    await request(buildApp("u123")).get("/protected").expect(200, { ok: true });
  });
});
