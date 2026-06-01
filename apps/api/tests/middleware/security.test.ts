import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { securityMiddleware } from "../../src/middleware/security.js";

function buildApp() {
  const app = express();
  app.use(securityMiddleware);
  app.get("/x", (_req, res) => res.json({ ok: true }));
  return app;
}

describe("security middleware", () => {
  it("sets helmet security headers (HSTS + CSP)", async () => {
    const res = await request(buildApp()).get("/x").expect(200);
    expect(res.headers["strict-transport-security"]).toContain("max-age=");
    expect(res.headers["content-security-policy"]).toContain("default-src 'self'");
  });

  it("reflects the configured origin with credentials for allowed origin", async () => {
    const res = await request(buildApp())
      .get("/x")
      .set("Origin", "https://localhost")
      .expect(200);
    expect(res.headers["access-control-allow-origin"]).toBe("https://localhost");
    expect(res.headers["access-control-allow-credentials"]).toBe("true");
  });
});
