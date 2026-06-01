import { describe, it, expect, afterAll } from "vitest";
import request from "supertest";
import { app } from "../src/app.js";
import { redis } from "../src/redis/client.js";

afterAll(async () => {
  await redis.quit();
});

describe("app", () => {
  it("GET /api/health returns ok with no auth", async () => {
    const res = await request(app).get("/api/health").expect(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  it("GET /api/csrf returns a token", async () => {
    const res = await request(app)
      .get("/api/csrf")
      .set("X-Forwarded-Proto", "https")
      .expect(200);
    expect(typeof res.body.csrfToken).toBe("string");
    expect(res.body.csrfToken.length).toBeGreaterThan(0);
  });
});
