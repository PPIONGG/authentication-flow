import { describe, it, expect, beforeEach, afterAll } from "vitest";
import request from "supertest";
import { app } from "../../src/app.js";
import { redis } from "../../src/redis/client.js";
import { resetState } from "../helpers/db.js";
import { makeCsrfAgent, HTTPS } from "../helpers/agent.js";

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe("GET /api/auth/me", () => {
  it("returns 401 when unauthenticated", async () => {
    const res = await request(app).get("/api/auth/me").set(HTTPS).expect(401);
    expect(res.body).toEqual({ error: "unauthenticated" });
  });

  it("returns the user when authenticated", async () => {
    const reg = await makeCsrfAgent(app);
    await reg.agent
      .post("/api/auth/register")
      .set(HTTPS)
      .set("x-csrf-token", reg.csrfToken)
      .send({ email: "me@user.com", password: "longenough1" })
      .expect(201);

    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post("/api/auth/login")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "me@user.com", password: "longenough1" })
      .expect(200);

    const res = await agent.get("/api/auth/me").set(HTTPS).expect(200);
    expect(res.body.user.email).toBe("me@user.com");
    expect(res.body.user.role).toBe("USER");
  });
});
