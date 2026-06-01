import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { app } from "../../src/app.js";
import { redis } from "../../src/redis/client.js";
import { resetState } from "../helpers/db.js";
import { makeCsrfAgent, HTTPS } from "../helpers/agent.js";

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe("login enumeration parity", () => {
  it("returns identical status and body for unknown email vs wrong password", async () => {
    // Register a known user.
    const reg = await makeCsrfAgent(app);
    await reg.agent
      .post("/api/auth/register")
      .set(HTTPS)
      .set("x-csrf-token", reg.csrfToken)
      .send({ email: "known@user.com", password: "longenough1" })
      .expect(201);

    const a = await makeCsrfAgent(app);
    const wrongPassword = await a.agent
      .post("/api/auth/login")
      .set(HTTPS)
      .set("x-csrf-token", a.csrfToken)
      .send({ email: "known@user.com", password: "totallywrong1" });

    const b = await makeCsrfAgent(app);
    const unknownEmail = await b.agent
      .post("/api/auth/login")
      .set(HTTPS)
      .set("x-csrf-token", b.csrfToken)
      .send({ email: "ghost@user.com", password: "totallywrong1" });

    expect(wrongPassword.status).toBe(unknownEmail.status);
    expect(wrongPassword.status).toBe(401);
    expect(wrongPassword.body).toEqual(unknownEmail.body);
    expect(wrongPassword.body).toEqual({ error: "invalid_credentials" });
  });
});
