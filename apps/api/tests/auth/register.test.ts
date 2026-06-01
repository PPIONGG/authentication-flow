import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { app } from "../../src/app.js";
import { prisma } from "../../src/db/prisma.js";
import { redis } from "../../src/redis/client.js";
import { resetState } from "../helpers/db.js";
import { makeCsrfAgent, HTTPS } from "../helpers/agent.js";

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe("POST /api/auth/register", () => {
  it("creates an active user and returns 201 {ok:true}", async () => {
    const { agent, csrfToken } = await makeCsrfAgent(app);
    const res = await agent
      .post("/api/auth/register")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "reg@user.com", password: "longenough1" })
      .expect(201);
    expect(res.body).toEqual({ ok: true });

    const user = await prisma.user.findUnique({
      where: { email: "reg@user.com" },
    });
    expect(user).not.toBeNull();
    expect(user!.emailVerifiedAt).not.toBeNull();

    const audit = await prisma.auditLog.findFirst({
      where: { event: "register" },
    });
    expect(audit).not.toBeNull();
  });

  it("rejects an invalid email with 400", async () => {
    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post("/api/auth/register")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "nope", password: "longenough1" })
      .expect(400);
  });

  it("rejects a duplicate email with 409 generic error", async () => {
    const { agent, csrfToken } = await makeCsrfAgent(app);
    await agent
      .post("/api/auth/register")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "dupe@user.com", password: "longenough1" })
      .expect(201);

    const second = await makeCsrfAgent(app);
    const res = await second.agent
      .post("/api/auth/register")
      .set(HTTPS)
      .set("x-csrf-token", second.csrfToken)
      .send({ email: "dupe@user.com", password: "anotherlong1" })
      .expect(409);
    expect(res.body).toEqual({ error: "registration_failed" });
  });

  it("rejects a POST with no csrf token (403)", async () => {
    await import("supertest").then(({ default: request }) =>
      request(app)
        .post("/api/auth/register")
        .set(HTTPS)
        .send({ email: "x@y.com", password: "longenough1" })
        .expect(403),
    );
  });
});
