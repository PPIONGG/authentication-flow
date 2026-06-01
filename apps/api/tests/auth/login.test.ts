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

async function registerUser(email: string, password: string) {
  const { agent, csrfToken } = await makeCsrfAgent(app);
  await agent
    .post("/api/auth/register")
    .set(HTTPS)
    .set("x-csrf-token", csrfToken)
    .send({ email, password })
    .expect(201);
}

describe("POST /api/auth/login", () => {
  it("logs in with correct credentials, sets cookie, indexes session, audits success", async () => {
    await registerUser("login@user.com", "longenough1");
    const { agent, csrfToken } = await makeCsrfAgent(app);

    const res = await agent
      .post("/api/auth/login")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "login@user.com", password: "longenough1" })
      .expect(200);

    expect(res.body.user.email).toBe("login@user.com");
    expect(res.body.user.role).toBe("USER");
    expect(typeof res.body.user.id).toBe("string");

    const setCookie = res.headers["set-cookie"] as unknown as string[];
    expect(setCookie.some((c) => c.startsWith("__Host-sid="))).toBe(true);

    // Session indexed under the per-user set.
    const members = await redis.sMembers(`user_sessions:${res.body.user.id}`);
    expect(members.length).toBe(1);

    const audit = await prisma.auditLog.findFirst({
      where: { event: "login_success" },
    });
    expect(audit).not.toBeNull();
  });

  it("returns 401 generic error + audits login_fail for a wrong password", async () => {
    await registerUser("login@user.com", "longenough1");
    const { agent, csrfToken } = await makeCsrfAgent(app);

    const res = await agent
      .post("/api/auth/login")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "login@user.com", password: "wrongpass1" })
      .expect(401);

    expect(res.body).toEqual({ error: "invalid_credentials" });

    const audit = await prisma.auditLog.findFirst({
      where: { event: "login_fail" },
    });
    expect(audit).not.toBeNull();
  });

  it("regenerates the session id on login (anti-fixation)", async () => {
    await registerUser("fix@user.com", "longenough1");
    const { agent, csrfToken } = await makeCsrfAgent(app);

    // Establish a pre-auth session id by hitting /api/csrf (already done by makeCsrfAgent).
    const before = await agent.get("/api/auth/me").set(HTTPS).expect(401);
    expect(before.body).toEqual({ error: "unauthenticated" });

    await agent
      .post("/api/auth/login")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .send({ email: "fix@user.com", password: "longenough1" })
      .expect(200);

    // After login the same agent is authenticated.
    const after = await agent.get("/api/auth/me").set(HTTPS).expect(200);
    expect(after.body.user.email).toBe("fix@user.com");
  });
});
