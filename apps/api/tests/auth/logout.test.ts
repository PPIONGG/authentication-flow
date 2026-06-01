import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { app } from "../../src/app.js";
import { redis } from "../../src/redis/client.js";
import { resetState } from "../helpers/db.js";
import { signedInAgent, HTTPS } from "../helpers/agent.js";

beforeEach(resetState);
afterAll(async () => {
  await redis.quit();
});

describe("POST /api/auth/logout", () => {
  it("destroys the session, de-indexes it, returns 204", async () => {
    // signedInAgent registers + logs in and returns a FRESH csrf token bound to the
    // post-login (regenerated) session.
    const { agent, csrfToken, user } = await signedInAgent(app, {
      email: "out@user.com",
      password: "longenough1",
    });

    await agent
      .post("/api/auth/logout")
      .set(HTTPS)
      .set("x-csrf-token", csrfToken)
      .expect(204);

    // /me is now unauthenticated for this agent.
    await agent.get("/api/auth/me").set(HTTPS).expect(401);

    // Per-user session set is empty.
    const members = await redis.sMembers(`user_sessions:${user.id}`);
    expect(members.length).toBe(0);
  });
});
