import request from "supertest";
import type { Express } from "express";

const HTTPS = { "X-Forwarded-Proto": "https" } as const;

export type Agent = ReturnType<typeof request.agent>;

export interface CsrfAgent {
  agent: Agent;
  csrfToken: string;
}

export interface Creds {
  email: string;
  password: string;
}

// Returns a cookie-jar agent plus a CSRF token bound to that agent's session.
export async function makeCsrfAgent(app: Express): Promise<CsrfAgent> {
  const agent = request.agent(app);
  const res = await agent.get("/api/csrf").set(HTTPS).expect(200);
  return { agent, csrfToken: res.body.csrfToken as string };
}

// Logs an EXISTING user in on the given agent, then re-fetches CSRF — login regenerates the
// session id, which invalidates the pre-login token, so a fresh one must be bound to the new
// session before any further mutating request.
export async function signInExistingUser(
  app: Express,
  agent: Agent,
  creds: Creds,
): Promise<{ csrfToken: string }> {
  const csrfRes = await agent.get("/api/csrf").set(HTTPS).expect(200);
  await agent
    .post("/api/auth/login")
    .set(HTTPS)
    .set("x-csrf-token", csrfRes.body.csrfToken as string)
    .send(creds)
    .expect(200);
  // Re-fetch CSRF after the session regeneration.
  const fresh = await agent.get("/api/csrf").set(HTTPS).expect(200);
  return { csrfToken: fresh.body.csrfToken as string };
}

// Registers (active-immediately) + logs in, returning the authed agent, the user, and a FRESH
// CSRF token bound to the post-login (regenerated) session.
export async function signedInAgent(
  app: Express,
  creds: Creds,
): Promise<{
  agent: Agent;
  user: { id: string; email: string; role: string };
  csrfToken: string;
}> {
  const { agent, csrfToken } = await makeCsrfAgent(app);
  await agent
    .post("/api/auth/register")
    .set(HTTPS)
    .set("x-csrf-token", csrfToken)
    .send(creds)
    .expect(201);

  const loginCsrf = await agent.get("/api/csrf").set(HTTPS).expect(200);
  const loginRes = await agent
    .post("/api/auth/login")
    .set(HTTPS)
    .set("x-csrf-token", loginCsrf.body.csrfToken as string)
    .send(creds)
    .expect(200);

  // Re-fetch CSRF after login regenerates the session.
  const fresh = await agent.get("/api/csrf").set(HTTPS).expect(200);
  return {
    agent,
    user: loginRes.body.user,
    csrfToken: fresh.body.csrfToken as string,
  };
}

export { HTTPS };
