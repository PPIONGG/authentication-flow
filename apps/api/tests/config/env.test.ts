import { describe, it, expect } from "vitest";

describe("env", () => {
  it("parses a valid environment", async () => {
    const { parseEnv } = await import("../../src/config/env.js");
    const parsed = parseEnv({
      DATABASE_URL: "postgres://app:app@db:5432/app",
      REDIS_URL: "redis://redis:6379",
      SESSION_SECRET: "x".repeat(32),
      CSRF_SECRET: "y".repeat(32),
      SMTP_HOST: "mailpit",
      SMTP_PORT: "1025",
      MAIL_FROM: "auth@example.com",
      APP_URL: "https://localhost",
      NODE_ENV: "test",
    });
    expect(parsed.SMTP_PORT).toBe(1025);
    expect(parsed.APP_URL).toBe("https://localhost");
  });

  it("throws when SESSION_SECRET is too short", async () => {
    const { parseEnv } = await import("../../src/config/env.js");
    expect(() =>
      parseEnv({
        DATABASE_URL: "postgres://app:app@db:5432/app",
        REDIS_URL: "redis://redis:6379",
        SESSION_SECRET: "short",
        CSRF_SECRET: "y".repeat(32),
        SMTP_HOST: "mailpit",
        SMTP_PORT: "1025",
        MAIL_FROM: "auth@example.com",
        APP_URL: "https://localhost",
        NODE_ENV: "test",
      }),
    ).toThrow();
  });
});
