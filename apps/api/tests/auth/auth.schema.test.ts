import { describe, it, expect } from "vitest";
import { RegisterBody, LoginBody } from "../../src/modules/auth/auth.schema.js";

describe("auth schemas", () => {
  it("accepts a valid register body", () => {
    const r = RegisterBody.safeParse({ email: "a@b.com", password: "longenough1" });
    expect(r.success).toBe(true);
  });

  it("rejects a short password on register", () => {
    const r = RegisterBody.safeParse({ email: "a@b.com", password: "short" });
    expect(r.success).toBe(false);
  });

  it("rejects a malformed email on register", () => {
    const r = RegisterBody.safeParse({ email: "not-an-email", password: "longenough1" });
    expect(r.success).toBe(false);
  });

  it("accepts a valid login body", () => {
    const r = LoginBody.safeParse({ email: "a@b.com", password: "whatever" });
    expect(r.success).toBe(true);
  });
});
