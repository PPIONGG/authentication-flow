import { describe, it, expect } from "vitest";
import { hashPassword, verifyPassword } from "../../src/lib/password.js";

describe("password", () => {
  it("hashes to a PHC argon2id string distinct from the plaintext", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).not.toBe("correct horse battery staple");
    expect(hash.startsWith("$argon2id$")).toBe(true);
  });

  it("verifies a correct password", async () => {
    const hash = await hashPassword("s3cret-password");
    expect(await verifyPassword(hash, "s3cret-password")).toBe(true);
  });

  it("rejects an incorrect password", async () => {
    const hash = await hashPassword("s3cret-password");
    expect(await verifyPassword(hash, "wrong-password")).toBe(false);
  });
});
