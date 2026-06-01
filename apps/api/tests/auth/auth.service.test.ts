import { describe, it, expect, beforeEach, afterAll } from "vitest";
import {
  createUser,
  verifyCredentials,
} from "../../src/modules/auth/auth.service.js";
import { HttpError } from "../../src/middleware/errorHandler.js";
import { prisma } from "../../src/db/prisma.js";

beforeEach(async () => {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
  );
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe("createUser", () => {
  it("creates an active (verified) user with a hashed password", async () => {
    const user = await createUser("new@user.com", "longenough1");
    expect(user.email).toBe("new@user.com");
    expect(user.emailVerifiedAt).not.toBeNull();
    expect(user.passwordHash).not.toBe("longenough1");
    expect(user.role).toBe("USER");
  });

  it("throws a generic 409 when the email already exists", async () => {
    await createUser("dupe@user.com", "longenough1");
    await expect(
      createUser("dupe@user.com", "anotherlong1"),
    ).rejects.toMatchObject({ status: 409 });
  });
});

describe("verifyCredentials", () => {
  it("returns the user for correct credentials", async () => {
    await createUser("login@user.com", "longenough1");
    const user = await verifyCredentials("login@user.com", "longenough1");
    expect(user.email).toBe("login@user.com");
  });

  it("throws a generic 401 for a wrong password", async () => {
    await createUser("login@user.com", "longenough1");
    await expect(
      verifyCredentials("login@user.com", "wrongpass1"),
    ).rejects.toBeInstanceOf(HttpError);
    await expect(
      verifyCredentials("login@user.com", "wrongpass1"),
    ).rejects.toMatchObject({ status: 401 });
  });

  it("throws a generic 401 for an unknown email (same as wrong password)", async () => {
    await expect(
      verifyCredentials("ghost@user.com", "whatever1"),
    ).rejects.toMatchObject({ status: 401 });
  });
});
