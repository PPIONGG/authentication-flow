import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { writeAudit } from "../../src/lib/audit.js";
import { prisma } from "../../src/db/prisma.js";

beforeEach(async () => {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
  );
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe("writeAudit", () => {
  it("records an event with no user (e.g. login_fail)", async () => {
    await writeAudit({ event: "login_fail", ip: "127.0.0.1", userAgent: "vitest" });
    const rows = await prisma.auditLog.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0].event).toBe("login_fail");
    expect(rows[0].userId).toBeNull();
  });

  it("records an event tied to a user", async () => {
    const user = await prisma.user.create({
      data: { email: "a@b.com", passwordHash: "x", emailVerifiedAt: new Date() },
    });
    await writeAudit({ userId: user.id, event: "login_success" });
    const rows = await prisma.auditLog.findMany();
    expect(rows[0].userId).toBe(user.id);
    expect(rows[0].event).toBe("login_success");
  });
});
