import { describe, it, expect } from "vitest";
import { prisma } from "../../src/db/prisma.js";

describe("prisma client", () => {
  it("runs a trivial query against the test database", async () => {
    const rows = await prisma.$queryRaw<{ one: number }[]>`SELECT 1 as one`;
    expect(rows[0].one).toBe(1);
  });

  it("exposes the user model", () => {
    expect(typeof prisma.user.findUnique).toBe("function");
  });
});
