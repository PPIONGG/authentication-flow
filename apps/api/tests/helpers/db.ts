import { prisma } from "../../src/db/prisma.js";
import { redis } from "../../src/redis/client.js";

export async function resetState(): Promise<void> {
  await prisma.$executeRawUnsafe(
    'TRUNCATE TABLE "AuditLog","VerificationToken","User" RESTART IDENTITY CASCADE',
  );
  await redis.flushDb();
}
