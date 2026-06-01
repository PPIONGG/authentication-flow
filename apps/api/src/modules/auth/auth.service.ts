import { prisma } from "../../db/prisma.js";
import { hashPassword, verifyPassword } from "../../lib/password.js";
import { HttpError } from "../../middleware/errorHandler.js";
import type { User } from "../../generated/prisma/client.js";

// Constant argon2id PHC hash of a random throwaway secret. On an unknown email we still run
// argon2.verify against THIS so the response timing matches the wrong-password path
// (anti-enumeration). Plan 05's SECURITY.md anti-enumeration timing claim relies on this.
const DECOY_HASH =
  "$argon2id$v=19$m=65536,t=3,p=4$c29tZS1jb25zdGFudC1zYWx0$3hgQ8Yc1Yp0r2yq1m9C0e0c4Yk2vJpQ6m7nQyq1m9C";

export async function createUser(email: string, password: string): Promise<User> {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    // Generic conflict; route layer returns the same shape regardless of cause.
    throw new HttpError(409, "registration_failed");
  }
  const passwordHash = await hashPassword(password);
  return prisma.user.create({
    data: {
      email,
      passwordHash,
      emailVerifiedAt: new Date(), // Plan 01: active immediately
    },
  });
}

export async function verifyCredentials(
  email: string,
  password: string,
): Promise<User> {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    // Anti-enumeration: still run a verify against a constant decoy hash to equalize timing,
    // then throw the identical error whether or not the email exists.
    await verifyPassword(DECOY_HASH, password);
    throw new HttpError(401, "invalid_credentials");
  }
  const ok = await verifyPassword(user.passwordHash, password);
  if (!ok) {
    throw new HttpError(401, "invalid_credentials");
  }
  return user;
}
