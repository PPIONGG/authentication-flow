import { prisma } from "../db/prisma.js";

// Canonical audit event union (CONTRACTS). Used by Plans 01–04.
export type AuditEvent =
  | "register"
  | "login_success"
  | "login_fail"
  | "logout"
  | "logout_all"
  | "password_reset"
  | "password_change"
  | "email_change"
  | "email_verified";

export interface AuditInput {
  event: AuditEvent;
  userId?: string;
  ip?: string;
  userAgent?: string;
}

export async function writeAudit(input: AuditInput): Promise<void> {
  await prisma.auditLog.create({
    data: {
      userId: input.userId ?? null,
      event: input.event,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
    },
  });
}
