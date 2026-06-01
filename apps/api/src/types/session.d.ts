import "express-session";
import type { Role } from "../generated/prisma/client.js";

declare module "express-session" {
  interface SessionData {
    userId?: string;
    role?: Role;
    // Set when issuing a CSRF token pre-login, so the (otherwise-empty) session
    // is persisted and a stable __Host-sid cookie is sent (csrf binds to its id).
    bootstrappedAt?: number;
  }
}
