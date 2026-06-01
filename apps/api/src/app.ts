// apps/api/src/app.ts  (Plan 00 created the skeleton; Plan 01 MODIFIES it)
import express from "express";
import cookieParser from "cookie-parser";
import { securityMiddleware } from "./middleware/security.js";
import { sessionMiddleware } from "./middleware/session.js";
import { csrfProtection, issueCsrfToken } from "./middleware/csrf.js";
import { globalLimiter, authLimiter } from "./middleware/rateLimit.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { authRouter } from "./modules/auth/auth.routes.js";

export const app = express();

// Behind Caddy (TLS terminator) so Secure cookies + correct req.ip work.
app.set("trust proxy", 1);

app.use(securityMiddleware);
app.use(express.json());
app.use(cookieParser());
app.use(sessionMiddleware);
app.use(globalLimiter);

// Public, no auth, no csrf.
app.get("/api/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

// Issue/return the CSRF token BEFORE csrf protection so the SPA can bootstrap.
// Modifying the session forces a stable __Host-sid cookie (saveUninitialized:false
// won't send a cookie for an untouched session); csrf binds the token to req.session.id.
app.get("/api/csrf", (req, res) => {
  req.session.bootstrappedAt = Date.now();
  res.status(200).json({ csrfToken: issueCsrfToken(req, res) });
});

// All mutating routes below are CSRF-protected.
app.use(csrfProtection);

// Tighter rate limit on auth endpoints.
app.use("/api/auth", authLimiter, authRouter);

// Central error handler LAST.
app.use(errorHandler);
