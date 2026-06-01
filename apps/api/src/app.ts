import express from "express";
import helmet from "helmet";
import cors from "cors";
import cookieParser from "cookie-parser";
import { env } from "./config/env.js";

export const app = express();

// Behind Caddy (reverse proxy): trust the proxy so Secure cookies are emitted.
app.set("trust proxy", 1);

// --- Security headers (helmet: CSP + HSTS) ---
app.use(helmet());

// --- CORS locked to the single origin, credentials enabled ---
app.use(
  cors({
    origin: env.APP_URL,
    credentials: true,
  }),
);

// --- Body + cookie parsing (cookie-parser must precede csrf in later plans) ---
app.use(express.json());
app.use(cookieParser());

// === API routes are mounted under /api ===
const api = express.Router();

// Public health check (no auth) — Plan 00.
api.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

// Future routers mounted here in later plans:
//   api.use("/auth", authRoutes)
//   api.use("/account", accountRoutes)
//   api.use("/admin", adminRoutes)
//   api.get("/csrf", ...)

app.use("/api", api);

// Central error handler is added in a later plan (errorHandler.ts).
