import { type RequestHandler } from "express";
import helmet from "helmet";
import cors from "cors";
import { env } from "../config/env.js";

const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "data:"],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'self'"],
    },
  },
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
});

const corsMiddleware = cors({
  origin: env.APP_URL,
  credentials: true,
});

export const securityMiddleware: RequestHandler[] = [
  helmetMiddleware,
  corsMiddleware,
];
