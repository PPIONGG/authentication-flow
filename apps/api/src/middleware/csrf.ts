import type { Request, Response } from "express";
import { doubleCsrf } from "csrf-csrf";
import { env } from "../config/env.js";

const { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError } =
  doubleCsrf({
    getSecret: () => env.CSRF_SECRET,
    getSessionIdentifier: (req: Request) => req.session.id,
    cookieName: "x-csrf-token",
    cookieOptions: {
      sameSite: "lax",
      secure: env.NODE_ENV !== "test", // see session.ts: relaxed under http tests
      httpOnly: false, // SPA must read it to echo in the header
      path: "/",
    },
    getCsrfTokenFromRequest: (req: Request) =>
      req.headers["x-csrf-token"] as string | undefined,
  });

export const csrfProtection = doubleCsrfProtection;
export const csrfInvalidError = invalidCsrfTokenError;

export function issueCsrfToken(req: Request, res: Response): string {
  return generateCsrfToken(req, res);
}
