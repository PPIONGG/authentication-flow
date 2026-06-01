import type { Request, Response, NextFunction } from "express";
import { csrfInvalidError } from "./csrf.js";

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
  ) {
    super(code);
    this.name = "HttpError";
  }
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction,
): void {
  if (err === csrfInvalidError) {
    res.status(403).json({ error: "invalid_csrf_token" });
    return;
  }
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code });
    return;
  }
  // eslint-disable-next-line no-console
  console.error("[errorHandler] unexpected error", err);
  res.status(500).json({ error: "internal_error" });
}
