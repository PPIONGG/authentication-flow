import "dotenv/config";
import { z } from "zod";

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  REDIS_URL: z.string().min(1),
  SESSION_SECRET: z.string().min(32),
  CSRF_SECRET: z.string().min(32),
  SMTP_HOST: z.string().min(1),
  SMTP_PORT: z.coerce.number().int().positive(),
  MAIL_FROM: z.email(),
  APP_URL: z.url(),
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
});

export type Env = z.infer<typeof EnvSchema>;

/**
 * Parse + validate an environment source. Pure and testable: throws on invalid
 * input rather than exiting, so unit tests can assert failures. The module-level
 * `env` below calls it once against process.env at startup.
 */
export function parseEnv(source: NodeJS.ProcessEnv = process.env): Readonly<Env> {
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    throw new Error(
      "Invalid environment configuration:\n" + z.prettifyError(parsed.error),
    );
  }
  return Object.freeze(parsed.data);
}

export const env = parseEnv();
