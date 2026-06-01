import { rateLimit } from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
import { redis } from "../redis/client.js";
import { env } from "../config/env.js";

const isTest = env.NODE_ENV === "test";

export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 1000,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  store: new RedisStore({
    prefix: "rl:global:",
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
});

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  // High in tests so multi-step integration flows (register→login→logout→me) are not
  // throttled; the rate-limit mechanism itself is covered by a dedicated unit test.
  limit: isTest ? 100 : 10,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  store: new RedisStore({
    prefix: "rl:auth:",
    sendCommand: (...args: string[]) => redis.sendCommand(args),
  }),
});
