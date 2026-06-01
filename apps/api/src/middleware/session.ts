import session from "express-session";
import { RedisStore } from "connect-redis";
import { redis } from "../redis/client.js";
import { env } from "../config/env.js";
import { SESSION_PREFIX } from "../lib/sessionStore.js";

const SEVEN_DAYS_MS = 1000 * 60 * 60 * 24 * 7;

const store = new RedisStore({
  client: redis,
  prefix: SESSION_PREFIX,
  ttl: SEVEN_DAYS_MS / 1000, // connect-redis ttl is in SECONDS
});

export const sessionMiddleware = session({
  store,
  name: "__Host-sid",
  secret: env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true, // refresh idle TTL on every response
  cookie: {
    httpOnly: true,
    // mandatory for the __Host- prefix in dev/prod; relaxed under tests because
    // supertest speaks http and superagent will not resend Secure cookies.
    secure: env.NODE_ENV !== "test",
    sameSite: "lax",
    path: "/", // mandatory for __Host- prefix
    maxAge: SEVEN_DAYS_MS,
    // do NOT set `domain` — __Host- forbids it
  },
});
