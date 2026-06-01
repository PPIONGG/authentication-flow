import { beforeAll } from "vitest";
import { connectRedis } from "../src/redis/client.js";

// API integration tests talk to the real Redis + Postgres services (reachable
// inside the docker network). node-redis v6 does NOT auto-connect, so open the
// shared client once before each test file runs. connectRedis() is idempotent.
beforeAll(async () => {
  await connectRedis();
});
