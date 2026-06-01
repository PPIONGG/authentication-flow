import { createClient } from "redis";
import { env } from "../config/env.js";

export const redis = createClient({ url: env.REDIS_URL });

redis.on("error", (err) => {
  console.error("[redis] client error:", err);
});

let connected = false;

export async function connectRedis(): Promise<void> {
  if (connected) return;
  await redis.connect();
  connected = true;
}

export async function disconnectRedis(): Promise<void> {
  if (!connected) return;
  await redis.quit();
  connected = false;
}
