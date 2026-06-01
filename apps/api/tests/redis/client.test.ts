import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { redis, connectRedis } from "../../src/redis/client.js";

describe("redis client", () => {
  beforeAll(async () => {
    await connectRedis();
  });

  afterAll(async () => {
    await redis.quit();
  });

  it("is connected and responds to PING", async () => {
    const pong = await redis.ping();
    expect(pong).toBe("PONG");
  });

  it("can set and get a key", async () => {
    await redis.set("test:key", "hello");
    const value = await redis.get("test:key");
    expect(value).toBe("hello");
    await redis.del("test:key");
  });
});
