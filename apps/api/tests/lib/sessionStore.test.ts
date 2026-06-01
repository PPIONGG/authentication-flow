import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { redis } from "../../src/redis/client.js";
import {
  SESSION_PREFIX,
  addUserSession,
  removeUserSession,
  destroyAllUserSessions,
} from "../../src/lib/sessionStore.js";

beforeEach(async () => {
  await redis.flushDb();
});

afterAll(async () => {
  await redis.quit();
});

describe("sessionStore", () => {
  it("indexes a session id under the user set", async () => {
    await addUserSession("user1", "sidA");
    const members = await redis.sMembers("user_sessions:user1");
    expect(members).toEqual(["sidA"]);
  });

  it("de-indexes a single session id", async () => {
    await addUserSession("user1", "sidA");
    await addUserSession("user1", "sidB");
    await removeUserSession("user1", "sidA");
    const members = await redis.sMembers("user_sessions:user1");
    expect(members).toEqual(["sidB"]);
  });

  it("destroys every session blob and clears the set", async () => {
    await redis.set(`${SESSION_PREFIX}sidA`, "blobA");
    await redis.set(`${SESSION_PREFIX}sidB`, "blobB");
    await addUserSession("user1", "sidA");
    await addUserSession("user1", "sidB");

    await destroyAllUserSessions("user1");

    expect(await redis.get(`${SESSION_PREFIX}sidA`)).toBeNull();
    expect(await redis.get(`${SESSION_PREFIX}sidB`)).toBeNull();
    expect(await redis.exists("user_sessions:user1")).toBe(0);
  });
});
