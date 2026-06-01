import { redis } from "../redis/client.js";

// Must match the connect-redis store prefix configured in middleware/session.ts
export const SESSION_PREFIX = "app:sess:";

function userSetKey(userId: string): string {
  return `user_sessions:${userId}`;
}

export async function addUserSession(
  userId: string,
  sessionId: string,
): Promise<void> {
  await redis.sAdd(userSetKey(userId), sessionId);
}

export async function removeUserSession(
  userId: string,
  sessionId: string,
): Promise<void> {
  await redis.sRem(userSetKey(userId), sessionId);
}

export async function destroyAllUserSessions(userId: string): Promise<void> {
  const key = userSetKey(userId);
  const sessionIds = await redis.sMembers(key);
  if (sessionIds.length > 0) {
    await redis.del(sessionIds.map((sid) => `${SESSION_PREFIX}${sid}`));
  }
  await redis.del(key);
}
