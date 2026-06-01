import { app } from "./app.js";
import { env } from "./config/env.js";
import { connectRedis } from "./redis/client.js";

async function main(): Promise<void> {
  await connectRedis();
  app.listen(env.PORT, () => {
    console.log(`[api] listening on http://0.0.0.0:${env.PORT}`);
  });
}

main().catch((err) => {
  console.error("[api] fatal startup error:", err);
  process.exit(1);
});
