import { createApp } from "./app.ts";
import { prisma } from "./db.ts";
import { env } from "./env.ts";

const app = await createApp();

app.listen(env.PORT, () => {
  console.log("API listening on %s", env.APP_URL);
});

// Expired sessions and SAML bookkeeping rows are useless, so sweep them hourly.
setInterval(
  () => {
    const now = new Date();
    Promise.all([
      prisma.session.deleteMany({ where: { expiresAt: { lt: now } } }),
      prisma.samlCacheEntry.deleteMany({ where: { expiresAt: { lt: now } } }),
    ]).catch((err) => console.error("cleanup failed", err));
  },
  60 * 60 * 1000,
).unref();
