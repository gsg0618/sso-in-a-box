import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cookieParser from "cookie-parser";
import express, { type Express } from "express";
import { env } from "./env.ts";
import { errorHandler, HttpError } from "./http.ts";
import { authRouter } from "./routes/auth.ts";
import { membersRouter } from "./routes/members.ts";
import { ssoRouter } from "./routes/sso.ts";
import { ssoAdminRouter } from "./routes/ssoAdmin.ts";
import { tasksRouter } from "./routes/tasks.ts";

export async function createApp(): Promise<Express> {
  const app = express();
  app.disable("x-powered-by");
  if (env.isProd) app.set("trust proxy", 1);

  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "same-origin");
    next();
  });
  app.use(cookieParser());

  // CSRF defence for the JSON API: the session cookie is SameSite=Lax, and on top of that any
  // state-changing request that names an Origin must come from our own web app.
  const allowedOrigins = new Set([new URL(env.WEB_URL).origin, new URL(env.APP_URL).origin]);
  app.use("/api", (req, _res, next) => {
    const safe = req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS";
    // The SAML ACS is the one endpoint an IdP posts to cross-site. It uses no session cookie:
    // it is authenticated by the signed assertion instead.
    const isAcs = req.method === "POST" && /^\/sso\/[^/]+\/saml\/acs$/.test(req.path);
    const origin = req.headers.origin;
    if (!safe && !isAcs && origin && !allowedOrigins.has(origin)) {
      return next(new HttpError(403, "bad_origin", "Cross-site request blocked."));
    }
    next();
  });

  app.get("/api/health", (_req, res) => {
    res.json({ ok: true });
  });

  // Registered before the JSON parser: these routes take redirects and form posts, not JSON.
  app.use("/api/sso", ssoRouter);

  app.use("/api", express.json({ limit: "100kb" }));
  app.use("/api/auth", authRouter);
  app.use("/api/tasks", tasksRouter);
  app.use("/api/members", membersRouter);
  app.use("/api/admin/sso", ssoAdminRouter);

  if (env.MOCK_IDP) {
    const { mockIdpRouter } = await import("./dev/mockIdp.ts");
    app.use("/mock-idp", mockIdpRouter());
    console.warn("[dev] Mock identity provider mounted at %s/mock-idp", env.APP_URL);
  }

  app.use("/api", (_req, _res, next) => next(new HttpError(404, "not_found", "No such endpoint.")));

  // In production the built web app is served from the same origin as the API.
  const webDist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../web/dist");
  if (existsSync(webDist)) {
    app.use(express.static(webDist));
    app.get("*", (_req, res) => res.sendFile(path.join(webDist, "index.html")));
  }

  app.use(errorHandler);
  return app;
}
