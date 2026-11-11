import express, { Router, type Response } from "express";
import rateLimit from "express-rate-limit";
import { prisma } from "../db.ts";
import { env } from "../env.ts";
import { ah } from "../http.ts";
import { createSession } from "../session.ts";
import { oidcCallback, oidcStart, type OidcTransaction } from "../sso/oidc.ts";
import { findOrProvisionSsoUser, SsoError } from "../sso/provision.ts";
import { samlCallback, samlMetadata, samlStart } from "../sso/saml.ts";

/**
 * Public SSO endpoints. Each tenant has its own URLs (/api/sso/<workspace>/...), so the workspace
 * a login belongs to comes from the URL the customer registered in their IdP, never from the
 * assertion itself.
 */
export const ssoRouter = Router();

const TX_COOKIE = "oidc_tx";
const TX_COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: env.APP_URL.startsWith("https://"),
  path: "/api/sso",
};

ssoRouter.use(
  rateLimit({ windowMs: 15 * 60 * 1000, limit: env.NODE_ENV === "test" ? 10_000 : 100, standardHeaders: true, legacyHeaders: false }),
);

async function loadConnection(slug: string) {
  const org = await prisma.organization.findUnique({ where: { slug: slug.toLowerCase() }, include: { ssoConnection: true } });
  const conn = org?.ssoConnection;
  if (!org || !conn || !conn.enabled) throw new SsoError("not_configured", "Single sign-on is not set up for this workspace.");
  return { org, conn };
}

/** SSO runs as full-page redirects, so failures go back to the login page with a short code. */
function fail(res: Response, slug: string, err: unknown) {
  const code = err instanceof SsoError ? err.code : "sso_failed";
  if (env.NODE_ENV !== "test" || process.env.SSO_DEBUG) console.warn("[sso] login failed for workspace %s: %s", slug, err instanceof Error ? err.message : err);
  if (!(err instanceof SsoError)) console.error(err);
  const params = new URLSearchParams({ sso_error: code, workspace: slug });
  res.redirect(env.WEB_URL + "/login?" + params.toString());
}

ssoRouter.get(
  "/:slug/start",
  ah(async (req, res) => {
    const slug = req.params.slug!;
    try {
      const { org, conn } = await loadConnection(slug);
      if (conn.type === "OIDC") {
        const { url, tx } = await oidcStart(conn, org.slug);
        res.cookie(TX_COOKIE, JSON.stringify(tx), { ...TX_COOKIE_OPTS, maxAge: 10 * 60 * 1000 });
        return res.redirect(url);
      }
      return res.redirect(await samlStart(conn, org.slug));
    } catch (err) {
      fail(res, slug, err);
    }
  }),
);

ssoRouter.get(
  "/:slug/oidc/callback",
  ah(async (req, res) => {
    const slug = req.params.slug!;
    try {
      const { org, conn } = await loadConnection(slug);
      if (conn.type !== "OIDC") throw new SsoError("not_configured", "This workspace does not use OIDC.");

      let tx: OidcTransaction | undefined;
      try {
        tx = JSON.parse(req.cookies?.[TX_COOKIE] ?? "");
      } catch {
        tx = undefined;
      }
      res.clearCookie(TX_COOKIE, TX_COOKIE_OPTS);
      // The cookie proves this browser started the login, for this workspace.
      if (!tx || tx.slug !== org.slug || !tx.state || !tx.nonce || !tx.codeVerifier) {
        throw new SsoError("session_expired", "The sign-in attempt expired or was started in another browser.");
      }

      const query = req.originalUrl.includes("?") ? req.originalUrl.slice(req.originalUrl.indexOf("?")) : "";
      const identity = await oidcCallback(conn, org.slug, query, tx);
      const user = await findOrProvisionSsoUser(org.id, identity);
      await createSession(res, user, "oidc");
      res.redirect(env.WEB_URL + "/");
    } catch (err) {
      fail(res, slug, err);
    }
  }),
);

/** SAML Assertion Consumer Service. The IdP makes the browser POST the signed response here. */
ssoRouter.post(
  "/:slug/saml/acs",
  express.urlencoded({ extended: false, limit: "512kb" }),
  ah(async (req, res) => {
    const slug = req.params.slug!;
    try {
      const { org, conn } = await loadConnection(slug);
      if (conn.type !== "SAML") throw new SsoError("not_configured", "This workspace does not use SAML.");
      const samlResponse = req.body?.SAMLResponse;
      if (typeof samlResponse !== "string" || !samlResponse) {
        throw new SsoError("saml_validation_failed", "No SAMLResponse was posted.");
      }
      const identity = await samlCallback(conn, org.slug, samlResponse);
      const user = await findOrProvisionSsoUser(org.id, identity);
      await createSession(res, user, "saml");
      res.redirect(env.WEB_URL + "/");
    } catch (err) {
      fail(res, slug, err);
    }
  }),
);

/** SP metadata XML that a customer can import into their IdP instead of typing the URLs. */
ssoRouter.get(
  "/:slug/saml/metadata",
  ah(async (req, res) => {
    const org = await prisma.organization.findUnique({ where: { slug: req.params.slug!.toLowerCase() }, include: { ssoConnection: true } });
    if (!org) return res.status(404).type("text/plain").send("Unknown workspace");
    res.type("application/xml").send(samlMetadata(org.ssoConnection, org.slug));
  }),
);
