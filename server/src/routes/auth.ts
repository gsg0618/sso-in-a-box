import { Router } from "express";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { DUMMY_PASSWORD_HASH, hashPassword, verifyPassword } from "../crypto.ts";
import { prisma } from "../db.ts";
import { env } from "../env.ts";
import { ah, HttpError } from "../http.ts";
import { auth, createSession, destroySession, requireAuth } from "../session.ts";

export const authRouter = Router();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: env.NODE_ENV === "test" ? 10_000 : 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "rate_limited", message: "Too many attempts. Try again in a few minutes." },
});

const email = z.string().trim().toLowerCase().email().max(254);
const password = z.string().min(10, "Password must be at least 10 characters").max(200);
const slug = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$/, "Use 3 to 40 lowercase letters, numbers or hyphens");

const RESERVED_SLUGS = new Set(["api", "admin", "login", "signup", "sso", "mock-idp", "www"]);

/** Creates a new tenant and its first admin. */
authRouter.post(
  "/signup",
  limiter,
  ah(async (req, res) => {
    const body = z
      .object({ orgName: z.string().trim().min(1).max(100), slug, name: z.string().trim().min(1).max(100), email, password })
      .parse(req.body);
    if (RESERVED_SLUGS.has(body.slug)) throw new HttpError(409, "slug_taken", "That workspace URL is taken.");
    const existing = await prisma.organization.findUnique({ where: { slug: body.slug } });
    if (existing) throw new HttpError(409, "slug_taken", "That workspace URL is taken.");

    const passwordHash = await hashPassword(body.password);
    const org = await prisma.organization.create({
      data: {
        slug: body.slug,
        name: body.orgName,
        users: { create: { email: body.email, name: body.name, role: "ADMIN", passwordHash } },
      },
      include: { users: true },
    });
    const user = org.users[0]!;
    await createSession(res, user, "password");
    res.status(201).json({ ok: true });
  }),
);

authRouter.post(
  "/login",
  limiter,
  ah(async (req, res) => {
    const body = z.object({ slug: z.string().trim().toLowerCase(), email, password: z.string().max(200) }).parse(req.body);
    const invalid = new HttpError(401, "invalid_credentials", "Wrong workspace, email or password.");

    const org = await prisma.organization.findUnique({ where: { slug: body.slug }, include: { ssoConnection: true } });
    const user = org
      ? await prisma.user.findUnique({ where: { orgId_email: { orgId: org.id, email: body.email } } })
      : null;

    // Always run one hash comparison so timing does not reveal whether the account exists.
    const ok = await verifyPassword(body.password, user?.passwordHash ?? DUMMY_PASSWORD_HASH);
    if (!org || !user || !user.passwordHash || !ok || !user.active) throw invalid;

    // Checked only after the password is proven, so it cannot be used to probe accounts.
    const sso = org.ssoConnection;
    if (sso?.enabled && sso.enforced && user.role !== "ADMIN") {
      throw new HttpError(403, "sso_required", "Your workspace requires single sign-on.", {
        ssoUrl: ssoStartUrl(org.slug),
      });
    }

    await createSession(res, user, "password");
    res.json({ ok: true });
  }),
);

/** Login page helper: given an email or a workspace slug, says whether to send the browser to SSO. */
authRouter.post(
  "/discover",
  limiter,
  ah(async (req, res) => {
    const body = z.object({ email: email.optional(), slug: z.string().trim().toLowerCase().optional() }).parse(req.body);
    let orgSlug: string | undefined;
    if (body.slug) {
      const org = await prisma.organization.findUnique({ where: { slug: body.slug }, include: { ssoConnection: true } });
      if (org?.ssoConnection?.enabled) orgSlug = org.slug;
    } else if (body.email) {
      const domain = body.email.split("@")[1]!;
      const conn = await prisma.ssoConnection.findFirst({
        where: { enabled: true, domains: { has: domain } },
        include: { org: true },
      });
      if (conn) orgSlug = conn.org.slug;
    }
    res.json(orgSlug ? { sso: true, slug: orgSlug, ssoUrl: ssoStartUrl(orgSlug) } : { sso: false });
  }),
);

authRouter.post(
  "/logout",
  ah(async (req, res) => {
    await destroySession(req, res);
    res.json({ ok: true });
  }),
);

authRouter.get(
  "/me",
  requireAuth,
  ah(async (req, res) => {
    const { userId, orgId } = auth(req);
    const user = await prisma.user.findFirstOrThrow({ where: { id: userId, orgId }, include: { org: true } });
    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      org: { id: user.org.id, slug: user.org.slug, name: user.org.name },
    });
  }),
);

export function ssoStartUrl(orgSlug: string): string {
  return env.APP_URL + "/api/sso/" + encodeURIComponent(orgSlug) + "/start";
}
