import type { Request, RequestHandler, Response } from "express";
import { newToken, sha256 } from "./crypto.ts";
import { prisma } from "./db.ts";
import { env } from "./env.ts";
import type { Role } from "./generated/prisma/client.ts";
import { ah, HttpError } from "./http.ts";

const COOKIE = "sid";
const TTL_MS = 7 * 24 * 60 * 60 * 1000;

export interface AuthContext {
  userId: string;
  /** The tenant this request acts in. Every data query must be filtered by it. */
  orgId: string;
  role: Role;
  tokenHash: string;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}

export async function createSession(res: Response, user: { id: string; orgId: string }, method: string) {
  const token = newToken();
  await prisma.session.create({
    data: {
      tokenHash: sha256(token),
      userId: user.id,
      orgId: user.orgId,
      method,
      expiresAt: new Date(Date.now() + TTL_MS),
    },
  });
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: env.APP_URL.startsWith("https://"),
    maxAge: TTL_MS,
    path: "/",
  });
}

export async function destroySession(req: Request, res: Response) {
  const token = req.cookies?.[COOKIE];
  if (typeof token === "string") {
    await prisma.session.deleteMany({ where: { tokenHash: sha256(token) } });
  }
  res.clearCookie(COOKIE, { path: "/" });
}

/** Loads the session on every request, so a deactivated user or revoked session stops working at once. */
export const requireAuth: RequestHandler = ah(async (req, _res, next) => {
  const token = req.cookies?.[COOKIE];
  if (typeof token !== "string") throw new HttpError(401, "unauthenticated", "Sign in to continue.");
  const tokenHash = sha256(token);
  const session = await prisma.session.findUnique({ where: { tokenHash }, include: { user: true } });
  if (!session || session.expiresAt < new Date() || !session.user.active) {
    throw new HttpError(401, "unauthenticated", "Sign in to continue.");
  }
  req.auth = { userId: session.userId, orgId: session.orgId, role: session.user.role, tokenHash };
  next();
});

export const requireAdmin: RequestHandler = (req, _res, next) => {
  if (req.auth?.role !== "ADMIN") return next(new HttpError(403, "forbidden", "Only workspace admins can do this."));
  next();
};

/** Use after requireAuth. */
export function auth(req: Request): AuthContext {
  if (!req.auth) throw new HttpError(401, "unauthenticated", "Sign in to continue.");
  return req.auth;
}
