import { Router } from "express";
import { z } from "zod";
import { hashPassword } from "../crypto.ts";
import { prisma } from "../db.ts";
import { ah, HttpError } from "../http.ts";
import { auth, requireAdmin, requireAuth } from "../session.ts";

export const membersRouter = Router();
membersRouter.use(requireAuth);

const select = { id: true, email: true, name: true, role: true, active: true, ssoSubject: true, passwordHash: true } as const;

function present(u: { id: string; email: string; name: string; role: string; active: boolean; ssoSubject: string | null; passwordHash: string | null }) {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    active: u.active,
    hasPassword: u.passwordHash !== null,
    ssoLinked: u.ssoSubject !== null,
  };
}

membersRouter.get(
  "/",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const users = await prisma.user.findMany({ where: { orgId }, select, orderBy: { createdAt: "asc" } });
    res.json({ members: users.map(present) });
  }),
);

/** Admin adds a member with a starting password. (SSO users are created on first login instead.) */
membersRouter.post(
  "/",
  requireAdmin,
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const body = z
      .object({
        email: z.string().trim().toLowerCase().email().max(254),
        name: z.string().trim().min(1).max(100),
        password: z.string().min(10, "Password must be at least 10 characters").max(200),
        role: z.enum(["ADMIN", "MEMBER"]).default("MEMBER"),
      })
      .parse(req.body);
    const existing = await prisma.user.findUnique({ where: { orgId_email: { orgId, email: body.email } } });
    if (existing) throw new HttpError(409, "email_taken", "Someone in this workspace already uses that email.");
    const user = await prisma.user.create({
      data: { orgId, email: body.email, name: body.name, role: body.role, passwordHash: await hashPassword(body.password) },
      select,
    });
    res.status(201).json({ member: present(user) });
  }),
);

membersRouter.patch(
  "/:id",
  requireAdmin,
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const memberId = z.string().uuid().parse(req.params.id);
    const body = z.object({ role: z.enum(["ADMIN", "MEMBER"]).optional(), active: z.boolean().optional() }).parse(req.body);

    const member = await prisma.$transaction(async (tx) => {
      const target = await tx.user.findFirst({ where: { id: memberId, orgId } });
      if (!target) throw new HttpError(404, "not_found", "Member not found.");

      // A workspace must always keep one active admin who can sign in with a password,
      // otherwise a broken SSO connection would lock everyone out.
      const losesAdmin = target.role === "ADMIN" && target.active && (body.role === "MEMBER" || body.active === false);
      if (losesAdmin) {
        const others = await tx.user.count({
          where: { orgId, role: "ADMIN", active: true, passwordHash: { not: null }, id: { not: target.id } },
        });
        if (others === 0) {
          throw new HttpError(409, "last_admin", "A workspace needs at least one active admin with a password.");
        }
      }

      const updated = await tx.user.update({ where: { id: target.id }, data: body, select });
      if (body.active === false) await tx.session.deleteMany({ where: { userId: target.id } });
      return updated;
    });
    res.json({ member: present(member) });
  }),
);
