import { Router } from "express";
import { z } from "zod";
import { prisma } from "../db.ts";
import { ah, HttpError } from "../http.ts";
import { auth, requireAuth } from "../session.ts";

/**
 * Tenant isolation rule for this file: every query carries `orgId` from the session,
 * never from the request. A task ID from another tenant behaves exactly like a missing one (404).
 */
export const tasksRouter = Router();
tasksRouter.use(requireAuth);

const status = z.enum(["TODO", "IN_PROGRESS", "DONE"]);
const id = z.string().uuid();

const include = { assignee: { select: { id: true, name: true, email: true } } } as const;

async function assertAssigneeInOrg(orgId: string, assigneeId: string | null | undefined) {
  if (!assigneeId) return;
  const user = await prisma.user.findFirst({ where: { id: assigneeId, orgId, active: true } });
  if (!user) throw new HttpError(400, "invalid_assignee", "That person is not an active member of this workspace.");
}

tasksRouter.get(
  "/",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const tasks = await prisma.task.findMany({ where: { orgId }, include, orderBy: { createdAt: "desc" } });
    res.json({ tasks });
  }),
);

tasksRouter.post(
  "/",
  ah(async (req, res) => {
    const { orgId, userId } = auth(req);
    const body = z
      .object({ title: z.string().trim().min(1).max(200), assigneeId: id.nullish(), status: status.optional() })
      .parse(req.body);
    await assertAssigneeInOrg(orgId, body.assigneeId);
    const task = await prisma.task.create({
      data: { orgId, createdById: userId, title: body.title, assigneeId: body.assigneeId ?? null, status: body.status },
      include,
    });
    res.status(201).json({ task });
  }),
);

tasksRouter.patch(
  "/:id",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const taskId = id.parse(req.params.id);
    const body = z
      .object({ title: z.string().trim().min(1).max(200).optional(), assigneeId: id.nullable().optional(), status: status.optional() })
      .parse(req.body);
    await assertAssigneeInOrg(orgId, body.assigneeId);
    const { count } = await prisma.task.updateMany({ where: { id: taskId, orgId }, data: body });
    if (count === 0) throw new HttpError(404, "not_found", "Task not found.");
    const task = await prisma.task.findFirstOrThrow({ where: { id: taskId, orgId }, include });
    res.json({ task });
  }),
);

tasksRouter.delete(
  "/:id",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const taskId = id.parse(req.params.id);
    const { count } = await prisma.task.deleteMany({ where: { id: taskId, orgId } });
    if (count === 0) throw new HttpError(404, "not_found", "Task not found.");
    res.json({ ok: true });
  }),
);
