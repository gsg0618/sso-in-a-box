import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Browser, login, PASSWORD, resetDb, signup, startServer, stopServer } from "./helpers.ts";

beforeAll(startServer);
afterAll(stopServer);
beforeEach(resetDb);

describe("accounts", () => {
  it("creates a workspace, signs in and out", async () => {
    const admin = await signup("acme");
    const me = await admin.get("/api/auth/me");
    expect(me.body.user.role).toBe("ADMIN");
    expect(me.body.org.slug).toBe("acme");

    await admin.post("/api/auth/logout");
    expect((await admin.get("/api/auth/me")).status).toBe(401);

    const again = await login("acme", "admin@acme.test");
    expect(again.res.status).toBe(200);
  });

  it("rejects wrong passwords, unknown users and unknown workspaces with the same answer", async () => {
    await signup("acme");
    const wrongPassword = await login("acme", "admin@acme.test", "not the password");
    const unknownUser = await login("acme", "nobody@acme.test");
    const unknownOrg = await login("nope", "admin@acme.test");
    for (const { res } of [wrongPassword, unknownUser, unknownOrg]) {
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("invalid_credentials");
    }
  });

  it("treats the same email in two workspaces as two separate accounts", async () => {
    await signup("acme", "sam@shared.test");
    const other = new Browser();
    await other.post("/api/auth/signup", { orgName: "Globex", slug: "globex", name: "Sam", email: "sam@shared.test", password: "a different password" });

    // Each password only works in its own workspace.
    expect((await login("globex", "sam@shared.test", PASSWORD)).res.status).toBe(401);
    expect((await login("acme", "sam@shared.test", "a different password")).res.status).toBe(401);
    expect((await login("acme", "sam@shared.test", PASSWORD)).res.status).toBe(200);
  });

  it("requires a session", async () => {
    const anon = new Browser();
    expect((await anon.get("/api/tasks")).status).toBe(401);
    expect((await anon.get("/api/members")).status).toBe(401);
    expect((await anon.get("/api/admin/sso")).status).toBe(401);
  });

  it("blocks state-changing requests from other origins", async () => {
    const admin = await signup("acme");
    const res = await admin.request("POST", "/api/tasks", { json: { title: "x" }, headers: { origin: "https://evil.example" } });
    expect(res.status).toBe(403);
    expect(res.body.error).toBe("bad_origin");
  });
});

describe("tenant isolation", () => {
  it("never shows or changes another workspace's tasks", async () => {
    const acme = await signup("acme");
    const globex = await signup("globex");

    const created = await acme.post("/api/tasks", { title: "Acme secret roadmap" });
    expect(created.status).toBe(201);
    const taskId = created.body.task.id;

    expect((await globex.get("/api/tasks")).body.tasks).toEqual([]);
    expect((await globex.patch("/api/tasks/" + taskId, { title: "hijacked" })).status).toBe(404);
    expect((await globex.delete("/api/tasks/" + taskId)).status).toBe(404);

    const stillThere = await acme.get("/api/tasks");
    expect(stillThere.body.tasks).toHaveLength(1);
    expect(stillThere.body.tasks[0].title).toBe("Acme secret roadmap");
  });

  it("refuses to assign a task to someone in another workspace", async () => {
    const acme = await signup("acme");
    const globex = await signup("globex");
    const globexAdminId = (await globex.get("/api/auth/me")).body.user.id;

    const res = await acme.post("/api/tasks", { title: "Cross-tenant assignment", assigneeId: globexAdminId });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_assignee");
  });

  it("only lists and manages members of the caller's workspace", async () => {
    const acme = await signup("acme");
    const globex = await signup("globex");
    const acmeAdminId = (await acme.get("/api/auth/me")).body.user.id;

    const members = (await globex.get("/api/members")).body.members;
    expect(members.map((m: any) => m.email)).toEqual(["admin@globex.test"]);
    expect((await globex.patch("/api/members/" + acmeAdminId, { active: false })).status).toBe(404);
  });
});

describe("roles", () => {
  it("keeps admin actions away from members", async () => {
    const admin = await signup("acme");
    await admin.post("/api/members", { email: "mia@acme.test", name: "Mia", password: PASSWORD });
    const { browser: member } = await login("acme", "mia@acme.test");

    expect((await member.get("/api/tasks")).status).toBe(200);
    expect((await member.post("/api/members", { email: "x@acme.test", name: "X", password: PASSWORD })).status).toBe(403);
    expect((await member.get("/api/admin/sso")).status).toBe(403);
    expect((await member.put("/api/admin/sso", { type: "OIDC" })).status).toBe(403);
  });

  it("ends a deactivated member's sessions immediately", async () => {
    const admin = await signup("acme");
    const created = await admin.post("/api/members", { email: "mia@acme.test", name: "Mia", password: PASSWORD });
    const { browser: member } = await login("acme", "mia@acme.test");
    expect((await member.get("/api/tasks")).status).toBe(200);

    await admin.patch("/api/members/" + created.body.member.id, { active: false });
    expect((await member.get("/api/tasks")).status).toBe(401);
    expect((await login("acme", "mia@acme.test")).res.status).toBe(401);
  });

  it("will not remove the last admin", async () => {
    const admin = await signup("acme");
    const me = (await admin.get("/api/auth/me")).body.user.id;
    const demote = await admin.patch("/api/members/" + me, { role: "MEMBER" });
    expect(demote.status).toBe(409);
    expect(demote.body.error).toBe("last_admin");
  });
});
