import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { mockOidc } from "../src/dev/mockIdp.ts";
import { BASE, Browser, env, login, PASSWORD, prisma, resetDb, signup, ssoError, startServer, stopServer } from "./helpers.ts";

beforeAll(startServer);
afterAll(stopServer);
beforeEach(resetDb);

const oidcConfig = (extra: Record<string, unknown> = {}) => ({
  type: "OIDC",
  enabled: true,
  oidcIssuer: mockOidc.issuer,
  oidcClientId: mockOidc.clientId,
  oidcClientSecret: mockOidc.clientSecret,
  ...extra,
});

/** Walks the redirect to the IdP and "signs in" there, returning the callback URL the IdP sends the browser to. */
async function signInAtIdp(browser: Browser, slug: string, email: string, name = "Sso User") {
  const start = await browser.get("/api/sso/" + slug + "/start");
  expect(start.status).toBe(302);
  const authorize = new URL(start.location!);
  expect(authorize.origin + authorize.pathname).toBe(mockOidc.issuer + "/authorize");
  const q = authorize.searchParams;
  expect(q.get("code_challenge_method")).toBe("S256");
  expect(q.get("redirect_uri")).toBe(BASE + "/api/sso/" + slug + "/oidc/callback");

  const approved = await new Browser().request("POST", mockOidc.issuer + "/authorize", {
    form: {
      redirect_uri: q.get("redirect_uri")!,
      state: q.get("state")!,
      nonce: q.get("nonce")!,
      code_challenge: q.get("code_challenge")!,
      email,
      name,
    },
  });
  expect(approved.status).toBe(302);
  return approved.location!;
}

describe("OIDC single sign-on", () => {
  it("signs a new user in and provisions them in the right workspace", async () => {
    const admin = await signup("acme");
    expect((await admin.put("/api/admin/sso", oidcConfig())).status).toBe(200);

    const browser = new Browser();
    const callbackUrl = await signInAtIdp(browser, "acme", "Alice@Acme.test", "Alice A");
    const done = await browser.get(callbackUrl);
    expect(done.status).toBe(302);
    expect(done.location).toBe(env.WEB_URL + "/");

    const me = await browser.get("/api/auth/me");
    expect(me.body.user).toMatchObject({ email: "alice@acme.test", name: "Alice A", role: "MEMBER" });
    expect(me.body.org.slug).toBe("acme");

    // A second login reuses the same account instead of creating another.
    const again = new Browser();
    await again.get(await signInAtIdp(again, "acme", "alice@acme.test"));
    expect((await admin.get("/api/members")).body.members).toHaveLength(2);
  });

  it("never returns the client secret, and stores it encrypted", async () => {
    const admin = await signup("acme");
    const saved = await admin.put("/api/admin/sso", oidcConfig());
    expect(JSON.stringify(saved.body)).not.toContain(mockOidc.clientSecret);
    expect(saved.body.connection.oidcClientSecretSet).toBe(true);

    const row = await prisma.ssoConnection.findFirstOrThrow();
    expect(row.oidcClientSecretEnc).not.toContain(mockOidc.clientSecret);

    // Saving again without a secret keeps the stored one, and login still works.
    await admin.put("/api/admin/sso", oidcConfig({ oidcClientSecret: "" }));
    const browser = new Browser();
    expect((await browser.get(await signInAtIdp(browser, "acme", "bob@acme.test"))).location).toBe(env.WEB_URL + "/");
  });

  it("rejects a callback that this browser did not start", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", oidcConfig());

    const victim = new Browser();
    const callbackUrl = await signInAtIdp(new Browser(), "acme", "attacker@acme.test");
    const res = await victim.get(callbackUrl);
    expect(ssoError(res)).toBe("session_expired");
    expect((await victim.get("/api/auth/me")).status).toBe(401);
  });

  it("rejects a tampered state", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", oidcConfig());
    const browser = new Browser();
    const url = new URL(await signInAtIdp(browser, "acme", "alice@acme.test"));
    url.searchParams.set("state", "forged");
    expect(ssoError(await browser.get(url.href))).toBe("oidc_validation_failed");
  });

  it("does not let a login started for one workspace finish in another", async () => {
    const acme = await signup("acme");
    const globex = await signup("globex");
    await acme.put("/api/admin/sso", oidcConfig());
    await globex.put("/api/admin/sso", oidcConfig());

    const browser = new Browser();
    const acmeCallback = await signInAtIdp(browser, "acme", "alice@acme.test");
    const crossed = acmeCallback.replace("/api/sso/acme/", "/api/sso/globex/");
    expect(ssoError(await browser.get(crossed))).toBe("session_expired");
    expect((await globex.get("/api/members")).body.members).toHaveLength(1);
  });

  it("refuses SSO for workspaces without an enabled connection", async () => {
    const admin = await signup("acme");
    expect(ssoError(await new Browser().get("/api/sso/acme/start"))).toBe("not_configured");
    await admin.put("/api/admin/sso", oidcConfig({ enabled: false }));
    expect(ssoError(await new Browser().get("/api/sso/acme/start"))).toBe("not_configured");
    expect(ssoError(await new Browser().get("/api/sso/unknown/start"))).toBe("not_configured");
  });

  it("refuses deactivated users", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", oidcConfig());
    const first = new Browser();
    await first.get(await signInAtIdp(first, "acme", "alice@acme.test"));
    const alice = (await admin.get("/api/members")).body.members.find((m: any) => m.email === "alice@acme.test");
    await admin.patch("/api/members/" + alice.id, { active: false });

    const second = new Browser();
    expect(ssoError(await second.get(await signInAtIdp(second, "acme", "alice@acme.test")))).toBe("deactivated");
  });
});

describe("SSO settings", () => {
  it("will not turn on an incomplete connection", async () => {
    const admin = await signup("acme");
    const res = await admin.put("/api/admin/sso", { type: "OIDC", enabled: true, oidcIssuer: mockOidc.issuer });
    expect(res.status).toBe(400);
    expect(res.body.message).toContain("client ID");
  });

  it("requires SSO for members when enforced, but keeps admin password login as break-glass", async () => {
    const admin = await signup("acme");
    await admin.post("/api/members", { email: "mia@acme.test", name: "Mia", password: PASSWORD });
    await admin.put("/api/admin/sso", oidcConfig({ enforced: true }));

    const member = await login("acme", "mia@acme.test");
    expect(member.res.status).toBe(403);
    expect(member.res.body.error).toBe("sso_required");
    expect(member.res.body.ssoUrl).toBe(BASE + "/api/sso/acme/start");

    expect((await login("acme", "admin@acme.test")).res.status).toBe(200);
  });

  it("routes by email domain and keeps a domain to one workspace", async () => {
    const acme = await signup("acme");
    const globex = await signup("globex");
    await acme.put("/api/admin/sso", oidcConfig({ domains: ["Acme.test"] }));

    const found = await new Browser().post("/api/auth/discover", { email: "anyone@acme.test" });
    expect(found.body).toMatchObject({ sso: true, slug: "acme" });
    expect((await new Browser().post("/api/auth/discover", { email: "anyone@other.test" })).body.sso).toBe(false);

    const clash = await globex.put("/api/admin/sso", oidcConfig({ domains: ["acme.test"] }));
    expect(clash.status).toBe(409);
    expect(clash.body.error).toBe("domain_taken");
  });
});
