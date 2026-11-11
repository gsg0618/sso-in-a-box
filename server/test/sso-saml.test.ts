import { inflateRawSync } from "node:zlib";
import { generate as generateCert } from "selfsigned";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildSamlResponse, mockSaml, type SamlResponseOptions } from "../src/dev/mockIdp.ts";
import { BASE, Browser, env, resetDb, signup, ssoError, startServer, stopServer } from "./helpers.ts";

beforeAll(startServer);
afterAll(stopServer);
beforeEach(resetDb);

const samlConfig = (extra: Record<string, unknown> = {}) => ({
  type: "SAML",
  enabled: true,
  samlIdpEntityId: mockSaml.entityId,
  samlIdpSsoUrl: mockSaml.ssoUrl,
  samlIdpCertificate: mockSaml.certificate,
  ...extra,
});

const sp = (slug: string) => ({
  acsUrl: BASE + "/api/sso/" + slug + "/saml/acs",
  audience: BASE + "/api/sso/" + slug + "/saml/metadata",
});

/** Starts a login and returns the ID of the AuthnRequest we sent to the IdP. */
async function startLogin(slug: string): Promise<string> {
  const start = await new Browser().get("/api/sso/" + slug + "/start");
  expect(start.status).toBe(302);
  const url = new URL(start.location!);
  expect(url.origin + url.pathname).toBe(mockSaml.ssoUrl);
  const xml = inflateRawSync(Buffer.from(url.searchParams.get("SAMLRequest")!, "base64")).toString();
  expect(xml).toContain(sp(slug).acsUrl);
  return xml.match(/\bID="([^"]+)"/)![1]!;
}

function postAcs(browser: Browser, slug: string, samlResponse: string) {
  // IdPs post from their own origin, so send a foreign Origin header like a real browser would.
  return browser.request("POST", "/api/sso/" + slug + "/saml/acs", {
    form: { SAMLResponse: samlResponse },
    headers: { origin: "https://idp.example" },
  });
}

async function loginWith(slug: string, overrides: Partial<SamlResponseOptions> = {}) {
  const inResponseTo = await startLogin(slug);
  const browser = new Browser();
  const response = buildSamlResponse({ ...sp(slug), email: "alice@acme.test", name: "Alice A", inResponseTo, ...overrides });
  const res = await postAcs(browser, slug, response);
  return { browser, res, response };
}

describe("SAML single sign-on", () => {
  it("signs a new user in and provisions them in the right workspace", async () => {
    const admin = await signup("acme");
    const saved = await admin.put("/api/admin/sso", samlConfig());
    expect(saved.status).toBe(200);
    expect(saved.body.connection.samlCertificateInfo.expired).toBe(false);

    const { browser, res } = await loginWith("acme");
    expect(res.status).toBe(302);
    expect(res.location).toBe(env.WEB_URL + "/");

    const me = await browser.get("/api/auth/me");
    expect(me.body.user).toMatchObject({ email: "alice@acme.test", name: "Alice A", role: "MEMBER" });
    expect(me.body.org.slug).toBe("acme");
  });

  it("accepts a certificate pasted as bare base64", async () => {
    const admin = await signup("acme");
    const bare = mockSaml.certificate.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
    expect((await admin.put("/api/admin/sso", samlConfig({ samlIdpCertificate: bare }))).status).toBe(200);
    expect((await loginWith("acme")).res.location).toBe(env.WEB_URL + "/");

    const bad = await admin.put("/api/admin/sso", samlConfig({ samlIdpCertificate: "not a certificate" }));
    expect(bad.body.error).toBe("invalid_certificate");
  });

  it("rejects a replayed response", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", samlConfig());
    const { response, res } = await loginWith("acme");
    expect(res.location).toBe(env.WEB_URL + "/");

    const replay = await postAcs(new Browser(), "acme", response);
    expect(ssoError(replay)).toBe("saml_validation_failed");
  });

  it("rejects an assertion issued for another workspace, even when both trust the same IdP", async () => {
    const acme = await signup("acme");
    const globex = await signup("globex");
    await acme.put("/api/admin/sso", samlConfig());
    await globex.put("/api/admin/sso", samlConfig({ samlAllowIdpInitiated: true }));

    // A valid, correctly signed assertion addressed to Acme, delivered to Globex's ACS.
    const forAcme = buildSamlResponse({ ...sp("acme"), email: "admin@globex.test" });
    const attacker = new Browser();
    const res = await postAcs(attacker, "globex", forAcme);
    expect(ssoError(res)).toBe("saml_validation_failed");
    expect((await attacker.get("/api/auth/me")).status).toBe(401);
  });

  it("rejects an assertion signed with a different key", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", samlConfig());
    const other = await generateCert([{ name: "commonName", value: "Evil IdP" }], { keySize: 2048 });
    const { res } = await loginWith("acme", { privateKey: other.private });
    expect(ssoError(res)).toBe("saml_validation_failed");
  });

  it("rejects an assertion whose signed content was altered", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", samlConfig());
    const inResponseTo = await startLogin("acme");
    const good = buildSamlResponse({ ...sp("acme"), email: "alice@acme.test", inResponseTo });
    const tampered = Buffer.from(Buffer.from(good, "base64").toString().replaceAll("alice@acme.test", "admin@acme.test")).toString("base64");
    expect(ssoError(await postAcs(new Browser(), "acme", tampered))).toBe("saml_validation_failed");
  });

  it("rejects an expired assertion", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", samlConfig());
    const { res } = await loginWith("acme", { notOnOrAfter: new Date(Date.now() - 60 * 60 * 1000) });
    expect(ssoError(res)).toBe("saml_validation_failed");
  });

  it("rejects an unexpected issuer", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", samlConfig());
    const { res } = await loginWith("acme", { issuer: "https://some-other-idp.example" });
    expect(ssoError(res)).toBe("issuer_mismatch");
  });

  it("only accepts IdP-initiated logins when the admin allowed them", async () => {
    const admin = await signup("acme");
    await admin.put("/api/admin/sso", samlConfig());
    const unsolicited = () => buildSamlResponse({ ...sp("acme"), email: "alice@acme.test" });

    expect(ssoError(await postAcs(new Browser(), "acme", unsolicited()))).toBe("saml_validation_failed");

    await admin.put("/api/admin/sso", samlConfig({ samlAllowIdpInitiated: true }));
    expect((await postAcs(new Browser(), "acme", unsolicited())).location).toBe(env.WEB_URL + "/");
  });

  it("publishes service provider metadata per workspace", async () => {
    await signup("acme");
    const res = await new Browser().get("/api/sso/acme/saml/metadata");
    expect(res.status).toBe(200);
    expect(res.text).toContain(sp("acme").acsUrl);
    expect(res.text).toContain('entityID="' + sp("acme").audience + '"');
  });
});
