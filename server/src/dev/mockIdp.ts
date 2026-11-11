/**
 * A fake identity provider for local development and tests. It speaks just enough OIDC and SAML
 * to exercise the real login code without an Okta or Entra account.
 *
 * It signs in anyone as anyone, so it is only mounted when MOCK_IDP=true, which env.ts refuses in production.
 */
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import express, { Router } from "express";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generate as generateCert } from "selfsigned";
import { SignedXml } from "xml-crypto";
import { env } from "../env.ts";

const BASE = env.APP_URL + "/mock-idp";

export const mockOidc = {
  issuer: BASE + "/oidc",
  clientId: "mock-client",
  clientSecret: "mock-secret",
};

const oidcKeys = await generateKeyPair("RS256", { extractable: true });
const oidcJwk = { ...(await exportJWK(oidcKeys.publicKey)), kid: "mock-key-1", use: "sig", alg: "RS256" };

const samlKeys = await generateCert([{ name: "commonName", value: "Mock IdP" }], { keySize: 2048, algorithm: "sha256" });

export const mockSaml = {
  entityId: BASE + "/saml",
  ssoUrl: BASE + "/saml/sso",
  certificate: samlKeys.cert,
};

const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

function page(title: string, body: string) {
  return (
    "<!doctype html><html><head><meta charset='utf-8'><title>" +
    esc(title) +
    "</title><style>body{font-family:system-ui;max-width:560px;margin:48px auto;padding:0 16px;color:#1f2937}" +
    "input{display:block;width:100%;padding:8px;margin:4px 0 12px;box-sizing:border-box}button{padding:8px 16px}" +
    "code{background:#f3f4f6;padding:2px 4px;word-break:break-all}.tag{background:#fef3c7;padding:2px 8px;border-radius:4px}</style></head><body>" +
    "<p><span class='tag'>Mock identity provider, for local testing only</span></p>" +
    body +
    "</body></html>"
  );
}

function loginForm(action: string, hidden: Record<string, string>) {
  const fields = Object.entries(hidden)
    .map(([k, v]) => "<input type='hidden' name='" + esc(k) + "' value='" + esc(v) + "'>")
    .join("");
  return (
    "<h1>Sign in as anyone</h1><form method='post' action='" +
    esc(action) +
    "'>" +
    fields +
    "<label>Email<input name='email' type='email' value='alice@example.com' required></label>" +
    "<label>Name<input name='name' value='Alice Example'></label><button>Sign in</button></form>"
  );
}

// ---------------------------------------------------------------- OIDC

interface AuthCode {
  email: string;
  name: string;
  nonce?: string;
  codeChallenge?: string;
  redirectUri: string;
  expiresAt: number;
}
const codes = new Map<string, AuthCode>();

export interface SamlResponseOptions {
  acsUrl: string;
  audience: string;
  email: string;
  name?: string;
  inResponseTo?: string;
  /** Overrides for negative tests. */
  issuer?: string;
  notOnOrAfter?: Date;
  privateKey?: string;
}

/** Builds a base64 SAML response with a signed assertion, like the one an IdP posts to the ACS URL. */
export function buildSamlResponse(o: SamlResponseOptions): string {
  const now = new Date();
  const issueInstant = now.toISOString();
  const notBefore = new Date(now.getTime() - 60_000).toISOString();
  const notOnOrAfter = (o.notOnOrAfter ?? new Date(now.getTime() + 5 * 60_000)).toISOString();
  const issuer = esc(o.issuer ?? mockSaml.entityId);
  const irt = o.inResponseTo ? " InResponseTo='" + esc(o.inResponseTo) + "'" : "";
  const attr = (name: string, value: string) =>
    "<saml:Attribute Name='" + name + "'><saml:AttributeValue>" + esc(value) + "</saml:AttributeValue></saml:Attribute>";

  const xml =
    "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'" +
    " ID='_" + randomUUID() + "' Version='2.0' IssueInstant='" + issueInstant + "' Destination='" + esc(o.acsUrl) + "'" + irt + ">" +
    "<saml:Issuer>" + issuer + "</saml:Issuer>" +
    "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status>" +
    "<saml:Assertion ID='_" + randomUUID() + "' Version='2.0' IssueInstant='" + issueInstant + "'>" +
    "<saml:Issuer>" + issuer + "</saml:Issuer>" +
    "<saml:Subject><saml:NameID Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'>" + esc(o.email) + "</saml:NameID>" +
    "<saml:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>" +
    "<saml:SubjectConfirmationData NotOnOrAfter='" + notOnOrAfter + "' Recipient='" + esc(o.acsUrl) + "'" + irt + "/>" +
    "</saml:SubjectConfirmation></saml:Subject>" +
    "<saml:Conditions NotBefore='" + notBefore + "' NotOnOrAfter='" + notOnOrAfter + "'>" +
    "<saml:AudienceRestriction><saml:Audience>" + esc(o.audience) + "</saml:Audience></saml:AudienceRestriction></saml:Conditions>" +
    "<saml:AuthnStatement AuthnInstant='" + issueInstant + "' SessionIndex='_" + randomUUID() + "'><saml:AuthnContext>" +
    "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>" +
    "</saml:AuthnContext></saml:AuthnStatement>" +
    "<saml:AttributeStatement>" + attr("email", o.email) + (o.name ? attr("displayName", o.name) : "") + "</saml:AttributeStatement>" +
    "</saml:Assertion></samlp:Response>";

  const sig = new SignedXml({
    privateKey: o.privateKey ?? samlKeys.private,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#",
  });
  sig.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
  });
  sig.computeSignature(xml, {
    location: { reference: "//*[local-name(.)='Assertion']/*[local-name(.)='Issuer']", action: "after" },
  });
  return Buffer.from(sig.getSignedXml()).toString("base64");
}

export function mockIdpRouter(): Router {
  const r = Router();
  r.use(express.urlencoded({ extended: false }));

  r.get("/", (_req, res) => {
    res.send(
      page(
        "Mock IdP",
        "<h1>Mock IdP settings</h1><p>Paste these into the SSO settings page of a workspace.</p>" +
          "<h2>OIDC</h2><p>Issuer: <code>" + esc(mockOidc.issuer) + "</code></p><p>Client ID: <code>" + esc(mockOidc.clientId) +
          "</code></p><p>Client secret: <code>" + esc(mockOidc.clientSecret) + "</code></p>" +
          "<h2>SAML</h2><p>IdP issuer (entity ID): <code>" + esc(mockSaml.entityId) + "</code></p><p>Sign-on URL: <code>" +
          esc(mockSaml.ssoUrl) + "</code></p><p>Signing certificate:</p><pre>" + esc(mockSaml.certificate) + "</pre>",
      ),
    );
  });

  r.get("/oidc/.well-known/openid-configuration", (_req, res) => {
    res.json({
      issuer: mockOidc.issuer,
      authorization_endpoint: mockOidc.issuer + "/authorize",
      token_endpoint: mockOidc.issuer + "/token",
      jwks_uri: mockOidc.issuer + "/jwks",
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["openid", "email", "profile"],
    });
  });

  r.get("/oidc/jwks", (_req, res) => {
    res.json({ keys: [oidcJwk] });
  });

  r.get("/oidc/authorize", (req, res) => {
    const q = req.query as Record<string, string>;
    if (q.client_id !== mockOidc.clientId || q.response_type !== "code" || !q.redirect_uri) {
      return res.status(400).send(page("Error", "<p>Bad authorization request: check the client ID and redirect URI.</p>"));
    }
    res.send(
      page(
        "Mock IdP sign in",
        loginForm(mockOidc.issuer + "/authorize", {
          redirect_uri: q.redirect_uri,
          state: q.state ?? "",
          nonce: q.nonce ?? "",
          code_challenge: q.code_challenge ?? "",
        }),
      ),
    );
  });

  r.post("/oidc/authorize", (req, res) => {
    const b = req.body as Record<string, string>;
    if (!b.redirect_uri || !b.email) return res.status(400).send("Bad request");
    const code = randomBytes(24).toString("base64url");
    codes.set(code, {
      email: b.email,
      name: b.name ?? "",
      nonce: b.nonce || undefined,
      codeChallenge: b.code_challenge || undefined,
      redirectUri: b.redirect_uri,
      expiresAt: Date.now() + 60_000,
    });
    const url = new URL(b.redirect_uri);
    url.searchParams.set("code", code);
    if (b.state) url.searchParams.set("state", b.state);
    res.redirect(url.href);
  });

  r.post("/oidc/token", async (req, res) => {
    const b = req.body as Record<string, string>;
    let clientId = b.client_id;
    let clientSecret = b.client_secret;
    const basic = req.headers.authorization?.match(/^Basic (.+)$/);
    if (basic) {
      const [id, secret] = Buffer.from(basic[1]!, "base64").toString().split(":");
      clientId = decodeURIComponent(id ?? "");
      clientSecret = decodeURIComponent(secret ?? "");
    }
    if (clientId !== mockOidc.clientId || clientSecret !== mockOidc.clientSecret) {
      return res.status(401).json({ error: "invalid_client" });
    }
    const entry = codes.get(b.code ?? "");
    codes.delete(b.code ?? "");
    const challenge = createHash("sha256").update(b.code_verifier ?? "").digest("base64url");
    if (
      !entry ||
      entry.expiresAt < Date.now() ||
      entry.redirectUri !== b.redirect_uri ||
      (entry.codeChallenge && entry.codeChallenge !== challenge)
    ) {
      return res.status(400).json({ error: "invalid_grant" });
    }
    const idToken = await new SignJWT({ email: entry.email, email_verified: true, name: entry.name, nonce: entry.nonce })
      .setProtectedHeader({ alg: "RS256", kid: oidcJwk.kid })
      .setIssuer(mockOidc.issuer)
      .setSubject("mock|" + entry.email.toLowerCase())
      .setAudience(mockOidc.clientId)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(oidcKeys.privateKey);
    res.json({ access_token: randomBytes(16).toString("hex"), token_type: "Bearer", expires_in: 300, id_token: idToken });
  });

  // ---------------------------------------------------------------- SAML

  r.get("/saml/cert", (_req, res) => {
    res.type("text/plain").send(mockSaml.certificate);
  });

  r.get("/saml/sso", (req, res) => {
    const raw = req.query.SAMLRequest;
    if (typeof raw !== "string") return res.status(400).send(page("Error", "<p>Missing SAMLRequest.</p>"));
    let xml: string;
    try {
      xml = inflateRawSync(Buffer.from(raw, "base64")).toString("utf8");
    } catch {
      return res.status(400).send(page("Error", "<p>Could not decode the SAMLRequest.</p>"));
    }
    const requestId = xml.match(/\bID="([^"]+)"/)?.[1] ?? "";
    const acsUrl = xml.match(/AssertionConsumerServiceURL="([^"]+)"/)?.[1] ?? "";
    const audience = xml.match(/<(?:\w+:)?Issuer[^>]*>([^<]+)</)?.[1] ?? "";
    if (!requestId || !acsUrl || !audience) return res.status(400).send(page("Error", "<p>Unreadable AuthnRequest.</p>"));
    res.send(page("Mock IdP sign in", loginForm(mockSaml.ssoUrl, { requestId, acsUrl, audience })));
  });

  r.post("/saml/sso", (req, res) => {
    const b = req.body as Record<string, string>;
    if (!b.acsUrl || !b.audience || !b.email) return res.status(400).send("Bad request");
    const samlResponse = buildSamlResponse({
      acsUrl: b.acsUrl,
      audience: b.audience,
      email: b.email,
      name: b.name,
      inResponseTo: b.requestId,
    });
    res.send(
      page(
        "Signing in",
        "<form id='f' method='post' action='" + esc(b.acsUrl) + "'><input type='hidden' name='SAMLResponse' value='" +
          esc(samlResponse) + "'><noscript><button>Continue</button></noscript></form><script>document.getElementById('f').submit()</script>",
      ),
    );
  });

  return r;
}
