import { type CacheProvider, SAML, ValidateInResponseTo } from "@node-saml/node-saml";
import { prisma } from "../db.ts";
import type { SsoConnection } from "../generated/prisma/client.ts";
import { looksLikeEmail, SsoError, type SsoIdentity } from "./provision.ts";
import { spUrls } from "./urls.ts";

const REQUEST_TTL_MS = 10 * 60 * 1000;

/**
 * Database-backed store for AuthnRequest IDs and seen assertion IDs, scoped to one connection.
 * It lives in Postgres (not memory) so it works across restarts and multiple server instances.
 */
function cacheFor(connectionId: string): CacheProvider {
  const id = (key: string) => ({ connectionId_key: { connectionId, key } });
  const consume = async (key: string | null): Promise<string | null> => {
    if (!key) return null;
    try {
      // A single DELETE: of two concurrent copies of the same response, only one finds the row.
      const row = await prisma.samlCacheEntry.delete({ where: id(key) });
      return row.expiresAt > new Date() ? row.value : null;
    } catch {
      return null;
    }
  };
  return {
    async saveAsync(key, value) {
      const expiresAt = new Date(Date.now() + REQUEST_TTL_MS);
      await prisma.samlCacheEntry.upsert({ where: id(key), create: { connectionId, key, value, expiresAt }, update: {} });
      return { value, createdAt: Date.now() };
    },
    async getAsync(key) {
      const row = await prisma.samlCacheEntry.findUnique({ where: id(key) });
      return row && row.expiresAt > new Date() ? row.value : null;
    },
    removeAsync: consume,
    consumeAsync: consume,
    async saveIfAbsentAsync(key, value, expiresAtMs) {
      try {
        await prisma.samlCacheEntry.create({ data: { connectionId, key, value, expiresAt: new Date(expiresAtMs) } });
        return true;
      } catch {
        return false;
      }
    },
  };
}

function build(conn: SsoConnection, orgSlug: string): SAML {
  if (!conn.samlIdpSsoUrl || !conn.samlIdpCertificate || !conn.samlIdpEntityId) {
    throw new SsoError("not_configured", "The SAML connection is missing its sign-on URL, issuer or certificate.");
  }
  const sp = spUrls(orgSlug);
  return new SAML({
    // Service provider (us), unique per tenant.
    issuer: sp.samlEntityId,
    callbackUrl: sp.samlAcsUrl,
    audience: sp.samlEntityId,
    // Identity provider (the customer's Okta or Entra tenant).
    entryPoint: conn.samlIdpSsoUrl,
    idpCert: conn.samlIdpCertificate,
    // The assertion carries the identity, so that is the part that must be signed.
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: false,
    signatureAlgorithm: "sha256",
    acceptedClockSkewMs: 2 * 60 * 1000,
    maxAssertionAgeMs: 10 * 60 * 1000,
    // Unsolicited (IdP-initiated) responses are refused unless the admin opted in.
    validateInResponseTo: conn.samlAllowIdpInitiated ? ValidateInResponseTo.ifPresent : ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: REQUEST_TTL_MS,
    rejectReplayedAssertions: true,
    cacheProvider: cacheFor(conn.id),
    identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    // Asking for a specific authentication method is a common cause of Entra ID login failures.
    disableRequestedAuthnContext: true,
  });
}

export async function samlStart(conn: SsoConnection, orgSlug: string): Promise<string> {
  return build(conn, orgSlug).getAuthorizeUrlAsync("", {});
}

export function samlMetadata(conn: SsoConnection | null, orgSlug: string): string {
  // Metadata only describes our side, so it can be produced before the IdP details are known.
  const sp = spUrls(orgSlug);
  const saml = new SAML({
    issuer: sp.samlEntityId,
    callbackUrl: sp.samlAcsUrl,
    idpCert: conn?.samlIdpCertificate || "unused",
    identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    wantAssertionsSigned: true,
  });
  return saml.generateServiceProviderMetadata(null, null);
}

const ATTR = {
  email: ["email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
  name: ["displayName", "name", "http://schemas.microsoft.com/identity/claims/displayname"],
  first: ["firstName", "givenName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"],
  last: ["lastName", "surname", "sn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"],
};

function pick(profile: Record<string, unknown>, names: string[]): string | undefined {
  for (const n of names) {
    const v = profile[n];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

/**
 * Validates the POSTed SAMLResponse. node-saml verifies the XML signature against the pinned
 * certificate, the audience, the validity window, InResponseTo and replay; we then check the issuer.
 */
export async function samlCallback(conn: SsoConnection, orgSlug: string, samlResponse: string): Promise<SsoIdentity> {
  const saml = build(conn, orgSlug);
  let profile: Record<string, unknown> | null;
  try {
    const result = await saml.validatePostResponseAsync({ SAMLResponse: samlResponse });
    profile = result.loggedOut ? null : (result.profile as Record<string, unknown> | null);
  } catch (err) {
    throw new SsoError("saml_validation_failed", "The SAML response was rejected: " + (err as Error).message);
  }
  if (!profile) throw new SsoError("saml_validation_failed", "The SAML response did not contain a login assertion.");

  if (profile.issuer !== conn.samlIdpEntityId) {
    throw new SsoError("issuer_mismatch", "The SAML response came from an unexpected issuer: " + String(profile.issuer));
  }

  const nameId = typeof profile.nameID === "string" ? profile.nameID : "";
  const email = pick(profile, ATTR.email) ?? (looksLikeEmail(nameId) ? nameId : undefined);
  if (!email) {
    throw new SsoError("missing_email", "The SAML assertion has no email. Send it as the NameID or as an 'email' attribute.");
  }
  const fullName = pick(profile, ATTR.name) ?? [pick(profile, ATTR.first), pick(profile, ATTR.last)].filter(Boolean).join(" ");
  // Fall back to the email when the IdP sends no NameID, so the user still has a stable identifier.
  return { subject: nameId || email.toLowerCase(), email, name: fullName || undefined };
}
