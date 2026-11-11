import { X509Certificate } from "node:crypto";
import { Router } from "express";
import { z } from "zod";
import { encryptSecret } from "../crypto.ts";
import { prisma } from "../db.ts";
import { env } from "../env.ts";
import type { SsoConnection } from "../generated/prisma/client.ts";
import { ah, HttpError } from "../http.ts";
import { auth, requireAdmin, requireAuth } from "../session.ts";
import { issuerAllowed } from "../sso/oidc.ts";
import { spUrls } from "../sso/urls.ts";

/** Admin console API: each tenant's admins manage their own SSO connection, and only their own. */
export const ssoAdminRouter = Router();
ssoAdminRouter.use(requireAuth, requireAdmin);

/** Accepts a PEM certificate or the bare base64 body that IdP consoles often show, and returns PEM. */
function normalizeCertificate(input: string): string {
  const body = input.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
  const pem = "-----BEGIN CERTIFICATE-----\n" + (body.match(/.{1,64}/g) ?? []).join("\n") + "\n-----END CERTIFICATE-----\n";
  try {
    new X509Certificate(pem);
  } catch {
    throw new HttpError(400, "invalid_certificate", "That is not a valid X.509 certificate. Paste the IdP signing certificate in PEM or base64 form.");
  }
  return pem;
}

function certificateInfo(pem: string | null) {
  if (!pem) return null;
  try {
    const cert = new X509Certificate(pem);
    return {
      subject: cert.subject.replace(/\n/g, ", "),
      validFrom: new Date(cert.validFrom).toISOString(),
      validTo: new Date(cert.validTo).toISOString(),
      expired: new Date(cert.validTo) < new Date(),
      fingerprintSha256: cert.fingerprint256,
    };
  } catch {
    return null;
  }
}

function present(conn: SsoConnection | null, orgSlug: string) {
  return {
    serviceProvider: spUrls(orgSlug),
    connection: conn && {
      type: conn.type,
      enabled: conn.enabled,
      enforced: conn.enforced,
      domains: conn.domains,
      oidcIssuer: conn.oidcIssuer,
      oidcClientId: conn.oidcClientId,
      // The secret itself is write-only.
      oidcClientSecretSet: conn.oidcClientSecretEnc !== null,
      samlIdpEntityId: conn.samlIdpEntityId,
      samlIdpSsoUrl: conn.samlIdpSsoUrl,
      samlIdpCertificate: conn.samlIdpCertificate,
      samlCertificateInfo: certificateInfo(conn.samlIdpCertificate),
      samlAllowIdpInitiated: conn.samlAllowIdpInitiated,
      updatedAt: conn.updatedAt,
    },
  };
}

const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .nullish()
    .transform((v) => v || null);

const httpUrl = (value: string) => {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || (url.protocol === "http:" && !env.isProd);
  } catch {
    return false;
  }
};

const bodySchema = z.object({
  type: z.enum(["OIDC", "SAML"]),
  enabled: z.boolean().default(false),
  enforced: z.boolean().default(false),
  domains: z
    .array(
      z
        .string()
        .trim()
        .toLowerCase()
        .regex(/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/, "Enter domains like example.com"),
    )
    .max(10)
    .default([])
    .transform((d) => [...new Set(d)]),
  oidcIssuer: optionalText(500),
  oidcClientId: optionalText(500),
  /** Omit or leave empty to keep the stored secret. */
  oidcClientSecret: optionalText(1000),
  samlIdpEntityId: optionalText(500),
  samlIdpSsoUrl: optionalText(1000),
  samlIdpCertificate: optionalText(20_000),
  samlAllowIdpInitiated: z.boolean().default(false),
});

ssoAdminRouter.get(
  "/",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId }, include: { ssoConnection: true } });
    res.json(present(org.ssoConnection, org.slug));
  }),
);

ssoAdminRouter.put(
  "/",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    const body = bodySchema.parse(req.body);
    const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId }, include: { ssoConnection: true } });
    const existing = org.ssoConnection;

    if (body.oidcIssuer && !issuerAllowed(body.oidcIssuer)) {
      throw new HttpError(400, "invalid_input", "The issuer must be an https URL, for example https://your-org.okta.com.");
    }
    if (body.samlIdpSsoUrl && !httpUrl(body.samlIdpSsoUrl)) {
      throw new HttpError(400, "invalid_input", "The IdP sign-on URL must be an https URL.");
    }
    const certificate = body.samlIdpCertificate ? normalizeCertificate(body.samlIdpCertificate) : null;
    const secretEnc = body.oidcClientSecret ? encryptSecret(body.oidcClientSecret) : (existing?.oidcClientSecretEnc ?? null);

    if (body.enforced && !body.enabled) {
      throw new HttpError(400, "invalid_input", "Turn the connection on before requiring SSO for members.");
    }
    if (body.enforced) {
      // Admins keep password login as the way back in if the IdP breaks, so one must have a password.
      const breakGlass = await prisma.user.count({ where: { orgId, role: "ADMIN", active: true, passwordHash: { not: null } } });
      if (breakGlass === 0) {
        throw new HttpError(409, "no_break_glass", "Before requiring SSO, make sure at least one admin has a password.");
      }
    }
    if (body.enabled) {
      const missing =
        body.type === "OIDC"
          ? [!body.oidcIssuer && "issuer", !body.oidcClientId && "client ID", !secretEnc && "client secret"]
          : [!body.samlIdpEntityId && "IdP issuer (entity ID)", !body.samlIdpSsoUrl && "IdP sign-on URL", !certificate && "IdP signing certificate"];
      const names = missing.filter(Boolean);
      if (names.length) throw new HttpError(400, "incomplete", "Before turning this on, fill in: " + names.join(", ") + ".");
    }

    // A domain routes logins from the sign-in page, so two workspaces cannot both claim it.
    if (body.domains.length) {
      const clash = await prisma.ssoConnection.findFirst({ where: { orgId: { not: orgId }, domains: { hasSome: body.domains } } });
      if (clash) {
        const taken = body.domains.filter((d) => clash.domains.includes(d));
        throw new HttpError(409, "domain_taken", "Another workspace already uses: " + taken.join(", ") + ".");
      }
    }

    const data = {
      type: body.type,
      enabled: body.enabled,
      enforced: body.enforced,
      domains: body.domains,
      oidcIssuer: body.oidcIssuer,
      oidcClientId: body.oidcClientId,
      oidcClientSecretEnc: secretEnc,
      samlIdpEntityId: body.samlIdpEntityId,
      samlIdpSsoUrl: body.samlIdpSsoUrl,
      samlIdpCertificate: certificate,
      samlAllowIdpInitiated: body.samlAllowIdpInitiated,
    };

    // If the workspace now points at a different identity source, old subject IDs mean nothing.
    // Clearing them lets people be re-linked by email on their next login instead of being locked out.
    const sourceChanged =
      existing !== null &&
      (existing.type !== data.type ||
        (data.type === "OIDC" ? existing.oidcIssuer !== data.oidcIssuer : existing.samlIdpEntityId !== data.samlIdpEntityId));

    const conn = await prisma.$transaction(async (tx) => {
      if (sourceChanged) await tx.user.updateMany({ where: { orgId }, data: { ssoSubject: null } });
      return tx.ssoConnection.upsert({ where: { orgId }, create: { orgId, ...data }, update: data });
    });
    res.json(present(conn, org.slug));
  }),
);

ssoAdminRouter.delete(
  "/",
  ah(async (req, res) => {
    const { orgId } = auth(req);
    await prisma.$transaction([
      prisma.ssoConnection.deleteMany({ where: { orgId } }),
      prisma.user.updateMany({ where: { orgId }, data: { ssoSubject: null } }),
    ]);
    res.json({ ok: true });
  }),
);
