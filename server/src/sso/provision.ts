import { prisma } from "../db.ts";
import type { User } from "../generated/prisma/client.ts";

export class SsoError extends Error {
  /** Short machine code, shown on the login page and logged with the full reason. */
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface SsoIdentity {
  /** Stable identifier from the IdP: OIDC `sub` or SAML NameID. */
  subject: string;
  email: string;
  name?: string;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function looksLikeEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && EMAIL.test(value);
}

/**
 * Maps an identity asserted by a tenant's IdP to a user in that same tenant, creating one on first
 * login (just-in-time provisioning). Lookups are always scoped to `orgId`, so whatever an IdP
 * asserts, it can only ever reach accounts inside the tenant that configured it.
 */
export async function findOrProvisionSsoUser(orgId: string, identity: SsoIdentity): Promise<User> {
  const email = identity.email.trim().toLowerCase();
  if (!looksLikeEmail(email)) throw new SsoError("missing_email", "The identity provider did not send a usable email address.");
  if (!identity.subject) throw new SsoError("missing_subject", "The identity provider did not send a user identifier.");

  let user = await prisma.user.findUnique({ where: { orgId_ssoSubject: { orgId, ssoSubject: identity.subject } } });

  if (!user) {
    const byEmail = await prisma.user.findUnique({ where: { orgId_email: { orgId, email } } });
    if (byEmail?.ssoSubject) {
      // The email is already tied to a different IdP account. Refuse rather than guess,
      // because a recycled email address must not inherit the previous owner's account.
      throw new SsoError("subject_mismatch", "This email is linked to a different identity provider account.");
    }
    user = byEmail
      ? await prisma.user.update({ where: { id: byEmail.id }, data: { ssoSubject: identity.subject } })
      : await prisma.user.create({
          data: { orgId, email, name: identity.name?.trim() || email.split("@")[0]!, role: "MEMBER", ssoSubject: identity.subject },
        });
  }

  if (!user.active) throw new SsoError("deactivated", "This account has been deactivated.");
  return user;
}
