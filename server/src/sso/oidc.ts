import * as oidc from "openid-client";
import { decryptSecret } from "../crypto.ts";
import { env } from "../env.ts";
import type { SsoConnection } from "../generated/prisma/client.ts";
import { looksLikeEmail, SsoError, type SsoIdentity } from "./provision.ts";
import { spUrls } from "./urls.ts";

/** What we keep in a short-lived cookie between the redirect to the IdP and the callback. */
export interface OidcTransaction {
  slug: string;
  state: string;
  nonce: string;
  codeVerifier: string;
}

const configCache = new Map<string, { key: string; config: oidc.Configuration }>();

/** Plain-http issuers are only tolerated outside production (the local mock IdP uses one). */
export function issuerAllowed(issuer: string): boolean {
  try {
    const url = new URL(issuer);
    return url.protocol === "https:" || (url.protocol === "http:" && !env.isProd);
  } catch {
    return false;
  }
}

async function getConfig(conn: SsoConnection): Promise<oidc.Configuration> {
  if (!conn.oidcIssuer || !conn.oidcClientId || !conn.oidcClientSecretEnc) {
    throw new SsoError("not_configured", "The OIDC connection is missing its issuer, client ID or client secret.");
  }
  if (!issuerAllowed(conn.oidcIssuer)) throw new SsoError("bad_issuer", "The OIDC issuer must be an https URL.");

  const key = conn.id + ":" + conn.updatedAt.getTime();
  const cached = configCache.get(conn.id);
  if (cached?.key === key) return cached.config;

  const issuer = new URL(conn.oidcIssuer);
  let config: oidc.Configuration;
  try {
    config = await oidc.discovery(issuer, conn.oidcClientId, decryptSecret(conn.oidcClientSecretEnc), undefined, {
      execute: issuer.protocol === "http:" ? [oidc.allowInsecureRequests] : [],
      timeout: 10,
    });
  } catch (err) {
    throw new SsoError("discovery_failed", "Could not load the identity provider's OIDC configuration: " + (err as Error).message);
  }
  configCache.set(conn.id, { key, config });
  return config;
}

export async function oidcStart(conn: SsoConnection, orgSlug: string): Promise<{ url: string; tx: OidcTransaction }> {
  const config = await getConfig(conn);
  const tx: OidcTransaction = {
    slug: orgSlug,
    state: oidc.randomState(),
    nonce: oidc.randomNonce(),
    codeVerifier: oidc.randomPKCECodeVerifier(),
  };
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: spUrls(orgSlug).oidcRedirectUri,
    scope: "openid email profile",
    state: tx.state,
    nonce: tx.nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(tx.codeVerifier),
    code_challenge_method: "S256",
  });
  return { url: url.href, tx };
}

/**
 * Exchanges the authorization code and validates the ID token. openid-client checks the signature,
 * issuer, audience, expiry, state and nonce; we add the checks on the claims we rely on.
 */
export async function oidcCallback(conn: SsoConnection, orgSlug: string, query: string, tx: OidcTransaction): Promise<SsoIdentity> {
  const config = await getConfig(conn);
  // Rebuilt from our own configured URL, not from request headers, so a spoofed Host cannot alter it.
  const currentUrl = new URL(spUrls(orgSlug).oidcRedirectUri + query);

  let claims: oidc.IDToken | undefined;
  try {
    const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
      pkceCodeVerifier: tx.codeVerifier,
      expectedState: tx.state,
      expectedNonce: tx.nonce,
      idTokenExpected: true,
    });
    claims = tokens.claims();
  } catch (err) {
    throw new SsoError("oidc_validation_failed", "The identity provider's response was rejected: " + (err as Error).message);
  }
  if (!claims) throw new SsoError("oidc_validation_failed", "The identity provider did not return an ID token.");

  // Entra ID often omits `email` and puts the sign-in name in `preferred_username`.
  const email = looksLikeEmail(claims.email) ? claims.email : claims.preferred_username;
  if (!looksLikeEmail(email)) {
    throw new SsoError("missing_email", "The ID token has no email claim. Add the email scope or claim in the IdP.");
  }
  if (claims.email_verified === false) {
    throw new SsoError("email_unverified", "The identity provider says this email address is not verified.");
  }
  return { subject: claims.sub, email, name: typeof claims.name === "string" ? claims.name : undefined };
}
