import { env } from "../env.ts";

/** The values a customer's IT admin copies into Okta or Entra ID. They are unique per tenant. */
export function spUrls(orgSlug: string) {
  const base = env.APP_URL + "/api/sso/" + encodeURIComponent(orgSlug);
  return {
    startUrl: base + "/start",
    oidcRedirectUri: base + "/oidc/callback",
    samlAcsUrl: base + "/saml/acs",
    /** Doubles as the SAML audience and the metadata URL. */
    samlEntityId: base + "/saml/metadata",
  };
}
