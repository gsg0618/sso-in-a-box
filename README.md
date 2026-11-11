# SSO-in-a-Box

The SaaS vendor's side of enterprise single sign-on, built end to end.

It is a small multi-tenant task tracker ("Taskbox") where each customer workspace can connect its own identity provider (Okta, Microsoft Entra ID, or anything that speaks OIDC or SAML 2.0) from an admin console, without help from the vendor.

**Status:** steps 1 and 2 of the plan are built. SCIM provisioning and the "Test connection" debugger are planned next.

## What is in here

| Area | What it does |
| --- | --- |
| Multi-tenancy | Workspaces, users, roles (admin and member), password login, sessions. Every query is scoped to the caller's workspace. |
| Sample app | A task tracker, so there is real tenant data to protect. |
| OIDC | Authorization code flow with PKCE, state and nonce, per workspace. |
| SAML 2.0 | SP-initiated login, optional IdP-initiated login, signed assertions, replay protection, SP metadata per workspace. |
| Admin console | A workspace admin configures the connection, sees the URLs to paste into the IdP, routes email domains to SSO, and can require SSO for members. |
| Just-in-time provisioning | A user is created on their first SSO login and linked to the IdP's stable subject ID afterwards. |
| Mock IdP | A fake OIDC and SAML identity provider for local development and tests, so nothing needs an Okta account to run. |

## Run it locally

You need Node 22 or newer and PostgreSQL (or Docker).

```bash
# 1. Database
docker compose up -d            # or point DATABASE_URL at your own Postgres

# 2. API
cd server
npm install
cp .env.example .env            # then set SECRETS_KEY, see the comment in the file
npm run db:deploy
npm run dev                     # http://localhost:4000

# 3. Web app, in a second terminal
cd web
npm install
npm run dev                     # http://localhost:5173
```

Then:

1. Open http://localhost:5173/signup and create a workspace. You are its admin.
2. Go to **Single sign-on**. Open http://localhost:4000/mock-idp in another tab: it lists the issuer, client ID, secret and certificate of the mock IdP. Paste them in, tick **Enable**, and save.
3. Sign out, type the workspace name, and choose **Sign in with SSO**. The mock IdP lets you sign in as any email address.

### Tests

```bash
cd server
createdb sso_test               # once; or set TEST_DATABASE_URL
npm test
```

The tests start the real server and drive whole login flows against the mock IdP, including the attacks listed below.

## Connecting a real identity provider

The **Single sign-on** page shows the exact values for your workspace. In short:

**Okta, OIDC:** create an "OIDC - Web Application" integration. Set the sign-in redirect URI to the one shown. Paste the Okta domain (`https://your-org.okta.com`) as the issuer, plus the client ID and secret.

**Okta, SAML:** create a "SAML 2.0" integration. Set the single sign-on URL and audience URI to the ones shown, and the Name ID format to EmailAddress. Paste Okta's issuer, sign-on URL and signing certificate.

**Entra ID, OIDC:** register an app with a "Web" redirect URI. The issuer is `https://login.microsoftonline.com/<tenant-id>/v2.0`. Create a client secret. Add the optional `email` claim to the ID token, or the app falls back to `preferred_username`.

**Entra ID, SAML:** create a non-gallery enterprise application. The identifier is the audience URI and the reply URL is the ACS URL. Paste the "Microsoft Entra Identifier", the login URL, and the Base64 certificate.

Real IdPs need to reach your `APP_URL` over https, so for local testing run a tunnel (for example `ngrok http 4000`) and set `APP_URL` to the tunnel address.

## Design decisions worth explaining

**Users belong to exactly one workspace.** `User` is unique on `(orgId, email)`, not on email. If accounts were global, a malicious tenant could point its "IdP" at a server that asserts `ceo@victim.com` and be signed in as that person. With per-tenant accounts, whatever an IdP asserts can only reach accounts inside the workspace that configured it.

**The workspace comes from the URL, never from the assertion.** Each workspace has its own redirect URI, ACS URL and SAML entity ID. The entity ID is also the required audience, so a correctly signed assertion issued for workspace A is rejected at workspace B even when both trust the same IdP. There is a test for exactly this.

**The database enforces tenancy too.** `Task` points at its creator and assignee through composite foreign keys `(userId, orgId)`, so a task cannot reference a user from another workspace even if application code has a bug.

**SAML validation is left to a maintained library.** XML signature handling is where SAML implementations get broken (signature wrapping, comment injection), so `@node-saml/node-saml` does that part. On top of it the app pins one certificate per connection, requires a signed assertion, checks audience, issuer and expiry, only accepts responses to requests it issued (stored in Postgres, single use), and rejects replayed assertions.

**OIDC uses PKCE, state and nonce**, and the transaction lives in an httpOnly cookie, so a callback only completes in the browser that started it and only for the workspace it was started for.

**Secrets at rest.** OIDC client secrets are encrypted with AES-256-GCM and are write-only in the API. Passwords are hashed with scrypt. Session tokens are stored only as SHA-256 hashes.

**Lockout protection.** Admins can still use a password when SSO is required, enforcing SSO needs at least one admin with a password, and the last such admin cannot be demoted or deactivated.

**Changing IdP does not strand users.** When a connection moves to a different issuer, stored subject IDs are cleared so people are re-linked by email on their next login.

## What the tests prove

- A workspace cannot read, edit or delete another workspace's tasks or members, and cannot assign tasks across workspaces.
- Members cannot use admin endpoints. Deactivating a user ends their sessions at once.
- OIDC: full login, callback rejected in a different browser, tampered state rejected, a login started for one workspace cannot finish in another.
- SAML: full login, replay rejected, wrong audience rejected, wrong signing key rejected, altered assertion rejected, expired assertion rejected, wrong issuer rejected, unsolicited responses rejected unless allowed.
- The client secret never appears in API responses or in plain text in the database.

## Known limits and what is next

- **Domain verification.** A workspace can claim any unclaimed email domain for login routing. Real products verify ownership with a DNS TXT record first. The impact here is limited to routing, because accounts are per workspace.
- **Outbound requests to the issuer.** The server fetches the OIDC discovery document from an admin-supplied URL. Production use needs an allowlist or a block on private network addresses.
- **No invitations or password reset.** Admins add members with a starting password.
- **No single logout**, and sessions are not shortened to match the IdP session.
- **Next:** SCIM 2.0 provisioning, then the "Test connection" debugger that decodes an assertion or token and explains what is wrong.

## Layout

```
server/   Express + TypeScript API, Prisma schema and migrations, tests
  src/routes/   auth, tasks, members, SSO admin, public SSO endpoints
  src/sso/      OIDC, SAML, just-in-time provisioning
  src/dev/      mock identity provider (never enabled in production)
web/      React + Vite app: login, tasks, members, SSO admin console
```
