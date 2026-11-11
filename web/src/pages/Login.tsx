import { type FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError } from "../api";

/** Plain-language versions of the error codes the server sends back after a failed SSO attempt. */
const SSO_ERRORS: Record<string, string> = {
  not_configured: "Single sign-on is not set up for this workspace. Ask a workspace admin, or sign in with a password.",
  session_expired: "That sign-in attempt expired. Please try again.",
  oidc_validation_failed: "Your identity provider's response could not be verified. Ask your admin to check the SSO settings.",
  saml_validation_failed: "Your identity provider's response could not be verified. Ask your admin to check the SSO settings.",
  issuer_mismatch: "The response came from a different identity provider than the one this workspace trusts.",
  discovery_failed: "We could not reach your identity provider. Ask your admin to check the issuer URL.",
  missing_email: "Your identity provider did not send an email address, so we could not find your account.",
  email_unverified: "Your identity provider says your email address is not verified.",
  subject_mismatch: "This email is already linked to a different identity provider account. Ask your admin for help.",
  deactivated: "Your account has been deactivated. Ask a workspace admin for help.",
  sso_failed: "Single sign-on failed. Please try again.",
};

export function Login({ onSignedIn }: { onSignedIn: () => Promise<void> }) {
  const [params] = useSearchParams();
  const ssoError = params.get("sso_error");
  const [slug, setSlug] = useState(params.get("workspace") ?? "");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(ssoError ? (SSO_ERRORS[ssoError] ?? SSO_ERRORS.sso_failed!) : null);
  const [ssoUrl, setSsoUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSsoUrl(null);
    try {
      await api("POST", "/auth/login", { slug, email, password });
      await onSignedIn();
    } catch (err) {
      if (err instanceof ApiError && err.code === "sso_required") setSsoUrl(String(err.data.ssoUrl));
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  /** Finds the workspace's identity provider from the workspace name or the email's domain. */
  const startSso = async () => {
    setError(null);
    if (!slug && !email) return setError("Enter your workspace or your work email first.");
    try {
      const found = await api("POST", "/auth/discover", slug ? { slug } : { email });
      if (found.sso) window.location.assign(found.ssoUrl);
      else setError("We could not find single sign-on for that workspace or email. Sign in with a password instead.");
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <div className="card narrow">
      <h1>Sign in to Taskbox</h1>
      {error && <p className="error">{error}</p>}
      {ssoUrl && (
        <p>
          <a className="button" href={ssoUrl}>
            Continue with single sign-on
          </a>
        </p>
      )}
      <form onSubmit={submit}>
        <label>
          Workspace
          <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="acme" autoCapitalize="none" />
        </label>
        <label>
          Email
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
        </label>
        <label>
          Password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <div className="row">
          <button disabled={busy || !slug || !email || !password}>Sign in</button>
          <button type="button" className="secondary" onClick={startSso}>
            Sign in with SSO
          </button>
        </div>
      </form>
      <p className="muted">
        New here? <Link to="/signup">Create a workspace</Link>
      </p>
    </div>
  );
}
