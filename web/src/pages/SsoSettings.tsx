import { type FormEvent, useEffect, useState } from "react";
import { api, type SsoSettings } from "../api";

interface Form {
  type: "OIDC" | "SAML";
  enabled: boolean;
  enforced: boolean;
  domains: string;
  oidcIssuer: string;
  oidcClientId: string;
  oidcClientSecret: string;
  samlIdpEntityId: string;
  samlIdpSsoUrl: string;
  samlIdpCertificate: string;
  samlAllowIdpInitiated: boolean;
}

const EMPTY: Form = {
  type: "OIDC",
  enabled: false,
  enforced: false,
  domains: "",
  oidcIssuer: "",
  oidcClientId: "",
  oidcClientSecret: "",
  samlIdpEntityId: "",
  samlIdpSsoUrl: "",
  samlIdpCertificate: "",
  samlAllowIdpInitiated: false,
};

function toForm(c: SsoSettings["connection"]): Form {
  if (!c) return EMPTY;
  return {
    type: c.type,
    enabled: c.enabled,
    enforced: c.enforced,
    domains: c.domains.join(", "),
    oidcIssuer: c.oidcIssuer ?? "",
    oidcClientId: c.oidcClientId ?? "",
    oidcClientSecret: "",
    samlIdpEntityId: c.samlIdpEntityId ?? "",
    samlIdpSsoUrl: c.samlIdpSsoUrl ?? "",
    samlIdpCertificate: c.samlIdpCertificate ?? "",
    samlAllowIdpInitiated: c.samlAllowIdpInitiated,
  };
}

function Copyable({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="copyable">
      <span className="muted">{label}</span>
      <code>{value}</code>
      <button type="button" className="link" onClick={copy}>
        {copied ? "Copied" : "Copy"}
      </button>
    </div>
  );
}

export function SsoSettingsPage() {
  const [settings, setSettings] = useState<SsoSettings | null>(null);
  const [form, setForm] = useState<Form>(EMPTY);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api<SsoSettings>("GET", "/admin/sso")
      .then((s) => {
        setSettings(s);
        setForm(toForm(s.connection));
      })
      .catch((err) => setError(err.message));
  }, []);

  if (!settings) return <div className="card">{error ? <p className="error">{error}</p> : <p className="muted">Loading…</p>}</div>;

  const sp = settings.serviceProvider;
  const conn = settings.connection;
  const text = (key: keyof Form) => ({
    value: form[key] as string,
    onChange: (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value }),
  });
  const check = (key: keyof Form) => ({
    type: "checkbox" as const,
    checked: form[key] as boolean,
    onChange: (e: { target: { checked: boolean } }) => setForm({ ...form, [key]: e.target.checked }),
  });

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSaved(false);
    try {
      const body = { ...form, domains: form.domains.split(/[\s,]+/).filter(Boolean) };
      const next = await api<SsoSettings>("PUT", "/admin/sso", body);
      setSettings(next);
      setForm(toForm(next.connection));
      setSaved(true);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const remove = async () => {
    if (!window.confirm("Remove the SSO connection? People who only sign in through SSO will lose access.")) return;
    try {
      await api("DELETE", "/admin/sso");
      setSettings({ ...settings, connection: null });
      setForm(EMPTY);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const cert = conn?.samlCertificateInfo;

  return (
    <div className="card">
      <h1>Single sign-on</h1>
      <p className="muted">Connect this workspace to your company's identity provider, such as Okta or Microsoft Entra ID.</p>

      <form onSubmit={save}>
        <label>
          Protocol
          <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as Form["type"] })}>
            <option value="OIDC">OpenID Connect (OIDC)</option>
            <option value="SAML">SAML 2.0</option>
          </select>
        </label>

        <h2>Step 1: enter these in your identity provider</h2>
        {form.type === "OIDC" ? (
          <>
            <Copyable label="Sign-in redirect URI" value={sp.oidcRedirectUri} />
            <Copyable label="Initiate login URI (optional)" value={sp.startUrl} />
            <p className="muted">Create a "Web" application with the authorization code grant, and allow the openid, email and profile scopes.</p>
          </>
        ) : (
          <>
            <Copyable label="Single sign-on URL (ACS URL)" value={sp.samlAcsUrl} />
            <Copyable label="Audience URI (SP entity ID)" value={sp.samlEntityId} />
            <p className="muted">
              Set the Name ID to the user's email address. You can also import our metadata from the Audience URI above, which serves the XML.
            </p>
          </>
        )}

        <h2>Step 2: paste your identity provider's details</h2>
        {form.type === "OIDC" ? (
          <>
            <label>
              Issuer URL
              <input {...text("oidcIssuer")} placeholder="https://your-org.okta.com" />
            </label>
            <label>
              Client ID
              <input {...text("oidcClientId")} />
            </label>
            <label>
              Client secret
              <input
                type="password"
                {...text("oidcClientSecret")}
                placeholder={conn?.oidcClientSecretSet ? "Saved. Leave empty to keep it." : ""}
                autoComplete="new-password"
              />
            </label>
          </>
        ) : (
          <>
            <label>
              Identity provider issuer (entity ID)
              <input {...text("samlIdpEntityId")} placeholder="http://www.okta.com/exk..." />
            </label>
            <label>
              Identity provider sign-on URL
              <input {...text("samlIdpSsoUrl")} placeholder="https://your-org.okta.com/app/.../sso/saml" />
            </label>
            <label>
              Signing certificate (X.509)
              <textarea rows={6} {...text("samlIdpCertificate")} placeholder="-----BEGIN CERTIFICATE-----" />
            </label>
            {cert && (
              <p className={cert.expired ? "error" : "muted"}>
                {cert.expired ? "This certificate has expired. Logins will fail until you paste the new one. " : ""}
                Certificate for {cert.subject}, valid until {new Date(cert.validTo).toLocaleDateString()}.
              </p>
            )}
            <label className="check">
              <input {...check("samlAllowIdpInitiated")} />
              Allow sign-in started from the identity provider's dashboard (less strict)
            </label>
          </>
        )}

        <h2>Step 3: turn it on</h2>
        <label>
          Email domains to route to this connection (optional)
          <input {...text("domains")} placeholder="acme.com, acme.co.uk" />
        </label>
        <label className="check">
          <input {...check("enabled")} />
          Enable single sign-on for this workspace
        </label>
        <label className="check">
          <input {...check("enforced")} />
          Require SSO for members (admins can still use a password, in case the connection breaks)
        </label>

        {error && <p className="error">{error}</p>}
        {saved && <p className="ok">Saved.</p>}
        <div className="row">
          <button>Save</button>
          {conn?.enabled && (
            <a className="button secondary" href={sp.startUrl} target="_blank" rel="noreferrer">
              Test sign-in in a new tab
            </a>
          )}
          {conn && (
            <button type="button" className="link danger" onClick={remove}>
              Remove connection
            </button>
          )}
        </div>
      </form>
    </div>
  );
}
