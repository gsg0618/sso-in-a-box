import { type FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export function Signup({ onSignedIn }: { onSignedIn: () => Promise<void> }) {
  const [form, setForm] = useState({ orgName: "", slug: "", name: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (key: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [key]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("POST", "/auth/signup", form);
      await onSignedIn();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card narrow">
      <h1>Create a workspace</h1>
      <p className="muted">You will be its first admin.</p>
      {error && <p className="error">{error}</p>}
      <form onSubmit={submit}>
        <label>
          Company name
          <input value={form.orgName} onChange={set("orgName")} placeholder="Acme Inc" required />
        </label>
        <label>
          Workspace URL name
          <input value={form.slug} onChange={set("slug")} placeholder="acme" autoCapitalize="none" required />
        </label>
        <label>
          Your name
          <input value={form.name} onChange={set("name")} required />
        </label>
        <label>
          Email
          <input type="email" value={form.email} onChange={set("email")} required />
        </label>
        <label>
          Password (at least 10 characters)
          <input type="password" value={form.password} onChange={set("password")} minLength={10} required />
        </label>
        <button disabled={busy}>Create workspace</button>
      </form>
      <p className="muted">
        Already have one? <Link to="/login">Sign in</Link>
      </p>
    </div>
  );
}
