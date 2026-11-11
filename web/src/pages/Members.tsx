import { type FormEvent, useEffect, useState } from "react";
import { api, type Me, type Member } from "../api";

export function Members({ me }: { me: Me }) {
  const isAdmin = me.user.role === "ADMIN";
  const [members, setMembers] = useState<Member[]>([]);
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState<string | null>(null);

  const load = async () => setMembers((await api("GET", "/members")).members);
  useEffect(() => {
    load().catch((err) => setError(err.message));
  }, []);

  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const add = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await api("POST", "/members", form);
      setForm({ name: "", email: "", password: "" });
    });
  };

  return (
    <div className="card">
      <h1>Members</h1>
      {error && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Email</th>
            <th>Signs in with</th>
            <th>Role</th>
            {isAdmin && <th />}
          </tr>
        </thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.id} className={m.active ? "" : "done"}>
              <td>{m.name}</td>
              <td>{m.email}</td>
              <td>{[m.hasPassword && "Password", m.ssoLinked && "SSO"].filter(Boolean).join(" + ") || "Not yet signed in"}</td>
              <td>
                {isAdmin ? (
                  <select value={m.role} onChange={(e) => run(() => api("PATCH", "/members/" + m.id, { role: e.target.value }))}>
                    <option value="ADMIN">Admin</option>
                    <option value="MEMBER">Member</option>
                  </select>
                ) : m.role === "ADMIN" ? (
                  "Admin"
                ) : (
                  "Member"
                )}
              </td>
              {isAdmin && (
                <td>
                  <button className="link" onClick={() => run(() => api("PATCH", "/members/" + m.id, { active: !m.active }))}>
                    {m.active ? "Deactivate" : "Reactivate"}
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>

      {isAdmin && (
        <>
          <h2>Add a member</h2>
          <p className="muted">People who sign in through your identity provider are added automatically on their first login.</p>
          <form className="row" onSubmit={add}>
            <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <input type="email" placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
            <input
              type="password"
              placeholder="Starting password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              minLength={10}
              required
            />
            <button>Add</button>
          </form>
        </>
      )}
    </div>
  );
}
