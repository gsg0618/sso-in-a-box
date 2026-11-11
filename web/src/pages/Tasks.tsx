import { type FormEvent, useEffect, useState } from "react";
import { api, type Member, type Task } from "../api";

const STATUS_LABEL: Record<Task["status"], string> = { TODO: "To do", IN_PROGRESS: "In progress", DONE: "Done" };

export function Tasks() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const [t, m] = await Promise.all([api("GET", "/tasks"), api("GET", "/members")]);
      setTasks(t.tasks);
      setMembers(m.members.filter((x: Member) => x.active));
    } catch (err) {
      setError((err as Error).message);
    }
  };
  useEffect(() => {
    void load();
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
      await api("POST", "/tasks", { title });
      setTitle("");
    });
  };

  return (
    <div className="card">
      <h1>Tasks</h1>
      {error && <p className="error">{error}</p>}
      <form className="row" onSubmit={add}>
        <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="What needs doing?" />
        <button disabled={!title.trim()}>Add task</button>
      </form>
      {tasks.length === 0 ? (
        <p className="muted">No tasks yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Task</th>
              <th>Status</th>
              <th>Assignee</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tasks.map((t) => (
              <tr key={t.id} className={t.status === "DONE" ? "done" : ""}>
                <td>{t.title}</td>
                <td>
                  <select value={t.status} onChange={(e) => run(() => api("PATCH", "/tasks/" + t.id, { status: e.target.value }))}>
                    {Object.entries(STATUS_LABEL).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <select
                    value={t.assigneeId ?? ""}
                    onChange={(e) => run(() => api("PATCH", "/tasks/" + t.id, { assigneeId: e.target.value || null }))}
                  >
                    <option value="">Unassigned</option>
                    {members.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <button className="link" onClick={() => run(() => api("DELETE", "/tasks/" + t.id))}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
