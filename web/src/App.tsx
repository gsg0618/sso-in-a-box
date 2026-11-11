import { useCallback, useEffect, useState } from "react";
import { Navigate, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { api, type Me } from "./api";
import { Login } from "./pages/Login";
import { Members } from "./pages/Members";
import { Signup } from "./pages/Signup";
import { SsoSettingsPage } from "./pages/SsoSettings";
import { Tasks } from "./pages/Tasks";

export function App() {
  // undefined = still loading, null = signed out
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const navigate = useNavigate();

  const refresh = useCallback(async () => {
    try {
      setMe(await api<Me>("GET", "/auth/me"));
    } catch {
      setMe(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  if (me === undefined) return <p className="center muted">Loading…</p>;

  if (me === null) {
    return (
      <Routes>
        <Route path="/login" element={<Login onSignedIn={refresh} />} />
        <Route path="/signup" element={<Signup onSignedIn={refresh} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  const isAdmin = me.user.role === "ADMIN";
  const logout = async () => {
    await api("POST", "/auth/logout");
    setMe(null);
    navigate("/login");
  };

  return (
    <>
      <header className="topbar">
        <strong>{me.org.name}</strong>
        <nav>
          <NavLink to="/">Tasks</NavLink>
          <NavLink to="/members">Members</NavLink>
          {isAdmin && <NavLink to="/settings/sso">Single sign-on</NavLink>}
        </nav>
        <span className="muted">
          {me.user.name} ({me.user.role === "ADMIN" ? "admin" : "member"})
        </span>
        <button className="link" onClick={logout}>
          Sign out
        </button>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Tasks />} />
          <Route path="/members" element={<Members me={me} />} />
          {isAdmin && <Route path="/settings/sso" element={<SsoSettingsPage />} />}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </>
  );
}
