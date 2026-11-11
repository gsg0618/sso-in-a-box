import type { Server } from "node:http";
import { createApp } from "../src/app.ts";
import { prisma } from "../src/db.ts";
import { env } from "../src/env.ts";

export const BASE = env.APP_URL;
export { env, prisma };

let server: Server | undefined;

/** The server listens on a real port because the OIDC client fetches discovery documents over HTTP. */
export async function startServer() {
  const app = await createApp();
  await new Promise<void>((resolve) => {
    server = app.listen(env.PORT, resolve);
  });
}

export async function stopServer() {
  await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
  await prisma.$disconnect();
}

/** Every table hangs off Organization with cascading deletes, so this empties the database. */
export async function resetDb() {
  await prisma.organization.deleteMany();
}

export interface Reply {
  status: number;
  body: any;
  text: string;
  location: string | null;
}

/** A tiny stand-in for a browser: keeps cookies between requests and never follows redirects by itself. */
export class Browser {
  cookies = new Map<string, string>();

  async request(method: string, url: string, opts: { json?: unknown; form?: Record<string, string>; headers?: Record<string, string> } = {}): Promise<Reply> {
    const headers: Record<string, string> = { ...opts.headers };
    if (this.cookies.size) headers.cookie = [...this.cookies].map(([k, v]) => k + "=" + v).join("; ");
    let body: string | undefined;
    if (opts.json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(opts.json);
    } else if (opts.form) {
      headers["content-type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams(opts.form).toString();
    }
    const res = await fetch(url.startsWith("http") ? url : BASE + url, { method, headers, body, redirect: "manual" });
    for (const line of res.headers.getSetCookie()) {
      const [pair] = line.split(";");
      const eq = pair!.indexOf("=");
      const name = pair!.slice(0, eq);
      const value = pair!.slice(eq + 1);
      if (value === "" || /expires=Thu, 01 Jan 1970/i.test(line)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await res.text();
    let parsed: any = null;
    try {
      parsed = JSON.parse(text);
    } catch {
      // not JSON
    }
    return { status: res.status, body: parsed, text, location: res.headers.get("location") };
  }

  get(url: string) {
    return this.request("GET", url);
  }
  post(url: string, json?: unknown) {
    return this.request("POST", url, { json: json ?? {} });
  }
  put(url: string, json: unknown) {
    return this.request("PUT", url, { json });
  }
  patch(url: string, json: unknown) {
    return this.request("PATCH", url, { json });
  }
  delete(url: string) {
    return this.request("DELETE", url);
  }
}

export const PASSWORD = "correct horse battery";

/** Creates a workspace and returns a browser signed in as its first admin. */
export async function signup(slug: string, email = "admin@" + slug + ".test") {
  const browser = new Browser();
  const res = await browser.post("/api/auth/signup", { orgName: slug + " Inc", slug, name: "Admin " + slug, email, password: PASSWORD });
  if (res.status !== 201) throw new Error("signup failed: " + res.text);
  return browser;
}

export async function login(slug: string, email: string, password = PASSWORD) {
  const browser = new Browser();
  const res = await browser.post("/api/auth/login", { slug, email, password });
  return { browser, res };
}

/** Reads the `sso_error` code from a redirect back to the login page. */
export function ssoError(reply: Reply): string | null {
  return reply.location ? new URL(reply.location).searchParams.get("sso_error") : null;
}
