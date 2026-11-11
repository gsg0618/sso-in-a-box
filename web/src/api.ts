export class ApiError extends Error {
  status: number;
  code: string;
  data: Record<string, unknown>;

  constructor(status: number, data: Record<string, unknown>) {
    super(typeof data.message === "string" ? data.message : "Something went wrong.");
    this.status = status;
    this.code = typeof data.error === "string" ? data.error : "error";
    this.data = data;
  }
}

export async function api<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch("/api" + path, {
    method,
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data);
  return data as T;
}

export interface Me {
  user: { id: string; email: string; name: string; role: "ADMIN" | "MEMBER" };
  org: { id: string; slug: string; name: string };
}

export interface Member {
  id: string;
  email: string;
  name: string;
  role: "ADMIN" | "MEMBER";
  active: boolean;
  hasPassword: boolean;
  ssoLinked: boolean;
}

export interface Task {
  id: string;
  title: string;
  status: "TODO" | "IN_PROGRESS" | "DONE";
  assigneeId: string | null;
  assignee: { id: string; name: string; email: string } | null;
}

export interface SsoSettings {
  serviceProvider: { startUrl: string; oidcRedirectUri: string; samlAcsUrl: string; samlEntityId: string };
  connection: null | {
    type: "OIDC" | "SAML";
    enabled: boolean;
    enforced: boolean;
    domains: string[];
    oidcIssuer: string | null;
    oidcClientId: string | null;
    oidcClientSecretSet: boolean;
    samlIdpEntityId: string | null;
    samlIdpSsoUrl: string | null;
    samlIdpCertificate: string | null;
    samlCertificateInfo: null | { subject: string; validTo: string; expired: boolean; fingerprintSha256: string };
    samlAllowIdpInitiated: boolean;
  };
}
