// API client. Auth: the dashboard takes a session token at startup (flows/03:
// "an approval inbox is NEVER unauthenticated" - review-2 SEC-3) and sends it
// as a Bearer header on every request. The token is entered once and kept in
// memory; nothing is persisted.

import type {
  CheckpointRow,
  EscalationRow,
  LedgerEntry,
  VerifyResult,
} from "./types";

const API_BASE = "/v1";

export class ApiError extends Error {
  status: number;
  code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let sessionToken: string | null = null;

export function setSessionToken(token: string) {
  sessionToken = token;
}

export function hasSessionToken(): boolean {
  return sessionToken !== null;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!sessionToken) {
    throw new ApiError(401, "NO_SESSION", "no session token; start with --token");
  }
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${sessionToken}`,
      ...init?.headers,
    },
  });
  if (!res.ok) {
    let code = "HTTP_" + res.status;
    let message = res.statusText;
    try {
      const body = await res.json();
      code = body?.error?.code ?? code;
      message = body?.error?.message ?? message;
    } catch {
      // non-JSON error body
    }
    throw new ApiError(res.status, code, message);
  }
  return res.json() as Promise<T>;
}

export const api = {
  pendingEscalations: () => request<EscalationRow[]>("/escalations"),
  resolveEscalation: (id: string, resolution: "approve" | "deny", note?: string) =>
    request<{ resolved: string }>(`/escalations/${id}/resolve`, {
      method: "POST",
      body: JSON.stringify({ resolution, note }),
    }),
  ledgerEntries: (afterSeq = 0, limit = 100) =>
    request<{ entries: LedgerEntry[]; next_after_seq: number | null }>(
      `/ledger/entries?after_seq=${afterSeq}&limit=${limit}`,
    ),
  verifyLedger: () => request<VerifyResult>("/ledger/verify"),
  checkpoints: () => request<CheckpointRow[]>("/ledger/checkpoints"),
};
