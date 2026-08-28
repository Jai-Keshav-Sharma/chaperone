// Approval inbox (flows/03): pending escalations with what/why/agent/params,
// an expiry countdown, and approve/deny + note. Empty and error states are
// explicit. Refreshes on an interval; actions are optimistic with rollback.

import { useCallback, useEffect, useState } from "react";
import { Check, X, Warning } from "@phosphor-icons/react";
import { api } from "../lib/api";
import type { EscalationRow } from "../lib/types";

function timeLeft(expiresAt: string, now: number): string {
  const ms = new Date(expiresAt).getTime() - now;
  if (ms <= 0) return "expired";
  const m = Math.floor(ms / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

export function InboxView() {
  const [rows, setRows] = useState<EscalationRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [note, setNote] = useState<Record<string, string>>({});
  // Countdown tick: re-renders every second so timeLeft() stays fresh
  // without calling Date.now() during render (React purity).
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      setError(null);
      setRows(await api.pendingEscalations());
    } catch (e) {
      setError(e instanceof Error ? e.message : "load failed");
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000); // keep the inbox fresh
    const clock = setInterval(() => setNow(Date.now()), 1000); // countdown ticks
    return () => {
      clearInterval(timer);
      clearInterval(clock);
    };
  }, [load]);

  const resolve = async (row: EscalationRow, resolution: "approve" | "deny") => {
    setBusyId(row.escalation_id);
    try {
      await api.resolveEscalation(row.escalation_id, resolution, note[row.escalation_id]);
      setRows((prev) => prev?.filter((r) => r.escalation_id !== row.escalation_id) ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "resolve failed");
    } finally {
      setBusyId(null);
    }
  };

  if (error) {
    return (
      <div className="surface flex items-center gap-3 p-6 text-sm text-gate-deny">
        <Warning size={18} weight="duotone" />
        <span>Inbox unavailable: {error}. Is the gate running?</span>
      </div>
    );
  }

  if (rows === null) {
    return (
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2" aria-busy="true">
        {[0, 1].map((i) => (
          <div key={i} className="surface h-40 animate-pulse bg-ink-850" />
        ))}
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className="surface flex flex-col items-center gap-3 p-10 text-center">
        <Check size={24} className="text-gate-500" />
        <p className="font-medium text-mist-300">No pending approvals</p>
        <p className="text-sm text-mist-500">
          Escalations created by the gate will appear here.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-mist-300">
        Pending approvals
        <span className="ml-2 font-mono text-sm text-mist-500">{rows.length}</span>
      </h2>
      <ul className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {rows.map((row) => (
          <li key={row.escalation_id} className="surface surface-hover p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="mono text-xs text-gate-warn">{row.escalation_id}</div>
                <h3 className="mt-1 truncate font-medium text-mist-300">{row.tool}</h3>
                <p className="mono mt-0.5 text-xs text-mist-500">
                  {row.agent_id} · {row.policy_id} v{row.policy_version}
                </p>
              </div>
              <span
                className={`chip shrink-0 ${
                  timeLeft(row.expires_at, now) === "expired"
                    ? "bg-gate-deny/10 text-gate-deny"
                    : "bg-ink-800 text-mist-400"
                }`}
              >
                {timeLeft(row.expires_at, now)}
              </span>
            </div>

            <details className="mt-3">
              <summary className="cursor-pointer text-xs text-mist-500 hover:text-mist-300">
                Proposed params
              </summary>
              <pre className="mt-2 overflow-x-auto rounded bg-ink-850 p-3 font-mono text-xs leading-relaxed text-mist-400">
                {row.proposed_params ?? "(purged after retention)"}
              </pre>
            </details>

            <div className="mt-3 space-y-2">
              <label className="block">
                <span className="sr-only">Resolution note</span>
                <input
                  value={note[row.escalation_id] ?? ""}
                  onChange={(e) =>
                    setNote((prev) => ({ ...prev, [row.escalation_id]: e.target.value }))
                  }
                  placeholder="Note (optional)"
                  className="w-full rounded-md border border-ink-600 bg-ink-850 px-3 py-1.5 text-sm text-mist-300 outline-none transition-colors focus:border-gate-500"
                />
              </label>
              <div className="flex gap-2">
                <button
                  onClick={() => resolve(row, "approve")}
                  disabled={busyId === row.escalation_id}
                  className="btn btn-primary flex-1"
                >
                  <Check size={14} weight="bold" /> Approve
                </button>
                <button
                  onClick={() => resolve(row, "deny")}
                  disabled={busyId === row.escalation_id}
                  className="btn btn-deny flex-1"
                >
                  <X size={14} weight="bold" /> Deny
                </button>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
