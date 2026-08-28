// Token gate (flows/03 SEC-3: the approval inbox is NEVER unauthenticated).
// The session token is entered once at startup and kept in memory.

import { useState } from "react";
import { Key, ArrowRight } from "@phosphor-icons/react";
import { setSessionToken } from "../lib/api";

export function TokenGate({ onToken }: { onToken: (token: string) => void }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const token = value.trim();
    if (!token) {
      setError("Enter the session token printed by `chaperone serve`.");
      return;
    }
    setSessionToken(token);
    setError(null);
    onToken(token);
  };

  return (
    <div className="flex min-h-[100dvh] items-center justify-center p-4">
      <form
        onSubmit={submit}
        className="surface w-full max-w-sm p-6"
        aria-label="Session token"
      >
        <div className="flex items-center gap-2">
          <Key size={18} className="text-gate-500" />
          <h1 className="font-mono text-base font-semibold text-mist-300">
            chaperone dashboard
          </h1>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-mist-500">
          Enter the session token printed by{" "}
          <code className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-xs text-mist-300">
            chaperone serve
          </code>{" "}
          at startup.
        </p>
        <label className="mt-4 block">
          <span className="label">Session token</span>
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-ink-600 bg-ink-850 px-3 py-2 font-mono text-sm text-mist-300 outline-none transition-colors focus:border-gate-500"
            placeholder="chp_..."
            autoFocus
          />
        </label>
        {error && <p className="mt-2 text-sm text-gate-deny">{error}</p>}
        <button type="submit" className="btn btn-primary mt-4 w-full">
          Connect <ArrowRight size={14} />
        </button>
      </form>
    </div>
  );
}
