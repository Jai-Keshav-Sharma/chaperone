// Ledger explorer: paginated entries, a verify action with the result
// inline, and checkpoint badges (signed / anchored states).

import { useCallback, useEffect, useState } from "react";
import { Check, ShieldCheck, Anchor, Link } from "@phosphor-icons/react";
import { api } from "../lib/api";
import type { CheckpointRow, LedgerEntry, VerifyResult } from "../lib/types";

export function LedgerView() {
  const [entries, setEntries] = useState<LedgerEntry[] | null>(null);
  const [nextSeq, setNextSeq] = useState<number | null>(null);
  const [checkpoints, setCheckpoints] = useState<CheckpointRow[]>([]);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setError(null);
      const [page, cps] = await Promise.all([
        api.ledgerEntries(0, 100),
        api.checkpoints(),
      ]);
      setEntries(page.entries);
      setNextSeq(page.next_after_seq);
      setCheckpoints(cps);
    } catch (e) {
      setError(e instanceof Error ? e.message : "load failed");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const runVerify = async () => {
    setVerifying(true);
    try {
      setVerify(await api.verifyLedger());
    } catch (e) {
      setError(e instanceof Error ? e.message : "verify failed");
    } finally {
      setVerifying(false);
    }
  };

  const latestCheckpoint = checkpoints[0];

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-mist-300">Ledger</h2>
        <div className="flex flex-wrap items-center gap-3">
          {latestCheckpoint && (
            <span
              className="chip bg-ink-800 text-mist-400"
              title={`${latestCheckpoint.tree_size} entries · ${latestCheckpoint.root_hash.slice(0, 12)}…`}
            >
              <ShieldCheck size={13} className="text-gate-500" />
              checkpoint #{latestCheckpoint.checkpoint_id}
              {latestCheckpoint.anchored_rekor && (
                <Anchor size={12} className="text-mist-400" aria-label="anchored in Rekor" />
              )}
            </span>
          )}
          <button
            onClick={runVerify}
            disabled={verifying}
            className="btn btn-ghost"
          >
            <Link size={14} /> {verifying ? "Verifying..." : "Verify chain"}
          </button>
        </div>
      </div>

      {verify && (
        <div
          className={`mt-4 flex items-center gap-2 rounded-md border px-4 py-2 font-mono text-sm ${
            verify.status === "ok"
              ? "border-gate-500/40 bg-gate-500/10 text-gate-500"
              : "border-gate-deny/40 bg-gate-deny/10 text-gate-deny"
          }`}
        >
          <Check size={14} weight="bold" />
          {verify.status === "ok"
            ? `CHAIN OK (${verify.entries} entries)`
            : `CHAIN BROKEN at seq ${verify.broken_at}: ${verify.reason}`}
        </div>
      )}

      {error && <p className="mt-4 text-sm text-gate-deny">{error}</p>}

      {entries === null ? (
        <div className="surface mt-4 h-40 animate-pulse bg-ink-850" aria-busy="true" />
      ) : entries.length === 0 ? (
        <div className="surface mt-4 p-10 text-center text-sm text-mist-500">
          The ledger is empty. Genesis is written on first startup.
        </div>
      ) : (
        <>
          <ul className="mt-4 divide-y divide-ink-800 overflow-hidden rounded-lg border border-ink-700 bg-ink-900">
            {entries.map((e) => (
              <li
                key={e.entry_seq}
                className="grid grid-cols-[3.5rem_1fr_auto] items-center gap-x-4 gap-y-0.5 px-4 py-2.5 md:grid-cols-[3.5rem_7rem_1fr_auto]"
              >
                <span className="mono text-xs text-mist-500">#{e.entry_seq}</span>
                <span className="mono hidden text-xs text-mist-500 md:inline">
                  {e.entry_type}
                </span>
                <span className="mono truncate text-sm text-mist-300">
                  {e.tool}
                  <span className="ml-2 text-xs text-mist-500">{e.decision}</span>
                </span>
                <span className="mono shrink-0 text-xs text-mist-500">{e.entry_ts}</span>
              </li>
            ))}
          </ul>
          {nextSeq !== null && (
            <button
              onClick={() => api.ledgerEntries(nextSeq, 100).then((p) => setEntries(p.entries))}
              className="btn btn-ghost mt-4"
            >
              Load older
            </button>
          )}
        </>
      )}
    </div>
  );
}
