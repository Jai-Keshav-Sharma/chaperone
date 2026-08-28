// Live decision stream: WebSocket-fed list with per-decision verdict chips.
// New entries animate in (motion; collapses under reduced motion). The
// socket never backpressures (append-only in memory, capped at 200).

import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { useDecisionStream } from "../lib/useDecisionStream";
import { MetricsTiles } from "./MetricsTiles";
import type { DecisionResponse } from "../lib/types";

function verdictChip(decision: DecisionResponse["decision"]) {
  switch (decision) {
    case "ALLOW":
      return <span className="chip bg-gate-500/10 text-gate-500">ALLOW</span>;
    case "BLOCK":
      return <span className="chip bg-gate-deny/10 text-gate-deny">BLOCK</span>;
    case "ESCALATE":
      return <span className="chip bg-gate-warn/10 text-gate-warn">ESCALATE</span>;
    default:
      return (
        <span className="chip bg-ink-800 text-mist-400">
          {decision.replace("WOULD_", "WOULD ")}
        </span>
      );
  }
}

export function StreamView() {
  const decisions = useDecisionStream(true);
  const reduce = useReducedMotion();

  return (
    <div>
      <MetricsTiles streamCount={decisions.length} />
      <div className="mt-6">
        <h2 className="text-lg font-semibold text-mist-300">
          Live decisions
          <span className="ml-2 font-mono text-sm text-mist-500">{decisions.length}</span>
        </h2>
        {decisions.length === 0 ? (
          <div className="surface mt-4 p-10 text-center text-sm text-mist-500">
            Waiting for decisions. Trigger a tool call through a gate seam and it will appear
            here.
          </div>
        ) : (
          <ul className="mt-4 space-y-2">
            <AnimatePresence initial={false}>
              {decisions.map((d) => (
                <motion.li
                  key={d.entry_seq}
                  layout
                  initial={reduce ? false : { opacity: 0, y: -8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={reduce ? undefined : { opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="surface flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-2.5"
                >
                  <span className="mono w-16 shrink-0 text-xs text-mist-500">
                    #{d.entry_seq}
                  </span>
                  {verdictChip(d.decision)}
                  <span className="mono truncate text-sm text-mist-300">{d.policy_id}</span>
                  <span className="mono truncate text-xs text-mist-500">
                    {d.determining_rule_ids.join(", ") || "-"}
                  </span>
                  <span className="mono ml-auto shrink-0 text-xs text-mist-500">
                    {d.reason_code}
                  </span>
                </motion.li>
              ))}
            </AnimatePresence>
          </ul>
        )}
      </div>
    </div>
  );
}
