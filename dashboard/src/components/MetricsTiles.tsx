// Metrics tiles: gate posture + pending approvals + ledger head + stream
// count. Data-dense cockpit: mono numerals, hairlines, no card boxes
// (VISUAL_DENSITY 7).

import { useEffect, useState } from "react";
import { ShieldCheck, Hourglass, ListNumbers, Radio } from "@phosphor-icons/react";
import { api } from "../lib/api";

interface Metrics {
  pending: number;
  ledgerHead: number | null;
  streamCount: number;
}

export function MetricsTiles({ streamCount = 0 }: { streamCount?: number }) {
  const [metrics, setMetrics] = useState<Metrics>({
    pending: 0,
    ledgerHead: null,
    streamCount: 0,
  });

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [pending, entries] = await Promise.all([
          api.pendingEscalations(),
          api.ledgerEntries(0, 1),
        ]);
        if (cancelled) return;
        setMetrics({
          pending: pending.length,
          ledgerHead: entries.entries[0]?.entry_seq ?? null,
          streamCount,
        });
      } catch {
        // gate unreachable: tiles stay empty (surface, don't crash)
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [streamCount]);

  const tiles = [
    {
      label: "Gate",
      value: "ENFORCE",
      icon: <ShieldCheck size={16} weight="duotone" />,
      accent: "text-gate-500",
    },
    {
      label: "Pending approvals",
      value: String(metrics.pending),
      icon: <Hourglass size={16} weight="duotone" />,
      accent: "text-gate-warn",
    },
    {
      label: "Ledger head",
      value: metrics.ledgerHead === null ? "..." : `#${metrics.ledgerHead}`,
      icon: <ListNumbers size={16} weight="duotone" />,
      accent: "text-mist-400",
    },
    {
      label: "Stream",
      value: String(streamCount),
      icon: <Radio size={16} weight="duotone" />,
      accent: "text-mist-400",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-ink-700 bg-ink-700 lg:grid-cols-4">
      {tiles.map((t) => (
        <div key={t.label} className="flex items-center gap-3 bg-ink-900 px-4 py-3">
          <span className={t.accent}>{t.icon}</span>
          <div className="min-w-0">
            <div className="label truncate">{t.label}</div>
            <div className={`mono text-lg leading-tight ${t.accent}`}>{t.value}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
