// App shell: fixed sidebar nav (single line, 64px, icons from Phosphor),
// content area with the active view. Theme locked dark (index.css).

import { useState } from "react";
import { ShieldCheck, Tray, Radio, BookOpenText, FileText } from "@phosphor-icons/react";
import { MetricsTiles } from "./MetricsTiles";
import { InboxView } from "./InboxView";
import { StreamView } from "./StreamView";
import { LedgerView } from "./LedgerView";
import { PoliciesView } from "./PoliciesView";
import { TokenGate } from "./TokenGate";
import { hasSessionToken } from "../lib/api";

type View = "inbox" | "stream" | "ledger" | "policies";

const NAV: { id: View; label: string; icon: React.ReactNode }[] = [
  { id: "inbox", label: "Inbox", icon: <Tray size={18} weight="duotone" /> },
  { id: "stream", label: "Stream", icon: <Radio size={18} weight="duotone" /> },
  { id: "ledger", label: "Ledger", icon: <BookOpenText size={18} weight="duotone" /> },
  { id: "policies", label: "Policies", icon: <FileText size={18} weight="duotone" /> },
];

export function App() {
  const [view, setView] = useState<View>("inbox");
  const [token, setToken] = useState<string | null>(null);
  const authed = hasSessionToken() || token !== null;

  return (
    <div className="min-h-[100dvh]">
      {!authed ? (
        <TokenGate onToken={setToken} />
      ) : (
        <div className="grid min-h-[100dvh] grid-cols-1 md:grid-cols-[220px_1fr]">
          <aside className="border-b border-ink-700 bg-ink-900 md:border-b-0 md:border-r">
            <div className="flex h-16 items-center gap-2 px-4">
              <ShieldCheck size={20} weight="fill" className="text-gate-500" />
              <span className="font-mono text-sm font-semibold text-mist-300">chaperone</span>
            </div>
            <nav className="flex md:flex-col" aria-label="Primary">
              {NAV.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setView(item.id)}
                  aria-current={view === item.id ? "page" : undefined}
                  className={`flex h-12 flex-1 items-center justify-center gap-2 border-l-2 text-sm transition-colors md:flex-none md:justify-start md:px-4 ${
                    view === item.id
                      ? "border-gate-500 bg-ink-850 text-mist-300"
                      : "border-transparent text-mist-500 hover:bg-ink-850 hover:text-mist-300"
                  }`}
                >
                  {item.icon}
                  <span className="hidden md:inline">{item.label}</span>
                </button>
              ))}
            </nav>
          </aside>

          <main className="min-w-0 p-4 md:p-6">
            <MetricsTiles />
            <div className="mt-6">
              {view === "inbox" && <InboxView />}
              {view === "stream" && <StreamView />}
              {view === "ledger" && <LedgerView />}
              {view === "policies" && <PoliciesView />}
            </div>
          </main>
        </div>
      )}
    </div>
  );
}
