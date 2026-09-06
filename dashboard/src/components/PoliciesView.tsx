// Policy lifecycle: upload a policy document (.md/.txt/.pdf/.docx/.html),
// compile it into validated IR via the configured LLM, review the rules, then
// activate. Every state is explicit (idle / compiling / error / review /
// activated). The LLM output is inert until the operator activates it.

import { useCallback, useEffect, useState } from "react";
import {
  Upload,
  FileText,
  Check,
  X,
  Sparkle,
  ShieldCheck,
  ArrowClockwise,
} from "@phosphor-icons/react";
import { api } from "../lib/api";
import type { CompileResponse, PolicyShell } from "../lib/types";

type Phase = "idle" | "compiling" | "review" | "activated" | "error";

function verdictChip(effect: string) {
  switch (effect) {
    case "allow":
      return <span className="chip bg-gate-500/10 text-gate-500">ALLOW</span>;
    case "block":
      return <span className="chip bg-gate-deny/10 text-gate-deny">BLOCK</span>;
    case "escalate":
      return <span className="chip bg-gate-warn/10 text-gate-warn">ESCALATE</span>;
    default:
      return <span className="chip bg-ink-800 text-mist-400">{effect}</span>;
  }
}

export function PoliciesView() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [fileName, setFileName] = useState<string | null>(null);
  const [provider, setProvider] = useState("ollama");
  const [compiled, setCompiled] = useState<CompileResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activating, setActivating] = useState(false);
  const [policies, setPolicies] = useState<PolicyShell[]>([]);

  const refreshPolicies = useCallback(async () => {
    try {
      setPolicies(await api.listPolicies());
    } catch {
      // gate unreachable: keep the list empty, surface elsewhere
    }
  }, []);

  useEffect(() => {
    refreshPolicies();
  }, [refreshPolicies]);

  const onFile = async (file: File) => {
    setFileName(file.name);
    setPhase("compiling");
    setError(null);
    setCompiled(null);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      const result = await api.compilePolicy(bytes, file.name, provider);
      setCompiled(result);
      setPhase("review");
    } catch (e) {
      setError(e instanceof Error ? e.message : "compile failed");
      setPhase("error");
    }
  };

  const activate = async () => {
    if (!compiled) return;
    setActivating(true);
    setError(null);
    try {
      await api.activatePolicy(compiled.policy.policy_id, compiled.policy.version);
      setPhase("activated");
      await refreshPolicies();
    } catch (e) {
      setError(e instanceof Error ? e.message : "activation failed");
      setPhase("error");
    } finally {
      setActivating(false);
    }
  };

  const reset = () => {
    setPhase("idle");
    setFileName(null);
    setCompiled(null);
    setError(null);
  };

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-mist-300">Policies</h2>
        <button onClick={reset} disabled={phase === "compiling"} className="btn btn-ghost">
          <ArrowClockwise size={14} /> New
        </button>
      </div>

      {/* Provider selector: local-first, one accent, familiar control. */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="label">Compiler</span>
        {["ollama", "openai-compat", "anthropic"].map((p) => (
          <button
            key={p}
            onClick={() => setProvider(p)}
            className={`chip cursor-pointer transition-colors ${
              provider === p
                ? "bg-gate-500/15 text-gate-500"
                : "bg-ink-800 text-mist-400 hover:text-mist-300"
            }`}
            aria-pressed={provider === p}
          >
            {p}
          </button>
        ))}
      </div>

      {/* Upload drop zone (idle). */}
      {phase === "idle" && (
        <label className="mt-6 flex cursor-pointer flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-ink-600 bg-ink-900 p-12 text-center transition-colors hover:border-gate-500/60 hover:bg-ink-850">
          <Upload size={24} className="text-gate-500" weight="duotone" />
          <div>
            <p className="font-medium text-mist-300">Upload a policy document</p>
            <p className="mt-1 text-sm text-mist-500">
              Markdown, plain text, PDF, DOCX, or HTML. It compiles to deterministic
              rules you review before activating.
            </p>
          </div>
          <input
            type="file"
            accept=".md,.txt,.pdf,.docx,.html,.markdown"
            className="sr-only"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void onFile(f);
              e.target.value = "";
            }}
          />
        </label>
      )}

      {/* Compiling (loading). */}
      {phase === "compiling" && (
        <div className="surface mt-6 flex items-center gap-3 p-6" aria-busy="true">
          <Sparkle size={18} className="animate-pulse text-gate-500" />
          <div className="min-w-0">
            <p className="font-medium text-mist-300">Compiling {fileName}…</p>
            <p className="text-sm text-mist-500">
              Ingesting the document and generating policy IR via {provider}. This
              can take a moment for a local model.
            </p>
          </div>
        </div>
      )}

      {/* Review + activate (compiled IR). */}
      {phase === "review" && compiled && (
        <div className="mt-6 space-y-4">
          <div className="surface p-4">
            <div className="flex flex-wrap items-center gap-2">
              <ShieldCheck size={16} className="text-gate-500" weight="duotone" />
              <span className="mono text-sm text-mist-300">{compiled.policy.policy_id}</span>
              <span className="mono text-xs text-mist-500">
                v{compiled.policy.version} · {compiled.model}
              </span>
            </div>
            <p className="mt-2 text-sm text-mist-400">{compiled.policy.description}</p>

            <ul className="mt-4 divide-y divide-ink-800">
              {compiled.policy.rules.map((r) => (
                <li key={r.rule_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2">
                  {verdictChip(r.effect)}
                  <span className="mono text-xs text-mist-500">{r.rule_id}</span>
                  <span className="min-w-0 flex-1 text-sm text-mist-300">
                    {r.description}
                  </span>
                  <span className="mono shrink-0 text-xs text-mist-500">
                    {r.target.tools.join(", ") || "*"}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={activate}
              disabled={activating}
              className="btn btn-primary"
            >
              <Check size={14} weight="bold" />
              {activating ? "Activating…" : "Activate policy"}
            </button>
            <button onClick={reset} className="btn btn-ghost">
              <X size={14} /> Discard
            </button>
          </div>
        </div>
      )}

      {/* Activated confirmation. */}
      {phase === "activated" && compiled && (
        <div className="surface mt-6 flex items-center gap-3 p-6">
          <Check size={20} weight="bold" className="text-gate-500" />
          <div>
            <p className="font-medium text-mist-300">
              {compiled.policy.policy_id} is now active.
            </p>
            <p className="text-sm text-mist-500">
              The gate now enforces these rules on every matching tool call. The
              previous version was superseded.
            </p>
          </div>
        </div>
      )}

      {/* Error. */}
      {phase === "error" && (
        <div className="surface mt-6 flex items-center gap-3 border-gate-deny/40 p-6">
          <X size={18} className="text-gate-deny" weight="bold" />
          <div className="min-w-0">
            <p className="font-medium text-gate-deny">Something went wrong</p>
            <p className="mt-1 text-sm text-mist-400">{error}</p>
          </div>
          <button onClick={reset} className="btn btn-ghost ml-auto">
            Try again
          </button>
        </div>
      )}

      {/* Existing policies (read-only context). */}
      {policies.length > 0 && (
        <div className="mt-8">
          <h3 className="text-sm font-semibold text-mist-300">Active policies</h3>
          <ul className="mt-2 divide-y divide-ink-800 rounded-lg border border-ink-700 bg-ink-900">
            {policies.map((p) => (
              <li key={p.policy_id} className="flex items-center gap-3 px-4 py-2.5">
                <FileText size={16} className="text-mist-500" />
                <span className="mono text-sm text-mist-300">{p.policy_id}</span>
                <span className="mono ml-auto text-xs text-mist-500">
                  {p.active_version ? `v${p.active_version}` : "no active version"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
