// Build-plan Phase 12 tests: inbox_shows_pending, stream_renders_decisions.
// The api module is mocked; the components render real DOM against it.

import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, render, screen } from "@testing-library/react";
import { InboxView } from "../components/InboxView";
import { StreamView } from "../components/StreamView";
import type { EscalationRow } from "../lib/types";

vi.mock("../lib/api", () => ({
  api: {
    pendingEscalations: vi.fn(),
    resolveEscalation: vi.fn(),
    ledgerEntries: vi.fn(),
    verifyLedger: vi.fn(),
    checkpoints: vi.fn(),
  },
}));

import { api } from "../lib/api";
const mockedApi = vi.mocked(api);

function esc(overrides: Partial<EscalationRow> = {}): EscalationRow {
  return {
    escalation_id: "esc_9f4c2b71",
    request_id: "req_1",
    agent_id: "agent_support_09",
    policy_id: "pol_refunds",
    policy_version: 3,
    rule_ids: '["r-escalate-mid"]',
    tool: "stripe.refunds.create",
    proposed_params: '{"amount":450}',
    params_binding_hash: "a".repeat(64),
    status: "pending",
    resolver: null,
    resolution_note: null,
    created_at: "2026-08-25T14:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    resolved_at: null,
    decision_entry_seq: 1,
    resolution_entry_seq: null,
    ...overrides,
  };
}

describe("InboxView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("inbox_shows_pending", async () => {
    mockedApi.pendingEscalations.mockResolvedValue([
      esc(),
      esc({ escalation_id: "esc_2", tool: "fs.write", expires_at: "2099-01-01T00:05:00Z" }),
    ]);

    render(<InboxView />);

    // Both pending escalations render with their identity + tool.
    expect(await screen.findByText("esc_9f4c2b71")).toBeInTheDocument();
    expect(screen.getByText("stripe.refunds.create")).toBeInTheDocument();
    expect(screen.getByText("esc_2")).toBeInTheDocument();
    expect(screen.getByText("fs.write")).toBeInTheDocument();
    // Expiry countdowns are present for both.
    expect(screen.getAllByText(/m \d+s/).length).toBe(2);
    // The approve/deny actions exist.
    expect(screen.getAllByRole("button", { name: /Approve/ })).toHaveLength(2);
    expect(screen.getAllByRole("button", { name: /Deny/ })).toHaveLength(2);
  });
});

describe("StreamView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (globalThis as unknown as { WebSocket: { instances: unknown[] } }).WebSocket.instances = [];
    mockedApi.pendingEscalations.mockResolvedValue([]);
    mockedApi.ledgerEntries.mockResolvedValue({ entries: [], next_after_seq: null });
  });

  it("stream_renders_decisions", async () => {
    render(<StreamView />);

    // The stream is empty until a frame arrives.
    expect(screen.getByText(/Waiting for decisions/)).toBeInTheDocument();

    // Simulate a server frame over the mock socket.
    const sockets = (globalThis as unknown as { WebSocket: { instances: { emit: (s: string) => void }[] } })
      .WebSocket.instances;
    expect(sockets.length).toBeGreaterThan(0);
    await act(async () => {
      sockets[0].emit(
        JSON.stringify({
          type: "decision",
          data: {
            decision: "BLOCK",
            reason_code: "RULE_MATCH",
            determining_rule_ids: ["r-block-large"],
            policy_id: "pol_refunds",
            policy_version: 3,
            policy_hash: "h".repeat(64),
            entry_seq: 7,
            entry_hash: "e".repeat(64),
            escalation_id: null,
            escalation_expires_at: null,
            trace: [],
            derived_context: {},
            evaluation_latency_ms: 1.2,
          },
        }),
      );
    });

    expect(await screen.findByText("#7")).toBeInTheDocument();
    expect(screen.getByText("BLOCK")).toBeInTheDocument();
    expect(screen.getByText("pol_refunds")).toBeInTheDocument();
  });
});
