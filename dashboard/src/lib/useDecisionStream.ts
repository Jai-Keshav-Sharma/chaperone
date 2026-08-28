// Live decision stream: subscribes to /ws/decisions and appends messages.
// Server drops slow consumers (api-contracts); the client reconnects with
// backoff and never backpressures (the stream is append-only in memory).

import { useEffect, useRef, useState } from "react";
import type { DecisionResponse } from "./types";

export function useDecisionStream(enabled: boolean) {
  const [decisions, setDecisions] = useState<DecisionResponse[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const retryRef = useRef(0);

  useEffect(() => {
    if (!enabled) return;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws/decisions`);
      socketRef.current = ws;

      ws.onopen = () => {
        retryRef.current = 0;
      };
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data as string);
          if (msg?.type === "decision" && msg.data) {
            setDecisions((prev) => [msg.data, ...prev].slice(0, 200));
          }
        } catch {
          // malformed frame: ignore, keep the stream alive
        }
      };
      ws.onclose = () => {
        if (disposed) return;
        const delay = Math.min(1000 * 2 ** retryRef.current, 15000);
        retryRef.current += 1;
        setTimeout(connect, delay);
      };
      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      disposed = true;
      socketRef.current?.close();
    };
  }, [enabled]);

  return decisions;
}
