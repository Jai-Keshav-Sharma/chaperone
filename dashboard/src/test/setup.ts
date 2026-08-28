// Vitest setup: jsdom + jest-dom matchers. The api module is mocked per
// test (the dashboard never touches a real gate in unit tests).

import "@testing-library/jest-dom/vitest";

// React 19 requires the act environment flag for testing-library.
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

// Silence motion's useReducedMotion in jsdom (no matchMedia).
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});

// WebSocket is not implemented in jsdom; the stream hook guards on it.
class MockWebSocket {
  static instances: MockWebSocket[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }
  close() {}
  // Test helper: simulate a server frame.
  emit(data: string) {
    this.onmessage?.({ data });
  }
}

(globalThis as unknown as { WebSocket: unknown }).WebSocket = MockWebSocket;
