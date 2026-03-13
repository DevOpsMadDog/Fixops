/**
 * Vitest global setup — loads jest-dom matchers and cleans up after each test.
 */
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(() => {
  cleanup();
});

// ── Stub browser APIs ──

// ResizeObserver (used by Radix, Recharts)
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;

// matchMedia (used by motion, theme checks)
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// IntersectionObserver
class IntersectionObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.IntersectionObserver = IntersectionObserverStub as unknown as typeof IntersectionObserver;

// Scroll methods
Element.prototype.scrollTo = vi.fn() as any;
Element.prototype.scrollIntoView = vi.fn() as any;
window.scrollTo = vi.fn() as any;

// URL.createObjectURL / revokeObjectURL
URL.createObjectURL = vi.fn(() => "blob:mock");
URL.revokeObjectURL = vi.fn();

// EventSource (used by LiveFeed SSE)
class EventSourceStub {
  url: string;
  readyState = 0;
  onopen: (() => void) | null = null;
  onmessage: ((e: any) => void) | null = null;
  onerror: ((e: any) => void) | null = null;
  constructor(url: string) { this.url = url; }
  close() { this.readyState = 2; }
  addEventListener() {}
  removeEventListener() {}
  dispatchEvent() { return false; }
}
(globalThis as any).EventSource = EventSourceStub;
