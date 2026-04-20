import { useNavigate, useLocation } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import { LayoutDashboard, Search } from "lucide-react";
import { Button } from "@/components/ui/button";

/* ─────────────────────────────────────────────
   Animated shield SVG — scan-line sweeps down
   every 2.4 s, mirroring ALDECI's core action.
───────────────────────────────────────────── */
function ShieldScan() {
  return (
    <svg
      width="96"
      height="96"
      viewBox="0 0 96 96"
      fill="none"
      aria-hidden="true"
      className="select-none"
    >
      {/* Outer glow ring */}
      <circle
        cx="48"
        cy="48"
        r="44"
        stroke="oklch(0.65 0.15 195 / 0.12)"
        strokeWidth="1"
      />
      <circle
        cx="48"
        cy="48"
        r="44"
        stroke="oklch(0.65 0.15 195 / 0.06)"
        strokeWidth="12"
      />

      {/* Shield body */}
      <path
        d="M48 10 L78 24 L78 52 C78 67 64 78 48 86 C32 78 18 67 18 52 L18 24 Z"
        fill="oklch(0.17 0.01 250)"
        stroke="oklch(0.65 0.15 195 / 0.5)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />

      {/* Inner shield highlight */}
      <path
        d="M48 16 L74 28 L74 52 C74 64.5 62 74 48 81 C34 74 22 64.5 22 52 L22 28 Z"
        fill="oklch(0.20 0.015 250)"
        stroke="oklch(0.65 0.15 195 / 0.15)"
        strokeWidth="0.75"
        strokeLinejoin="round"
      />

      {/* Cross / lock icon inside shield */}
      <rect
        x="43"
        y="37"
        width="10"
        height="8"
        rx="3"
        stroke="oklch(0.65 0.15 195 / 0.6)"
        strokeWidth="1.5"
        fill="none"
      />
      <rect
        x="40"
        y="44"
        width="16"
        height="12"
        rx="2"
        fill="oklch(0.65 0.15 195 / 0.15)"
        stroke="oklch(0.65 0.15 195 / 0.6)"
        strokeWidth="1.5"
      />
      <circle cx="48" cy="50" r="1.5" fill="oklch(0.65 0.15 195 / 0.8)" />

      {/* Scan line — sweeps top to bottom of shield */}
      <clipPath id="shield-clip">
        <path d="M48 16 L74 28 L74 52 C74 64.5 62 74 48 81 C34 74 22 64.5 22 52 L22 28 Z" />
      </clipPath>
      <g clipPath="url(#shield-clip)">
        <rect
          x="18"
          y="0"
          width="60"
          height="2"
          fill="oklch(0.65 0.15 195 / 0.55)"
          rx="1"
        >
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 10"
            to="0 76"
            dur="2.4s"
            repeatCount="indefinite"
            calcMode="linear"
          />
          <animate
            attributeName="opacity"
            values="0;1;1;0"
            keyTimes="0;0.08;0.92;1"
            dur="2.4s"
            repeatCount="indefinite"
          />
        </rect>
        {/* Scan line soft glow */}
        <rect
          x="18"
          y="0"
          width="60"
          height="8"
          fill="url(#scan-gradient)"
          rx="1"
        >
          <animateTransform
            attributeName="transform"
            type="translate"
            from="0 6"
            to="0 72"
            dur="2.4s"
            repeatCount="indefinite"
            calcMode="linear"
          />
          <animate
            attributeName="opacity"
            values="0;0.4;0.4;0"
            keyTimes="0;0.08;0.92;1"
            dur="2.4s"
            repeatCount="indefinite"
          />
        </rect>
      </g>

      <defs>
        <linearGradient id="scan-gradient" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="oklch(0.65 0.15 195)" stopOpacity="0" />
          <stop offset="50%" stopColor="oklch(0.65 0.15 195)" stopOpacity="1" />
          <stop offset="100%" stopColor="oklch(0.65 0.15 195)" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  );
}

/* ─────────────────────────────────────────────
   Glitch text — CSS-only, no runtime cost
───────────────────────────────────────────── */
function GlitchCode({ text }: { text: string }) {
  return (
    <span
      className="relative inline-block font-mono font-black tracking-tighter select-none"
      style={{ fontSize: "clamp(4rem, 12vw, 7rem)", lineHeight: 1 }}
      aria-label={text}
      data-text={text}
    >
      {/* Base */}
      <span
        className="relative z-10"
        style={{ color: "oklch(0.28 0.01 250)" }}
      >
        {text}
      </span>

      {/* Glitch layer 1 — cyan shift */}
      <span
        className="absolute inset-0 z-20 pointer-events-none"
        aria-hidden="true"
        style={{
          color: "oklch(0.65 0.15 195 / 0.35)",
          animation: "glitch-a 3.5s infinite step-end",
          clipPath: "polygon(0 15%, 100% 15%, 100% 40%, 0 40%)",
        }}
      >
        {text}
      </span>

      {/* Glitch layer 2 — red shift */}
      <span
        className="absolute inset-0 z-20 pointer-events-none"
        aria-hidden="true"
        style={{
          color: "oklch(0.55 0.2 25 / 0.3)",
          animation: "glitch-b 3.5s infinite step-end",
          clipPath: "polygon(0 60%, 100% 60%, 100% 80%, 0 80%)",
        }}
      >
        {text}
      </span>

      <style>{`
        @keyframes glitch-a {
          0%,89%,100% { transform: translate(0,0); opacity: 0; }
          90% { transform: translate(-3px, 1px); opacity: 1; }
          92% { transform: translate(3px,-1px); opacity: 1; }
          94% { transform: translate(0,0); opacity: 0; }
        }
        @keyframes glitch-b {
          0%,87%,100% { transform: translate(0,0); opacity: 0; }
          88% { transform: translate(3px, 2px); opacity: 1; }
          91% { transform: translate(-2px,-1px); opacity: 1; }
          93% { transform: translate(0,0); opacity: 0; }
        }
      `}</style>
    </span>
  );
}

/* ─────────────────────────────────────────────
   Dot-grid background — subtle, no perf cost
───────────────────────────────────────────── */
function DotGrid() {
  return (
    <div
      className="pointer-events-none absolute inset-0 opacity-[0.035]"
      aria-hidden="true"
      style={{
        backgroundImage:
          "radial-gradient(circle, oklch(0.65 0.15 195) 1px, transparent 1px)",
        backgroundSize: "28px 28px",
      }}
    />
  );
}

/* ─────────────────────────────────────────────
   Main 404 page
───────────────────────────────────────────── */
export default function NotFound() {
  const navigate = useNavigate();
  const location = useLocation();
  const [visible, setVisible] = useState(false);

  // Staggered entrance — avoids layout thrashing
  useEffect(() => {
    const id = requestAnimationFrame(() => setVisible(true));
    return () => cancelAnimationFrame(id);
  }, []);

  const badPath = location.pathname;

  return (
    <div
      className="relative flex min-h-[calc(100vh-4rem)] flex-col items-center justify-center overflow-hidden px-6 py-16 text-center"
      role="main"
      aria-label="Page not found"
    >
      <DotGrid />

      {/* Radial vignette */}
      <div
        className="pointer-events-none absolute inset-0"
        aria-hidden="true"
        style={{
          background:
            "radial-gradient(ellipse 80% 60% at 50% 50%, transparent 40%, oklch(0.13 0.01 250 / 0.9) 100%)",
        }}
      />

      <div
        className="relative z-10 flex flex-col items-center gap-6"
        style={{
          opacity: visible ? 1 : 0,
          transform: visible ? "translateY(0)" : "translateY(12px)",
          transition: "opacity 0.5s ease, transform 0.5s ease",
        }}
      >
        {/* Shield icon */}
        <div
          style={{
            filter: "drop-shadow(0 0 18px oklch(0.65 0.15 195 / 0.3))",
          }}
        >
          <ShieldScan />
        </div>

        {/* 404 glitch number */}
        <GlitchCode text="404" />

        {/* Headline */}
        <div className="flex flex-col items-center gap-2">
          <h1 className="text-xl font-semibold tracking-tight text-foreground sm:text-2xl">
            Page not found
          </h1>
          <p
            className="max-w-sm text-sm leading-relaxed"
            style={{ color: "oklch(0.60 0.01 250)" }}
          >
            The resource at{" "}
            <code
              className="rounded px-1.5 py-0.5 font-mono text-xs"
              style={{
                background: "oklch(0.20 0.01 250)",
                color: "oklch(0.65 0.15 195)",
                border: "1px solid oklch(0.25 0.01 250)",
              }}
            >
              {badPath}
            </code>{" "}
            does not exist or you lack permission to access it.
          </p>
        </div>

        {/* CTA buttons */}
        <div className="flex flex-col items-center gap-3 sm:flex-row">
          <Button
            size="lg"
            className="gap-2 font-medium"
            onClick={() => navigate("/", { replace: true })}
          >
            <LayoutDashboard className="h-4 w-4" />
            Return to Dashboard
          </Button>

          <button
            className="inline-flex items-center gap-2 rounded-lg border px-4 py-2.5 text-sm font-medium transition-colors"
            style={{
              borderColor: "oklch(0.25 0.01 250)",
              color: "oklch(0.60 0.01 250)",
              background: "transparent",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLButtonElement).style.borderColor =
                "oklch(0.65 0.15 195 / 0.4)";
              (e.currentTarget as HTMLButtonElement).style.color =
                "oklch(0.80 0.01 250)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLButtonElement).style.borderColor =
                "oklch(0.25 0.01 250)";
              (e.currentTarget as HTMLButtonElement).style.color =
                "oklch(0.60 0.01 250)";
            }}
            onClick={() => {
              // Emit Cmd+K shortcut to open search if registered
              document.dispatchEvent(
                new KeyboardEvent("keydown", {
                  key: "k",
                  metaKey: true,
                  bubbles: true,
                })
              );
            }}
            aria-label="Open search with Cmd K"
          >
            <Search className="h-4 w-4" />
            <span>Search</span>
            <kbd
              className="ml-1 inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-xs"
              style={{
                background: "oklch(0.20 0.01 250)",
                border: "1px solid oklch(0.25 0.01 250)",
                color: "oklch(0.50 0.01 250)",
              }}
            >
              <span className="text-[10px]">⌘</span>K
            </kbd>
          </button>
        </div>

        {/* Status line */}
        <p
          className="font-mono text-xs"
          style={{ color: "oklch(0.35 0.01 250)" }}
        >
          ALDECI · Threat Exposure Platform · HTTP 404
        </p>
      </div>
    </div>
  );
}
