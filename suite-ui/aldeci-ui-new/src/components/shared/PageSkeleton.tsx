import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

/* ─────────────────────────────────────────────
   Bone — used by the background skeleton layer
   so the layout shift on load is minimal.
───────────────────────────────────────────── */
function Bone({ className }: { className?: string }) {
  return (
    <div
      className={cn("animate-pulse rounded-lg bg-muted/60", className)}
    />
  );
}

/* ─────────────────────────────────────────────
   Animated progress bar — deterministic fake
   progress that slows near 90% and jumps to
   100% when the component unmounts (page ready).
───────────────────────────────────────────── */
function ProgressBar() {
  const [pct, setPct] = useState(0);
  const raf = useRef<number>(0);
  const startRef = useRef<number>(0);

  useEffect(() => {
    const duration = 3200; // expected load window

    function tick(ts: number) {
      if (!startRef.current) startRef.current = ts;
      const elapsed = ts - startRef.current;
      // Ease-out curve: fast start, slows before 90%
      const raw = elapsed / duration;
      const eased = 1 - Math.pow(1 - Math.min(raw, 1), 2.5);
      const capped = Math.min(eased * 90, 90); // never reaches 100 while loading
      setPct(capped);
      if (capped < 90) {
        raf.current = requestAnimationFrame(tick);
      }
    }

    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, []);

  return (
    <div
      className="relative h-0.5 w-48 overflow-hidden rounded-full"
      style={{ background: "oklch(0.22 0.01 250)" }}
      role="progressbar"
      aria-label="Loading"
      aria-valuenow={Math.round(pct)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <div
        className="absolute inset-y-0 left-0 rounded-full"
        style={{
          width: `${pct}%`,
          background:
            "linear-gradient(90deg, oklch(0.55 0.12 195), oklch(0.72 0.18 165))",
          transition: "width 0.12s linear",
          boxShadow: "0 0 8px oklch(0.65 0.15 195 / 0.6)",
        }}
      />
    </div>
  );
}

/* ─────────────────────────────────────────────
   Pulsing rings — three concentric circles
   that ripple outward from the shield center.
───────────────────────────────────────────── */
function PulseRings() {
  return (
    <div
      className="pointer-events-none absolute inset-0 flex items-center justify-center"
      aria-hidden="true"
    >
      {[1, 2, 3].map((i) => (
        <span
          key={i}
          className="absolute rounded-full border"
          style={{
            borderColor: "oklch(0.65 0.15 195 / 0.18)",
            width: `${i * 56}px`,
            height: `${i * 56}px`,
            animation: `aldeci-ring-pulse 2.4s ease-out ${i * 0.4}s infinite`,
          }}
        />
      ))}
      <style>{`
        @keyframes aldeci-ring-pulse {
          0%   { transform: scale(0.85); opacity: 0.7; }
          70%  { transform: scale(1.15); opacity: 0; }
          100% { transform: scale(1.15); opacity: 0; }
        }
      `}</style>
    </div>
  );
}

/* ─────────────────────────────────────────────
   Shield logo — compact version for loader
───────────────────────────────────────────── */
function ShieldLogo() {
  return (
    <svg
      width="44"
      height="44"
      viewBox="0 0 44 44"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M22 4 L38 11 L38 24 C38 32 31 38 22 42 C13 38 6 32 6 24 L6 11 Z"
        fill="oklch(0.20 0.015 250)"
        stroke="oklch(0.65 0.15 195 / 0.7)"
        strokeWidth="1.25"
        strokeLinejoin="round"
      />
      {/* Lock shackle */}
      <rect
        x="19"
        y="17"
        width="6"
        height="4"
        rx="2"
        stroke="oklch(0.65 0.15 195 / 0.7)"
        strokeWidth="1.25"
        fill="none"
      />
      {/* Lock body */}
      <rect
        x="17"
        y="20.5"
        width="10"
        height="7"
        rx="1.5"
        fill="oklch(0.65 0.15 195 / 0.18)"
        stroke="oklch(0.65 0.15 195 / 0.7)"
        strokeWidth="1.25"
      />
      <circle cx="22" cy="24" r="1" fill="oklch(0.72 0.18 165)" />
    </svg>
  );
}

/* ─────────────────────────────────────────────
   Skeleton layout — faded background content
   so the transition from loader → page is soft.
───────────────────────────────────────────── */
function BackgroundSkeleton() {
  return (
    <div
      className="pointer-events-none absolute inset-0 flex flex-col gap-6 p-6 opacity-[0.04]"
      aria-hidden="true"
    >
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <Bone className="h-6 w-48" />
          <Bone className="h-4 w-72 opacity-60" />
        </div>
        <div className="flex items-center gap-2">
          <Bone className="h-9 w-24" />
          <Bone className="h-9 w-9" />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-5"
          >
            <div className="flex items-center justify-between">
              <Bone className="h-4 w-24" />
              <Bone className="h-5 w-5 rounded-md" />
            </div>
            <Bone className="h-8 w-16" />
            <Bone className="h-3 w-28 opacity-60" />
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-5 lg:col-span-2">
          <Bone className="h-5 w-36" />
          <Bone className="h-4 w-full" />
          <Bone className="h-4 w-5/6 opacity-80" />
          <Bone className="h-4 w-4/6 opacity-60" />
        </div>
        <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-5">
          <Bone className="h-5 w-28" />
          <Bone className="mt-2 h-24 w-full rounded-lg opacity-50" />
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────
   PageSkeleton — premium branded loading screen
   Shown via <Suspense fallback={<PageSkeleton />}>
   while lazy route chunks are resolving.
───────────────────────────────────────────── */
export function PageSkeleton() {
  const [dots, setDots] = useState(".");

  // Animated ellipsis — low-frequency, no perf cost
  useEffect(() => {
    const id = setInterval(() => {
      setDots((d) => (d.length >= 3 ? "." : d + "."));
    }, 500);
    return () => clearInterval(id);
  }, []);

  return (
    <div
      className="relative flex min-h-screen w-full flex-col items-center justify-center overflow-hidden"
      style={{ background: "oklch(0.13 0.01 250)" }}
      aria-busy="true"
      aria-label="Loading page"
    >
      <BackgroundSkeleton />

      {/* Central loader */}
      <div className="relative z-10 flex flex-col items-center gap-5">
        {/* Shield + pulse rings */}
        <div className="relative flex h-20 w-20 items-center justify-center">
          <PulseRings />
          <div
            className="relative z-10"
            style={{
              filter: "drop-shadow(0 0 12px oklch(0.65 0.15 195 / 0.45))",
              animation: "aldeci-shield-breathe 2.4s ease-in-out infinite",
            }}
          >
            <ShieldLogo />
          </div>
        </div>

        {/* Wordmark */}
        <div className="flex flex-col items-center gap-1">
          <span
            className="font-mono text-[11px] font-semibold uppercase tracking-[0.25em]"
            style={{ color: "oklch(0.65 0.15 195 / 0.9)" }}
          >
            ALDECI
          </span>
          <span
            className="text-xs tracking-wide"
            style={{ color: "oklch(0.42 0.01 250)" }}
          >
            Loading{dots}
          </span>
        </div>

        {/* Progress bar */}
        <ProgressBar />
      </div>

      <style>{`
        @keyframes aldeci-shield-breathe {
          0%, 100% { transform: scale(1);    opacity: 1; }
          50%       { transform: scale(1.06); opacity: 0.85; }
        }
      `}</style>
    </div>
  );
}

export default PageSkeleton;
