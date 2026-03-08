import { cn } from "@/lib/utils";

function Bone({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-lg bg-muted/60",
        className
      )}
    />
  );
}

/**
 * PageSkeleton — animated placeholder that mirrors the standard
 * dashboard layout: header bar, 4 KPI cards, and a content area.
 * Shown while lazy-loaded pages are resolving.
 */
export function PageSkeleton() {
  return (
    <div className="flex flex-col gap-6 p-6" aria-busy="true" aria-label="Loading page">
      {/* ── Header bar ── */}
      <div className="flex items-center justify-between">
        <div className="flex flex-col gap-2">
          <Bone className="h-6 w-48" />
          <Bone className="h-4 w-72 opacity-60" />
        </div>
        {/* Right-side action area */}
        <div className="flex items-center gap-2">
          <Bone className="h-9 w-24" />
          <Bone className="h-9 w-9" />
        </div>
      </div>

      {/* ── KPI cards row ── */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-5 shadow-md"
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

      {/* ── Main content area ── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Primary panel */}
        <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-5 shadow-md lg:col-span-2">
          <div className="flex items-center justify-between">
            <Bone className="h-5 w-36" />
            <Bone className="h-7 w-20" />
          </div>
          <Bone className="h-4 w-full" />
          <Bone className="h-4 w-5/6 opacity-80" />
          <Bone className="h-4 w-4/6 opacity-60" />
          <div className="mt-2 flex flex-col gap-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center gap-3">
                <Bone className="h-8 w-8 shrink-0 rounded-lg" />
                <div className="flex flex-1 flex-col gap-1.5">
                  <Bone className="h-3 w-3/4" />
                  <Bone className="h-3 w-1/2 opacity-60" />
                </div>
                <Bone className="h-5 w-16 rounded-full" />
              </div>
            ))}
          </div>
        </div>

        {/* Secondary panel */}
        <div className="flex flex-col gap-3 rounded-xl border border-border/50 bg-card p-5 shadow-md">
          <Bone className="h-5 w-28" />
          <div className="flex flex-col gap-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex items-center justify-between gap-2">
                <Bone className="h-3 w-24" />
                <Bone className="h-3 w-12 opacity-70" />
              </div>
            ))}
          </div>
          <Bone className="mt-2 h-24 w-full rounded-lg opacity-50" />
        </div>
      </div>
    </div>
  );
}

export default PageSkeleton;
