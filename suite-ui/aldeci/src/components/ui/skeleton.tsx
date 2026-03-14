import { cn } from '../../lib/utils';

function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'animate-pulse rounded-md bg-gray-700/30',
        className
      )}
      {...props}
    />
  );
}

/**
 * PageSkeleton — full-page loading skeleton for dashboard-style pages.
 * Shows stat cards + table rows to match the typical ALdeci page layout.
 */
function PageSkeleton({ cards = 4, rows = 6 }: { cards?: number; rows?: number }) {
  return (
    <div className="space-y-6 p-1">
      {/* Header skeleton */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-10 w-24 rounded-md" />
          <Skeleton className="h-10 w-32 rounded-md" />
        </div>
      </div>

      {/* Stat cards skeleton */}
      <div className={`grid grid-cols-1 md:grid-cols-${Math.min(cards, 4)} gap-4`}>
        {Array.from({ length: cards }).map((_, i) => (
          <div key={i} className="border border-gray-700/30 bg-gray-900/40 rounded-lg p-6">
            <Skeleton className="h-3 w-20 mb-3" />
            <Skeleton className="h-8 w-16" />
          </div>
        ))}
      </div>

      {/* Table/list skeleton */}
      <div className="border border-gray-700/30 bg-gray-900/40 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between">
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-8 w-48 rounded-md" />
        </div>
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center gap-4 py-3 border-b border-gray-700/20 last:border-0">
            <Skeleton className="h-3 w-3 rounded-full" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-3 w-80" />
            </div>
            <Skeleton className="h-6 w-16 rounded-full" />
            <Skeleton className="h-4 w-12" />
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * CardSkeleton — individual card loading state
 */
function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div className="border border-gray-700/30 bg-gray-900/40 rounded-lg p-6 space-y-3">
      <Skeleton className="h-5 w-32" />
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className="h-3" style={{ width: `${85 - i * 15}%` }} />
      ))}
    </div>
  );
}

/**
 * ChartSkeleton — placeholder for chart loading
 */
function ChartSkeleton({ height = 200 }: { height?: number }) {
  return (
    <div className="border border-gray-700/30 bg-gray-900/40 rounded-lg p-6">
      <Skeleton className="h-5 w-40 mb-4" />
      <div className="flex items-end gap-2 justify-evenly" style={{ height }}>
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton
            key={i}
            className="rounded-t"
            style={{
              width: '10%',
              height: `${30 + ((i * 37 + 13) % 70)}%`,
            }}
          />
        ))}
      </div>
    </div>
  );
}

export { Skeleton, PageSkeleton, CardSkeleton, ChartSkeleton };
