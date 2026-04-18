import { useState, useMemo } from "react";
import { ChevronUp, ChevronDown, ChevronsUpDown, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

type SortDir = "asc" | "desc";

interface Column<T> {
  key: string;
  header: string;
  render?: (row: T) => React.ReactNode;
  className?: string;
  sortable?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  emptyMessage?: string;
  className?: string;
  /** If true, renders a search filter input above the table */
  filterable?: boolean;
  /** External filter value — controlled mode. When provided, hides built-in input */
  filterValue?: string;
  /** Default column key to sort by */
  defaultSortKey?: string;
  /** Default sort direction */
  defaultSortDir?: SortDir;
}

function SortIcon({ col, sortKey, sortDir }: { col: string; sortKey: string; sortDir: SortDir }) {
  if (col !== sortKey) return <ChevronsUpDown className="ml-1 h-3 w-3 opacity-40 inline-block" />;
  return sortDir === "asc"
    ? <ChevronUp className="ml-1 h-3 w-3 text-blue-400 inline-block" />
    : <ChevronDown className="ml-1 h-3 w-3 text-blue-400 inline-block" />;
}

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  onRowClick,
  emptyMessage = "No data available",
  className,
  filterable = false,
  filterValue,
  defaultSortKey,
  defaultSortDir = "desc",
}: DataTableProps<T>) {
  const firstSortable = columns.find((c) => c.sortable !== false)?.key ?? columns[0]?.key ?? "";
  const [sortKey, setSortKey] = useState<string>(defaultSortKey ?? firstSortable);
  const [sortDir, setSortDir] = useState<SortDir>(defaultSortDir);
  const [internalFilter, setInternalFilter] = useState("");

  const activeFilter = filterValue !== undefined ? filterValue : internalFilter;

  function handleHeaderClick(col: Column<T>) {
    if (col.sortable === false) return;
    if (col.key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(col.key);
      setSortDir("desc");
    }
  }

  const processed = useMemo(() => {
    const lower = activeFilter.toLowerCase();
    const filtered = lower
      ? data.filter((row) => JSON.stringify(row).toLowerCase().includes(lower))
      : data;

    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av === bv) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      const cmp = av > bv ? 1 : -1;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [data, sortKey, sortDir, activeFilter]);

  const showBuiltinFilter = filterable && filterValue === undefined;

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      {showBuiltinFilter && (
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Filter..."
            value={internalFilter}
            onChange={(e) => setInternalFilter(e.target.value)}
            className="pl-8 h-8 text-xs bg-muted/30 border-border/50"
          />
        </div>
      )}
      <div className="overflow-auto rounded-lg border border-border/50">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/50 bg-muted/30">
              {columns.map((col) => {
                const isSortable = col.sortable !== false;
                return (
                  <th
                    key={col.key}
                    onClick={() => handleHeaderClick(col)}
                    className={cn(
                      "px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground select-none",
                      isSortable && "cursor-pointer hover:text-foreground transition-colors",
                      col.className,
                    )}
                  >
                    {col.header}
                    {isSortable && (
                      <SortIcon col={col.key} sortKey={sortKey} sortDir={sortDir} />
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {processed.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-4 py-12 text-center text-muted-foreground">
                  {activeFilter ? `No results for "${activeFilter}"` : emptyMessage}
                </td>
              </tr>
            ) : (
              processed.map((row, i) => (
                <tr
                  key={i}
                  onClick={() => onRowClick?.(row)}
                  className={cn(
                    "border-b border-border/30 transition-colors",
                    onRowClick && "cursor-pointer hover:bg-muted/30",
                  )}
                >
                  {columns.map((col) => (
                    <td key={col.key} className={cn("px-4 py-3", col.className)}>
                      {col.render ? col.render(row) : String(row[col.key] ?? "")}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
