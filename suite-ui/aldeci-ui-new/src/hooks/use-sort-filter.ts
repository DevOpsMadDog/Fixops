import { useState, useMemo } from "react";

export type SortDir = "asc" | "desc";

export function useSortFilter<T extends Record<string, unknown>>(
  data: T[],
  defaultSort: keyof T,
  defaultDir: SortDir = "desc",
) {
  const [sortKey, setSortKey] = useState<keyof T>(defaultSort);
  const [sortDir, setSortDir] = useState<SortDir>(defaultDir);
  const [filter, setFilter] = useState("");

  function toggleSort(key: keyof T) {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  const sorted = useMemo(() => {
    const lower = filter.toLowerCase();
    const filtered = lower
      ? data.filter((item) =>
          JSON.stringify(item).toLowerCase().includes(lower),
        )
      : data;

    return [...filtered].sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (av === bv) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      const cmp = av > bv ? 1 : -1;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [data, sortKey, sortDir, filter]);

  return { sorted, sortKey, sortDir, setSortKey, setSortDir, toggleSort, filter, setFilter };
}
