import { useState, useMemo } from "react";

export function usePagination<T>(data: T[], itemsPerPage = 25) {
  const [page, setPage] = useState(1);

  const totalPages = Math.max(1, Math.ceil(data.length / itemsPerPage));

  // Clamp page when data shrinks (e.g. after a filter change)
  const safePage = Math.min(page, totalPages);

  const paged = useMemo(
    () => data.slice((safePage - 1) * itemsPerPage, safePage * itemsPerPage),
    [data, safePage, itemsPerPage],
  );

  function setPageClamped(next: number | ((prev: number) => number)) {
    setPage((prev) => {
      const raw = typeof next === "function" ? next(prev) : next;
      return Math.max(1, Math.min(raw, totalPages));
    });
  }

  return {
    paged,
    page: safePage,
    setPage: setPageClamped,
    totalPages,
    totalItems: data.length,
    startIndex: (safePage - 1) * itemsPerPage + 1,
    endIndex: Math.min(safePage * itemsPerPage, data.length),
  };
}
