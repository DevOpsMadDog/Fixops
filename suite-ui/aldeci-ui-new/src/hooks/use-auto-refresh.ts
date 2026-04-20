import { useEffect, useRef, useState, useCallback } from "react";

/**
 * useAutoRefresh — periodically calls fetchFn on an interval.
 *
 * Returns:
 *   - isPaused: whether auto-refresh is paused
 *   - togglePause: flip pause state
 *   - lastUpdated: Date of last completed refresh
 *   - secondsAgo: seconds since lastUpdated (updates every second)
 */
export function useAutoRefresh(
  fetchFn: () => void,
  intervalMs = 30_000,
) {
  const [isPaused, setIsPaused] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [secondsAgo, setSecondsAgo] = useState(0);
  const fetchRef = useRef(fetchFn);

  // Keep ref current so the interval closure never goes stale
  useEffect(() => {
    fetchRef.current = fetchFn;
  }, [fetchFn]);

  // Auto-refresh interval
  useEffect(() => {
    if (isPaused) return;
    const id = setInterval(() => {
      fetchRef.current();
      setLastUpdated(new Date());
    }, intervalMs);
    return () => clearInterval(id);
  }, [isPaused, intervalMs]);

  // "Seconds ago" ticker — updates every second
  useEffect(() => {
    const tick = setInterval(() => {
      setSecondsAgo(Math.floor((Date.now() - lastUpdated.getTime()) / 1000));
    }, 1000);
    return () => clearInterval(tick);
  }, [lastUpdated]);

  const togglePause = useCallback(() => setIsPaused((p) => !p), []);

  return { isPaused, togglePause, lastUpdated, secondsAgo };
}
