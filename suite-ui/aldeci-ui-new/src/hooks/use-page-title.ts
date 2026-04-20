import { useEffect } from "react";

/**
 * Sets the browser tab title to "ALDECI | {title}" on mount,
 * and restores the default on unmount.
 */
export function usePageTitle(title: string): void {
  useEffect(() => {
    const prev = document.title;
    document.title = `ALDECI | ${title}`;
    return () => {
      document.title = prev;
    };
  }, [title]);
}
