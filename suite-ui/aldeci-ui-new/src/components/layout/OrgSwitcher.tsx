import { useState, useRef, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Building2, ChevronDown, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { orgsApi, type OrgItem, getStoredOrgId, setStoredOrgId } from "@/lib/api";

export function OrgSwitcher() {
  const [open, setOpen] = useState(false);
  const [activeOrgId, setActiveOrgId] = useState<string>(getStoredOrgId);
  const ref = useRef<HTMLDivElement>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["orgs-list"],
    queryFn: () => orgsApi.list(),
    staleTime: 2 * 60 * 1000,
    retry: 1,
  });

  const orgs: OrgItem[] = data?.data?.items ?? data?.data?.orgs ?? [];

  // Close on outside click
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  // Close on Escape
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    if (open) document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [open]);

  function handleSelect(org: OrgItem) {
    setStoredOrgId(org.org_id);
    setActiveOrgId(org.org_id);
    setOpen(false);
    // Reload so all queries re-fire with the new X-Org-ID header
    window.location.reload();
  }

  const activeOrg = orgs.find((o) => o.org_id === activeOrgId);
  const displayName = activeOrg?.name ?? activeOrgId ?? "Org";
  // Trim to 18 chars max for top-bar brevity
  const trimmed = displayName.length > 18 ? displayName.slice(0, 16) + "…" : displayName;

  if (isLoading || orgs.length === 0) {
    // Still show org name skeleton / single-org label (no dropdown affordance)
    return (
      <div className="flex items-center gap-1.5 rounded-md border border-border/40 bg-muted/30 px-2.5 py-1 text-[11px] text-muted-foreground">
        <Building2 className="h-3.5 w-3.5 shrink-0" />
        <span className={isLoading ? "animate-pulse" : ""}>{isLoading ? "Loading…" : trimmed}</span>
      </div>
    );
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={cn(
          "flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] font-medium transition-colors",
          open
            ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-400"
            : "border-border/40 bg-muted/30 text-foreground hover:border-border hover:bg-muted/60"
        )}
      >
        <Building2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        <span className="max-w-[120px] truncate">{trimmed}</span>
        <ChevronDown
          className={cn(
            "h-3 w-3 shrink-0 text-muted-foreground/60 transition-transform duration-150",
            open && "rotate-180"
          )}
        />
      </button>

      {open && (
        <div
          role="listbox"
          aria-label="Switch organization"
          className="absolute right-0 top-full z-50 mt-1.5 min-w-[180px] max-w-[260px] rounded-lg border border-border bg-popover shadow-xl ring-1 ring-black/10 overflow-hidden"
        >
          <div className="px-3 py-2 border-b border-border/60">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Organizations
            </span>
          </div>
          <ul className="max-h-64 overflow-y-auto py-1">
            {orgs.map((org) => {
              const isActive = org.org_id === activeOrgId;
              return (
                <li key={org.org_id}>
                  <button
                    role="option"
                    aria-selected={isActive}
                    onClick={() => handleSelect(org)}
                    className={cn(
                      "flex w-full items-center gap-2.5 px-3 py-2 text-[12px] transition-colors text-left",
                      isActive
                        ? "bg-cyan-500/10 text-cyan-400"
                        : "text-foreground hover:bg-muted/60"
                    )}
                  >
                    <Building2 className="h-3.5 w-3.5 shrink-0 text-muted-foreground/60" />
                    <span className="flex-1 truncate">{org.name}</span>
                    {isActive && <Check className="h-3.5 w-3.5 shrink-0 text-cyan-400" />}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
