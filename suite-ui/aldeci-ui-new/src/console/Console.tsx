/**
 * The console shell: eight flows, a command palette, and a persona lens.
 *
 * No login. The key comes from configuration — see console/api.ts for why.
 *
 * Navigation is by JOB, not by subsystem. The previous surface had ~300 pages
 * because every engine earned a page, so the product's shape mirrored its
 * implementation rather than its use. Nine flows is not a simplification of
 * that surface; it is a different axis through it.
 *
 * The persona lens filters which flows are offered. It never hides data the
 * person is entitled to — a lens is a default, not a permission. Permissions
 * live in the API, where they can be enforced.
 */

import { Command } from "cmdk";
import { Boxes, ChevronRight, Search, Terminal } from "lucide-react";
import { useEffect, useMemo, useState, type ReactElement } from "react";

import { API_BASE } from "./api";
import { FLOWS, PERSONAS, flowsFor, type Flow, type Persona } from "./flows";

/** Read the flow out of /console/<id>, falling back to the queue. */
function flowIdFromUrl(): string {
  const last = window.location.pathname.split("/").filter(Boolean).pop();
  return last && FLOWS.some((f) => f.id === last) ? last : "triage";
}
import { ConnectScreen } from "./screens/Connect";
import { CoverageScreen } from "./screens/Coverage";
import { ComplyScreen } from "./screens/Comply";
import { DeclareScreen } from "./screens/Declare";
import { DecideScreen } from "./screens/Decide";
import { IngestScreen } from "./screens/Ingest";
import { OperateScreen } from "./screens/Operate";
import { ProveScreen } from "./screens/Prove";
import { TriageScreen } from "./screens/Triage";

const SCREENS: Record<string, () => ReactElement> = {
  ingest: IngestScreen,
  triage: TriageScreen,
  decide: DecideScreen,
  prove: ProveScreen,
  declare: DeclareScreen,
  comply: ComplyScreen,
  connect: ConnectScreen,
  coverage: CoverageScreen,
  operate: OperateScreen,
};

export default function Console() {
  const [flowId, setFlowId] = useState<string>(flowIdFromUrl);
  const [persona, setPersona] = useState<Persona | "all">("all");
  const [paletteOpen, setPaletteOpen] = useState(false);

  const visible = useMemo(() => flowsFor(persona), [persona]);

  // ⌘K / Ctrl-K. The palette is the primary navigation for anyone who works
  // here daily; the sidebar is for everyone else.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setPaletteOpen((open) => !open);
        return;
      }
      // Digit hotkeys jump straight to a flow, but not while typing.
      const target = e.target as HTMLElement | null;
      const typing = target && ["INPUT", "TEXTAREA"].includes(target.tagName);
      if (!typing && !e.metaKey && !e.ctrlKey) {
        const flow = FLOWS.find((f) => f.hotkey === e.key);
        if (flow) setFlowId(flow.id);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // A persona lens must never strand you on a flow it just hid.
  useEffect(() => {
    if (!visible.some((f) => f.id === flowId) && visible.length > 0) {
      setFlowId(visible[0].id);
    }
  }, [visible, flowId]);

  // Keep the address bar honest so a screen can be linked, bookmarked and
  // reported in a bug. Deliberately NOT an effect that re-derives flowId from
  // the URL on every render: that shape is what made 49 hubs ignore their own
  // tab clicks — the click set state, the effect read a not-yet-updated URL and
  // set it straight back. State leads; the URL follows it, and popstate is the
  // only thing allowed to push the other way.
  useEffect(() => {
    const want = `/console/${flowId}`;
    if (window.location.pathname !== want) {
      window.history.pushState({ flowId }, "", want);
    }
  }, [flowId]);

  useEffect(() => {
    const onPop = () => setFlowId(flowIdFromUrl());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const active = FLOWS.find((f) => f.id === flowId);
  const Screen = SCREENS[flowId];

  return (
    <div className="min-h-screen bg-[#08090c] text-slate-200 antialiased">
      <TopBar onSearch={() => setPaletteOpen(true)} persona={persona} setPersona={setPersona} />

      <div className="mx-auto flex max-w-[1600px] gap-6 px-6 py-6">
        <Sidebar flows={visible} activeId={flowId} onSelect={setFlowId} />

        <main className="min-w-0 flex-1">
          {active && (
            <header className="mb-5">
              <h1 className="text-[19px] font-medium tracking-tight text-slate-100">{active.label}</h1>
              <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-slate-500">{active.purpose}</p>
            </header>
          )}
          {Screen ? <Screen /> : null}
        </main>
      </div>

      <Palette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onSelect={(id) => {
          setFlowId(id);
          setPaletteOpen(false);
        }}
      />
    </div>
  );
}

function TopBar({
  onSearch,
  persona,
  setPersona,
}: {
  onSearch: () => void;
  persona: Persona | "all";
  setPersona: (p: Persona | "all") => void;
}) {
  return (
    <header className="sticky top-0 z-40 border-b border-white/8 bg-[#08090c]/90 backdrop-blur">
      <div className="mx-auto flex max-w-[1600px] items-center gap-4 px-6 py-3">
        <div className="flex items-center gap-2 text-[13px] font-medium tracking-tight text-slate-100">
          <Terminal className="h-4 w-4 text-cyan-300" />
          ALDECI
        </div>

        <button
          onClick={onSearch}
          className="group flex flex-1 items-center gap-2 rounded-md border border-white/8 bg-white/[0.02] px-3 py-1.5 text-left text-[12px] text-slate-500 transition hover:border-white/15 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/40"
        >
          <Search className="h-3.5 w-3.5" />
          <span className="flex-1">Go to a flow, a finding, a rule…</span>
          <kbd className="rounded border border-white/10 bg-white/[0.03] px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
            ⌘K
          </kbd>
        </button>

        <label className="flex items-center gap-2 text-[11px] text-slate-500">
          <span className="uppercase tracking-wider">Viewing as</span>
          <select
            value={persona}
            onChange={(e) => setPersona(e.target.value as Persona | "all")}
            className="rounded border border-white/10 bg-[#0d1117] px-2 py-1 text-[12px] text-slate-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/40"
          >
            <option value="all">Everyone</option>
            {PERSONAS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>

        {/* Where the numbers come from. An operator should never have to guess
            which deployment they are looking at. */}
        <span className="hidden font-mono text-[10px] text-slate-600 lg:inline">{API_BASE}</span>
      </div>
    </header>
  );
}

function Sidebar({
  flows,
  activeId,
  onSelect,
}: {
  flows: Flow[];
  activeId: string;
  onSelect: (id: string) => void;
}) {
  return (
    <nav className="hidden w-56 shrink-0 md:block">
      <ul className="space-y-0.5">
        {flows.map((flow) => {
          const isActive = flow.id === activeId;
          return (
            <li key={flow.id}>
              <button
                onClick={() => onSelect(flow.id)}
                className={`group flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-[13px] transition focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/40 ${
                  isActive
                    ? "bg-cyan-400/10 text-cyan-100"
                    : "text-slate-400 hover:bg-white/[0.03] hover:text-slate-200"
                }`}
              >
                <ChevronRight
                  className={`h-3.5 w-3.5 shrink-0 transition ${
                    isActive ? "text-cyan-300" : "text-slate-700 group-hover:text-slate-500"
                  }`}
                />
                <span className="min-w-0 flex-1 truncate">{flow.label}</span>
                <kbd className="rounded border border-white/8 px-1 font-mono text-[10px] text-slate-600">
                  {flow.hotkey}
                </kbd>
              </button>
            </li>
          );
        })}
      </ul>

      <p className="mt-4 px-2.5 text-[11px] leading-relaxed text-slate-600">
        {FLOWS.length} flows, chosen by what you came here to do. Press a number to jump.
      </p>
    </nav>
  );
}

function Palette({
  open,
  onOpenChange,
  onSelect,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSelect: (id: string) => void;
}) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[12vh] backdrop-blur-sm"
      onClick={() => onOpenChange(false)}
    >
      <Command
        className="w-full max-w-xl overflow-hidden rounded-lg border border-white/10 bg-[#0d1117] shadow-2xl"
        onClick={(e) => e.stopPropagation()}
        loop
      >
        <Command.Input
          autoFocus
          placeholder="Where do you want to go?"
          className="w-full border-b border-white/8 bg-transparent px-4 py-3 text-[14px] text-slate-100 outline-none placeholder:text-slate-600"
        />
        <Command.List className="max-h-80 overflow-y-auto p-2">
          <Command.Empty className="px-3 py-6 text-center text-[12px] text-slate-500">
            Nothing matches that.
          </Command.Empty>
          <Command.Group
            heading="Flows"
            className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-slate-600"
          >
            {FLOWS.map((flow) => (
              <Command.Item
                key={flow.id}
                value={`${flow.label} ${flow.purpose} ${flow.id}`}
                onSelect={() => onSelect(flow.id)}
                className="flex cursor-pointer items-center gap-3 rounded px-2.5 py-2 text-[13px] text-slate-300 data-[selected=true]:bg-cyan-400/10 data-[selected=true]:text-cyan-100"
              >
                <Boxes className="h-3.5 w-3.5 shrink-0 text-slate-600" />
                <span className="min-w-0 flex-1 truncate">{flow.label}</span>
                <kbd className="rounded border border-white/8 px-1 font-mono text-[10px] text-slate-600">
                  {flow.hotkey}
                </kbd>
              </Command.Item>
            ))}
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}
