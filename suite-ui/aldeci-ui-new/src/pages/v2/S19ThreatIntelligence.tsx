// Phase 1 stub — generated 2026-05-03
// Screen: S19 — Threat Intelligence
// Path:   /threats/intel
// Purpose: TI feeds + IOC
// Tabs:    ["feeds", "iocs", "actors", "campaigns"]
// Filters: ["source", "tlp"]
// API prefixes: ["/intel", "/threat-intel", "/ioc", "/feed", "/ti"]

import React from 'react';

interface EmptyStateProps {
  title: string;
  hint: string;
  apiHint: string;
}

const EmptyState: React.FC<EmptyStateProps> = ({ title, hint, apiHint }) => (
  <div className="flex flex-col items-center justify-center min-h-[400px] gap-4 text-slate-400">
    <div className="w-16 h-16 rounded-2xl bg-slate-800 flex items-center justify-center">
      <span className="text-2xl font-bold text-slate-600">S19</span>
    </div>
    <h2 className="text-xl font-semibold text-slate-200">{title}</h2>
    <p className="text-sm text-slate-500">{hint}</p>
    <p className="text-xs text-slate-600 font-mono">API: {apiHint}</p>
  </div>
);

const S19ThreatIntelligence: React.FC = () => (
  <div className="p-6">
    <EmptyState
      title="Threat Intelligence"
      hint="Phase 1 stub — wire to API in Phase 2"
      apiHint="/intel, /threat-intel, /ioc, /feed, /ti"
    />
  </div>
);

export default S19ThreatIntelligence;
