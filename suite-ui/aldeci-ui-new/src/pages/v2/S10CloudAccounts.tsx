// Phase 1 stub — generated 2026-05-03
// Screen: S10 — Cloud Accounts
// Path:   /cloud/accounts
// Purpose: Cloud account inventory
// Tabs:    ["accounts", "health", "cost", "onboarding"]
// Filters: ["cloud"]
// API prefixes: ["/account", "/tenant", "/cloud-account"]

import React from 'react';

interface EmptyStateProps {
  title: string;
  hint: string;
  apiHint: string;
}

const EmptyState: React.FC<EmptyStateProps> = ({ title, hint, apiHint }) => (
  <div className="flex flex-col items-center justify-center min-h-[400px] gap-4 text-slate-400">
    <div className="w-16 h-16 rounded-2xl bg-slate-800 flex items-center justify-center">
      <span className="text-2xl font-bold text-slate-600">S10</span>
    </div>
    <h2 className="text-xl font-semibold text-slate-200">{title}</h2>
    <p className="text-sm text-slate-500">{hint}</p>
    <p className="text-xs text-slate-600 font-mono">API: {apiHint}</p>
  </div>
);

const S10CloudAccounts: React.FC = () => (
  <div className="p-6">
    <EmptyState
      title="Cloud Accounts"
      hint="Phase 1 stub — wire to API in Phase 2"
      apiHint="/account, /tenant, /cloud-account"
    />
  </div>
);

export default S10CloudAccounts;
