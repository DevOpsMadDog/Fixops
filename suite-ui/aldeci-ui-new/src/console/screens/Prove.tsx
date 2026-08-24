/**
 * Prove it to an auditor — the commercial wedge.
 *
 * Generates a real, persisted, signed bundle and shows the two facts an
 * assessor cares about: the artifact still hashes to what we recorded (it has
 * not been altered) and that hash carries our signature (it came from us).
 *
 * The public key is offered here on purpose. An assessor should not have to
 * trust this console to check what this console produced.
 */

import { useEffect, useState } from "react";

import { API_BASE, apiGet, apiPost, type Result } from "../api";
import { Metric, Mono, Panel, Resolve } from "../primitives";

interface Bundle {
  id?: string;
  framework?: string;
  created_at?: string;
  controls_assessed?: number;
  controls_effective?: number;
  finding_count?: number;
  signature_valid?: boolean;
  signed_by?: string;
  hash?: string;
  signature_unavailable_reason?: string;
}

export function ProveScreen() {
  const [bundles, setBundles] = useState<Result<{ total?: number; bundles?: Bundle[] }>>({
    state: "loading", data: null, error: null, source: "/api/v1/evidence/bundles",
  });
  const [chain, setChain] = useState<Result<{ stats?: Record<string, number> }>>({
    state: "loading", data: null, error: null, source: "/api/v1/evidence-chain/",
  });
  const [busy, setBusy] = useState(false);
  const [verified, setVerified] = useState<Record<string, string>>({});

  const reload = () => {
    apiGet<{ total?: number; bundles?: Bundle[] }>("/api/v1/evidence/bundles").then(setBundles);
    apiGet<{ stats?: Record<string, number> }>("/api/v1/evidence-chain/").then(setChain);
  };
  useEffect(reload, []);

  async function generate() {
    setBusy(true);
    await apiPost("/api/v1/evidence/bundles/generate", { frameworks: ["SOC2"] });
    setBusy(false);
    reload();
  }

  async function verify(id: string) {
    setVerified((v) => ({ ...v, [id]: "checking…" }));
    const r = await apiPost<{ valid?: boolean; hash_match?: boolean; signature_valid?: boolean; issuer?: string }>(
      `/api/v1/evidence/bundles/${id}/verify`, {},
    );
    const d = r.data;
    setVerified((v) => ({
      ...v,
      [id]: r.state === "error"
        ? (r.error ?? "verification failed")
        : d?.valid
          ? `verified · ${d?.issuer ?? ""}`
          : `NOT verified · ${d?.issuer ?? ""}`,
    }));
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Panel title="Bundles"><Metric value={bundles.data?.total ?? 0} label="generated" /></Panel>
        <Panel title="Sealed">
          <Metric value={chain.data?.stats?.sealed_count ?? 0} label="in chain of custody" tone="good" />
        </Panel>
        <Panel title="Evidence items"><Metric value={chain.data?.stats?.total_evidence ?? 0} label="under custody" /></Panel>
        <Panel title="Verify offline">
          <a
            href={`${API_BASE}/api/v1/evidence/public-key`}
            target="_blank"
            rel="noreferrer"
            className="text-[12px] text-cyan-300 underline decoration-cyan-400/30 underline-offset-4 hover:text-cyan-200"
          >
            Public key →
          </a>
          <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">
            An auditor verifies with <Mono>scripts/verify_evidence_bundle.py</Mono> — no network, no FixOps.
          </p>
        </Panel>
      </div>

      <Panel
        title="Evidence bundles"
        subtitle="Sealed at generation, signed over the content hash"
        right={
          <button
            onClick={generate}
            disabled={busy}
            className="rounded border border-cyan-400/25 bg-cyan-400/10 px-2.5 py-1 text-[12px] font-medium text-cyan-200 transition hover:bg-cyan-400/15 disabled:opacity-50"
          >
            {busy ? "Generating…" : "Generate"}
          </button>
        }
      >
        <Resolve
          result={bundles}
          what="evidence bundles"
          empty={{
            headline: "No bundles yet.",
            because: "Generate one and it is sealed into the chain of custody and signed at the moment it exists.",
            action: { label: "Generate a bundle", onClick: generate },
          }}
        >
          {(data) => (
            <div className="space-y-2">
              {(data.bundles ?? []).map((b) => (
                <div key={b.id} className="rounded border border-white/8 bg-white/[0.02] p-3">
                  <div className="flex flex-wrap items-baseline justify-between gap-3">
                    <Mono>{b.id}</Mono>
                    <div className="flex items-center gap-3 text-[11px]">
                      <span className={b.signature_valid ? "text-emerald-300" : "text-slate-500"}>
                        {b.signature_valid ? `signed · ${b.signed_by ?? ""}` : b.signature_unavailable_reason ?? "unsigned"}
                      </span>
                      <button
                        onClick={() => b.id && verify(b.id)}
                        className="rounded border border-white/10 px-2 py-0.5 text-slate-300 transition hover:bg-white/5"
                      >
                        Verify
                      </button>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-[11px] text-slate-500">
                    <span>{b.framework}</span>
                    <span>controls assessed {b.controls_assessed ?? 0}</span>
                    <span>effective {b.controls_effective ?? 0}</span>
                    <span>findings {b.finding_count ?? 0}</span>
                  </div>
                  {b.id && verified[b.id] && (
                    <p
                      className={`mt-2 text-[11px] ${
                        verified[b.id].startsWith("verified") ? "text-emerald-300" : "text-amber-200"
                      }`}
                    >
                      {verified[b.id]}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </Resolve>
      </Panel>
    </div>
  );
}
