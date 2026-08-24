/**
 * Bring findings in — the front door.
 *
 * Nothing else in the product works until this does, so it is flow one and it
 * says so plainly. The upload is real: it posts to /api/v1/scanner-ingest/upload
 * and reports exactly what came back, including which tenant it landed in.
 */

import { Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { apiGet, uploadScan, type Result } from "../api";
import { Metric, Mono, Panel, Resolve } from "../primitives";

interface Supported { supported_scanners?: string[]; org_id?: string }
interface UploadResult { findings_count?: number; org_id?: string; scanner?: string; file_name?: string }

export function IngestScreen() {
  const [supported, setSupported] = useState<Result<Supported>>({
    state: "loading", data: null, error: null, source: "/api/v1/scanner-ingest/",
  });
  const [result, setResult] = useState<Result<UploadResult> | null>(null);
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => { apiGet<Supported>("/api/v1/scanner-ingest/").then(setSupported); }, []);

  async function onFile(file: File) {
    setBusy(true);
    setResult(null);
    setResult(await uploadScan<UploadResult>(file, "auto"));
    setBusy(false);
  }

  return (
    <div className="space-y-5">
      <Panel title="Upload scanner output" subtitle="SARIF, Trivy, Grype, Semgrep, Snyk, CycloneDX and more">
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            const file = e.dataTransfer.files?.[0];
            if (file) void onFile(file);
          }}
          className="rounded-lg border border-dashed border-white/12 bg-white/[0.015] px-6 py-10 text-center"
        >
          <Upload className="mx-auto h-5 w-5 text-slate-600" />
          <p className="mt-3 text-[13px] text-slate-300">Drop a scan file here</p>
          <p className="mt-1 text-[12px] text-slate-500">
            We normalise other tools' output. We do not run our own scanner.
          </p>
          <button
            onClick={() => fileRef.current?.click()}
            disabled={busy}
            className="mt-4 rounded border border-cyan-400/25 bg-cyan-400/10 px-3 py-1.5 text-[12px] font-medium text-cyan-200 transition hover:bg-cyan-400/15 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50"
          >
            {busy ? "Ingesting…" : "Choose a file"}
          </button>
          <input
            ref={fileRef}
            type="file"
            className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void onFile(f); }}
          />
        </div>

        {result && (
          <div className="mt-4">
            {result.state === "error" ? (
              <p className="rounded border border-amber-400/20 bg-amber-400/[0.06] p-3 text-[12px] text-amber-100">
                {result.error}
              </p>
            ) : (
              <div className="flex flex-wrap items-baseline gap-6 rounded border border-emerald-400/20 bg-emerald-400/[0.06] p-4">
                <Metric value={result.data?.findings_count ?? 0} label="findings parsed" tone="good" />
                {/* Which tenant it landed in, stated plainly. Everything used to
                    land in "default" regardless of the credential. */}
                <div className="text-[12px] text-slate-400">
                  filed under <Mono>{result.data?.org_id ?? "unknown"}</Mono>
                </div>
              </div>
            )}
          </div>
        )}
      </Panel>

      <Panel title="What we can read" right={<Mono>{supported.source}</Mono>}>
        <Resolve
          result={supported}
          what="the supported-scanner list"
          empty={{ headline: "No normalizers reported.", because: "The ingest service answered, but listed no supported scanners." }}
        >
          {(data) => (
            <div className="flex flex-wrap gap-1.5">
              {(data.supported_scanners ?? []).map((s) => (
                <span key={s} className="rounded border border-white/8 bg-white/[0.03] px-2 py-0.5 font-mono text-[11px] text-slate-400">
                  {s}
                </span>
              ))}
            </div>
          )}
        </Resolve>
      </Panel>
    </div>
  );
}
