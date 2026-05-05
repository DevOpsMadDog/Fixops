/**
 * AttestationSignPanel — tab "sign" in SBOMProvenanceHub
 *
 * Form to generate a new in-toto SLSA v0.2 attestation via
 * POST /api/v1/slsa/attest (slsaApi.attest).
 *
 * Shows the resulting DSSE envelope with copy-to-clipboard and
 * an optional verify call POST /api/v1/slsa/verify/{id}.
 */

import { useState } from "react";
import { PenSquare, RefreshCw, Send, Copy, CheckCircle, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { slsaApi } from "@/lib/api";

interface SignResult {
  id?: string;
  subject_name?: string;
  builder_id?: string;
  slsa_level?: number;
  dsse_envelope?: unknown;
  verified?: boolean;
  [key: string]: unknown;
}

interface VerifyResult {
  verified?: boolean;
  verifier?: string;
  message?: string;
  [key: string]: unknown;
}

export function AttestationSignPanel() {
  const [subjectName, setSubjectName] = useState("");
  const [subjectDigest, setSubjectDigest] = useState("");
  const [builderId, setBuilderId] = useState("aldeci-native");
  const [buildType, setBuildType] = useState("https://slsa.dev/build-type/v1");
  const [slsaLevel, setSlsaLevel] = useState<number>(1);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [result, setResult] = useState<SignResult | null>(null);

  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const [copied, setCopied] = useState(false);

  function handleSign(e: React.FormEvent) {
    e.preventDefault();
    if (!subjectName.trim() || !subjectDigest.trim()) return;
    setSubmitting(true);
    setSubmitError(null);
    setResult(null);
    setVerifyResult(null);
    slsaApi
      .attest({
        subject_name: subjectName.trim(),
        subject_digest: subjectDigest.trim(),
        builder_id: builderId.trim() || "aldeci-native",
        build_type: buildType.trim() || "https://slsa.dev/build-type/v1",
        slsa_level: slsaLevel,
        org_id: "default",
      })
      .then((r) => setResult(r.data as SignResult))
      .catch((e: unknown) => {
        const msg =
          (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
          (e instanceof Error ? e.message : "Signing failed");
        setSubmitError(msg);
      })
      .finally(() => setSubmitting(false));
  }

  function handleVerify() {
    if (!result?.id) return;
    setVerifying(true);
    setVerifyError(null);
    slsaApi
      .verify(result.id)
      .then((r) => setVerifyResult(r.data as VerifyResult))
      .catch((e: unknown) => {
        const msg =
          (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
          (e instanceof Error ? e.message : "Verification failed");
        setVerifyError(msg);
      })
      .finally(() => setVerifying(false));
  }

  function copyEnvelope() {
    const text = JSON.stringify(result?.dsse_envelope ?? result, null, 2);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="mt-4 space-y-6">
      {/* Sign form */}
      <Card className="bg-card/60 border-border/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <PenSquare className="h-4 w-4" />
            Generate SLSA Attestation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSign} className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">
                  Subject name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={subjectName}
                  onChange={(e) => setSubjectName(e.target.value)}
                  placeholder="my-app:v1.2.3"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">
                  Subject digest (SHA-256) <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={subjectDigest}
                  onChange={(e) => setSubjectDigest(e.target.value)}
                  placeholder="sha256:abc123..."
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Builder ID</label>
                <input
                  type="text"
                  value={builderId}
                  onChange={(e) => setBuilderId(e.target.value)}
                  placeholder="aldeci-native"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">Build type URI</label>
                <input
                  type="text"
                  value={buildType}
                  onChange={(e) => setBuildType(e.target.value)}
                  placeholder="https://slsa.dev/build-type/v1"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">SLSA level</label>
              <div className="flex gap-2">
                {([1, 2, 3, 4] as const).map((lvl) => (
                  <button
                    key={lvl}
                    type="button"
                    onClick={() => setSlsaLevel(lvl)}
                    className={`rounded-md border px-3 py-1 text-xs font-medium transition-colors ${
                      slsaLevel === lvl
                        ? "border-primary bg-primary/20 text-primary"
                        : "border-border bg-background text-muted-foreground hover:bg-muted/40"
                    }`}
                  >
                    L{lvl}
                  </button>
                ))}
              </div>
            </div>

            {submitError && (
              <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-400">
                {submitError}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting || !subjectName.trim() || !subjectDigest.trim()}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {submitting ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Send className="h-3.5 w-3.5" />
              )}
              {submitting ? "Signing…" : "Sign Attestation"}
            </button>
          </form>
        </CardContent>
      </Card>

      {/* Result */}
      {result && (
        <Card className="bg-card/60 border-border/50">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-400" />
                Attestation Generated
              </CardTitle>
              <div className="flex gap-2">
                <button
                  onClick={copyEnvelope}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1 text-xs text-muted-foreground hover:bg-muted/40 transition-colors"
                >
                  {copied ? (
                    <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                  ) : (
                    <Copy className="h-3.5 w-3.5" />
                  )}
                  {copied ? "Copied" : "Copy DSSE"}
                </button>
                <button
                  onClick={handleVerify}
                  disabled={verifying || !result.id}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1 text-xs text-muted-foreground hover:bg-muted/40 disabled:opacity-50 transition-colors"
                >
                  {verifying ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <ShieldCheck className="h-3.5 w-3.5" />
                  )}
                  {verifying ? "Verifying…" : "Verify"}
                </button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-2 text-xs">
              {result.id && (
                <>
                  <span className="text-muted-foreground">Attestation ID</span>
                  <span className="font-mono col-span-1 sm:col-span-2 truncate">{result.id}</span>
                </>
              )}
              {result.subject_name && (
                <>
                  <span className="text-muted-foreground">Subject</span>
                  <span className="col-span-1 sm:col-span-2">{result.subject_name}</span>
                </>
              )}
              {result.slsa_level != null && (
                <>
                  <span className="text-muted-foreground">SLSA Level</span>
                  <span>
                    <Badge variant="outline" className="text-xs">
                      L{result.slsa_level}
                    </Badge>
                  </span>
                </>
              )}
            </div>

            {verifyError && (
              <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-400">
                {verifyError}
              </div>
            )}
            {verifyResult && (
              <div
                className={`rounded-lg border p-3 text-xs ${
                  verifyResult.verified
                    ? "border-green-800 bg-green-950/30 text-green-400"
                    : "border-amber-800 bg-amber-950/30 text-amber-400"
                }`}
              >
                {verifyResult.verified ? "Verified" : "Not verified"}
                {verifyResult.message ? ` — ${verifyResult.message}` : ""}
              </div>
            )}

            <pre className="text-xs text-muted-foreground overflow-auto max-h-64 rounded bg-muted/60 p-2 leading-relaxed">
              {JSON.stringify(result.dsse_envelope ?? result, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
