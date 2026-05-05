/**
 * CryptoTrustHub — Cryptographic Posture & PKI unified hero
 * (Phase 3 UX consolidation, 2026-05-02)
 *
 * Folds 5 standalone crypto / PKI / certificate pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11 (S11 Cloud Posture — Crypto sub-cluster).
 *
 *   tab        | source page             | endpoint
 *   -----------|-------------------------|----------------------------------------------
 *   keys       | CryptoKeyDashboard      | /api/v1/crypto-keys/{keys,stats,expiring}
 *   certs      | CertificateDashboard    | /api/v1/certificates/{certificates,stats,alerts}
 *   manager    | CertificateManager      | /api/v1/certificates/{certificates,stats,alerts}
 *   pki        | PKIManagementDashboard  | /api/v1/pki/{stats,certificates,cas}
 *   quantum    | QuantumCryptoDashboard  | /api/v1/quantum-crypto/{health,status,keys}
 *
 * Route: /discover/crypto
 * Persona target: Sec Architect (#11), GRC Analyst (#12), Compliance Mgr (#13)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.11
 */

import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { Key, ShieldCheck, FileBadge, Network, Atom } from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { CryptoKeysPanel } from "@/components/crypto/CryptoKeysPanel";
import { CertificatesPanel } from "@/components/crypto/CertificatesPanel";
import { CertificateManagerPanel } from "@/components/crypto/CertificateManagerPanel";
import { PKIPanel } from "@/components/crypto/PKIPanel";
import { QuantumCryptoPanel } from "@/components/crypto/QuantumCryptoPanel";

type TabKey = "keys" | "certs" | "manager" | "pki" | "quantum";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "keys",
    label: "Crypto Keys",
    icon: Key,
    description:
      "Cryptographic key inventory with rotation/expiry tracking (Folded from CryptoKeyDashboard).",
  },
  {
    key: "certs",
    label: "Certificates",
    icon: ShieldCheck,
    description:
      "TLS / signing / client certificates with expiry and trust-store details (Folded from CertificateDashboard).",
  },
  {
    key: "manager",
    label: "Cert Manager",
    icon: FileBadge,
    description:
      "Operational certificate lifecycle workflows — issue, renew, revoke (Folded from CertificateManager).",
  },
  {
    key: "pki",
    label: "PKI",
    icon: Network,
    description:
      "Internal PKI hierarchy — CAs, intermediates, issued certs and chain-of-trust (Folded from PKIManagementDashboard).",
  },
  {
    key: "quantum",
    label: "Post-Quantum",
    icon: Atom,
    description:
      "Quantum-readiness assessments, asset inventory and PQC migration tracking (Folded from QuantumCryptoDashboard).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function CryptoTrustHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "keys";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Crypto & Trust"
        description="Unified cryptographic posture — keys, certificates, PKI hierarchy, and post-quantum readiness."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        {/* WIRED: crypto-keys inventory + stats + expiring */}
        <TabsContent value="keys">
          <Suspense fallback={<PageSkeleton />}>
            <CryptoKeysPanel />
          </Suspense>
        </TabsContent>

        {/* WIRED: certificate inventory + stats + expiry alerts */}
        <TabsContent value="certs">
          <Suspense fallback={<PageSkeleton />}>
            <CertificatesPanel />
          </Suspense>
        </TabsContent>

        {/* WIRED: cert manager — weak certs, domain TLS probe, lifecycle operations */}
        <TabsContent value="manager">
          <Suspense fallback={<PageSkeleton />}>
            <CertificateManagerPanel />
          </Suspense>
        </TabsContent>

        {/* WIRED: PKI hierarchy — CAs, intermediates, issued certs */}
        <TabsContent value="pki">
          <Suspense fallback={<PageSkeleton />}>
            <PKIPanel />
          </Suspense>
        </TabsContent>

        {/* WIRED: post-quantum readiness + health checks + active PQC key */}
        <TabsContent value="quantum">
          <Suspense fallback={<PageSkeleton />}>
            <QuantumCryptoPanel />
          </Suspense>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
