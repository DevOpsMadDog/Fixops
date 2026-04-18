/**
 * CVE Search & Enrichment
 *
 * Search CVEs by ID, view popular vulnerabilities, display CVSS/EPSS/KEV data.
 * Route: /cve-search
 *
 * API: GET /api/v1/cve/{cve_id} = falls back to mock data on failure.
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  AlertTriangle,
  Zap,
  Target,
  Shield,
  Link as LinkIcon,
  ChevronRight,
  Package,
  TrendingUp,
  Copy,
  Check,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

// ===========================================================
// Types
// ===========================================================

interface CVEData {
  cve_id: string;
  description: string;
  cvss_score: number;
  cvss_severity: "critical" | "high" | "medium" | "low";
  epss_score: number;
  epss_percentile: number;
  in_kev: boolean;
  affected_products: string[];
  references: string[];
  published_date: string;
  patch_priority: "critical" | "high" | "medium" | "low";
}

// ===========================================================
// Mock data
// ===========================================================

const POPULAR_CVES = [
  { id: "CVE-2021-44228", label: "Log4Shell" },
  { id: "CVE-2021-26855", label: "ProxyLogon" },
  { id: "CVE-2017-0143", label: "EternalBlue" },
  { id: "CVE-2014-0160", label: "Heartbleed" },
];

const MOCK_CVE_DATA: Record<string, CVEData> = {
  "CVE-2021-44228": {
    cve_id: "CVE-2021-44228",
    description: "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints. Attackers can control the Log4j2 configuration, log messages, and the public interfaces.",
    cvss_score: 10.0,
    cvss_severity: "critical",
    epss_score: 0.978,
    epss_percentile: 99,
    in_kev: true,
    affected_products: ["Apache Log4j2 2.0-beta9", "Apache Log4j2 2.0", "Apache Log4j2 2.1", "Apache Log4j2 2.15.0"],
    references: [
      "https://logging.apache.org/log4j/2.x/security.html",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    ],
    published_date: "2021-12-10",
    patch_priority: "critical",
  },
};

const DEFAULT_MOCK_CVE: CVEData = {
  cve_id: "CVE-XXXX-XXXXX",
  description: "No data available for this CVE. Check NVD or vendor advisories.",
  cvss_score: 0,
  cvss_severity: "low",
  epss_score: 0,
  epss_percentile: 0,
  in_kev: false,
  affected_products: [],
  references: [],
  published_date: "Unknown",
  patch_priority: "low",
};

// ===========================================================
// Helper functions
// ===========================================================

function getCVSSColor(score: number): string {
  if (score >= 9) return "bg-red-500/20 text-red-700 border-red-500/50";
  if (score >= 7) return "bg-orange-500/20 text-orange-700 border-orange-500/50";
  if (score >= 4) return "bg-yellow-500/20 text-yellow-700 border-yellow-500/50";
  return "bg-green-500/20 text-green-700 border-green-500/50";
}

function getPatchPriorityColor(priority: string): string {
  if (priority === "critical") return "bg-red-500 text-white";
  if (priority === "high") return "bg-orange-500 text-white";
  if (priority === "medium") return "bg-yellow-500 text-white";
  return "bg-blue-500 text-white";
}

// ===========================================================
// Component
// ===========================================================

export default function CVESearch() {
  const [searchInput, setSearchInput] = useState("");
  const [selectedCVE, setSelectedCVE] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Fetch CVE data from API or mock
  const { data: cveData, isLoading } = useQuery({
    queryKey: ["cve", selectedCVE],
    queryFn: async () => {
      if (!selectedCVE) return null;

      // Try API first
      try {
        const response = await fetch(`${API}/api/v1/cve/${selectedCVE}`, {
          headers: { "X-API-Key": API_KEY },
        });
        if (response.ok) {
          return await response.json();
        }
      } catch (_err) {
        // Fall back to mock
      }

      // Return mock data if available, or default
      return MOCK_CVE_DATA[selectedCVE] || { ...DEFAULT_MOCK_CVE, cve_id: selectedCVE };
    },
    enabled: !!selectedCVE,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = searchInput.trim().toUpperCase();
    if (trimmed) {
      setSelectedCVE(trimmed);
    }
  };

  const handleQuickSelect = (cveId: string) => {
    setSearchInput(cveId);
    setSelectedCVE(cveId);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 px-4 py-8">
      <PageHeader
        title="CVE Search & Enrichment"
        description="Search vulnerabilities by CVE ID and view enriched threat intelligence"
        icon={<Search className="w-8 h-8" />}
      />

      <div className="max-w-6xl mx-auto space-y-8">
        {/* Search Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <Card className="bg-slate-900 border-slate-700">
            <CardHeader>
              <CardTitle className="text-lg">Search CVEs</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Search input */}
              <form onSubmit={handleSearch} className="flex gap-2">
                <Input
                  placeholder="Search CVEs (e.g. CVE-2021-44228)"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  className="bg-slate-800 border-slate-700 text-slate-50 placeholder:text-slate-500"
                />
                <Button
                  type="submit"
                  className="bg-blue-600 hover:bg-blue-700 text-white px-6"
                >
                  <Search className="w-4 h-4 mr-2" />
                  Search
                </Button>
              </form>

              {/* Popular CVEs quick select */}
              <div className="space-y-2">
                <p className="text-sm text-slate-400">Popular vulnerabilities:</p>
                <div className="flex flex-wrap gap-2">
                  {POPULAR_CVES.map((cve) => (
                    <button
                      key={cve.id}
                      onClick={() => handleQuickSelect(cve.id)}
                      className={cn(
                        "px-3 py-1 rounded-full text-sm font-medium transition-all",
                        selectedCVE === cve.id
                          ? "bg-blue-600 text-white"
                          : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                      )}
                    >
                      {cve.label}
                    </button>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Results Section */}
        <AnimatePresence mode="wait">
          {isLoading && selectedCVE && (
            <motion.div
              key="loading"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex items-center justify-center py-12"
            >
              <div className="flex flex-col items-center gap-4">
                <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" / role="status" aria-live="polite">
                <p className="text-slate-400">Loading CVE data...</p>
              </div>
            </motion.div>
          )}

          {cveData && !isLoading && (
            <motion.div
              key={selectedCVE}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="space-y-6"
            >
              {/* CVE Header Card */}
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <CardTitle className="text-2xl">{cveData.cve_id}</CardTitle>
                        {cveData.in_kev && (
                          <Badge className="bg-red-500 text-white">Known Exploited</Badge>
                        )}
                        {!cveData.in_kev && (
                          <Badge className="bg-slate-700 text-slate-300">Not in KEV</Badge>
                        )}
                      </div>
                      <p className="text-sm text-slate-400">
                        Published {new Date(cveData.published_date).toLocaleDateString()}
                      </p>
                    </div>
                  </div>
                  <Separator className="bg-slate-700 my-4" />
                  <p className="text-slate-300 leading-relaxed text-sm">
                    {cveData.description}
                  </p>
                </CardHeader>
              </Card>

              {/* Risk Metrics Grid */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* CVSS Score */}
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      CVSS Score
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div
                      className={cn(
                        "px-4 py-3 rounded-lg border text-center font-bold text-xl",
                        getCVSSColor(cveData.cvss_score)
                      )}
                    >
                      {cveData.cvss_score.toFixed(1)}
                    </div>
                    <Badge
                      className={cn(
                        "w-full justify-center py-1",
                        cveData.cvss_severity === "critical"
                          ? "bg-red-500"
                          : cveData.cvss_severity === "high"
                            ? "bg-orange-500"
                            : cveData.cvss_severity === "medium"
                              ? "bg-yellow-500"
                              : "bg-green-500"
                      )}
                    >
                      {cveData.cvss_severity.toUpperCase()}
                    </Badge>
                  </CardContent>
                </Card>

                {/* EPSS Score */}
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                      <Zap className="w-4 h-4" />
                      EPSS Score
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="px-4 py-3 rounded-lg bg-slate-800 border border-slate-700 text-center">
                      <div className="font-bold text-xl text-blue-400">
                        {(cveData.epss_score * 100).toFixed(1)}%
                      </div>
                      <div className="text-xs text-slate-400 mt-1">
                        Percentile: {cveData.epss_percentile}th
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Patch Priority */}
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Patch Priority
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <Badge
                      className={cn(
                        "w-full justify-center py-2 text-center",
                        getPatchPriorityColor(cveData.patch_priority)
                      )}
                    >
                      {cveData.patch_priority.toUpperCase()}
                    </Badge>
                    <p className="text-xs text-slate-400 text-center mt-2">
                      Based on CVSS + EPSS + KEV composite
                    </p>
                  </CardContent>
                </Card>
              </div>

              {/* Affected Products */}
              {cveData.affected_products.length > 0 && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Package className="w-4 h-4" />
                      Affected Products
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-40">
                      <div className="space-y-2 pr-4">
                        {cveData.affected_products.map((product, idx) => (
                          <div
                            key={idx}
                            className="flex items-start justify-between gap-3 p-2 bg-slate-800 rounded border border-slate-700"
                          >
                            <span className="text-sm text-slate-300 flex-1">{product}</span>
                            <button
                              onClick={() => copyToClipboard(product)}
                              className="p-1 hover:bg-slate-700 rounded transition"
                            >
                              {copied ? (
                                <Check className="w-4 h-4 text-green-500" />
                              ) : (
                                <Copy className="w-4 h-4 text-slate-400" />
                              )}
                            </button>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}

              {/* References */}
              {cveData.references.length > 0 && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <LinkIcon className="w-4 h-4" />
                      References
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {cveData.references.map((ref, idx) => (
                        <a
                          key={idx}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center justify-between p-2 bg-slate-800 rounded border border-slate-700 hover:border-blue-500 transition group"
                        >
                          <span className="text-sm text-blue-400 truncate group-hover:text-blue-300">
                            {ref}
                          </span>
                          <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />
                        </a>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </motion.div>
          )}

          {!selectedCVE && !isLoading && (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center py-12"
            >
              <Search className="w-12 h-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-400">Enter a CVE ID or select a popular vulnerability to get started</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
