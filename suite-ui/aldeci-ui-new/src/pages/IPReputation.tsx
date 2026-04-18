/**
 * IP Reputation Lookup
 *
 * Search IP addresses, display ASN/organization/country, open ports, CVEs, C2 status.
 * Route: /ip-reputation
 *
 * API: GET /api/v1/cve/ip/{ip} — falls back to mock data on failure.
 */

import { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search,
  AlertTriangle,
  Globe,
  Network,
  Shield,
  AlertCircle,
  Copy,
  Check,
  ExternalLink,
  Flag,
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

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

interface IPReputationData {
  ip: string;
  asn: string;
  organization: string;
  country: string;
  country_code: string;
  open_ports: number[];
  hostnames: string[];
  known_cves: string[];
  abuse_confidence_score: number;
  is_c2: boolean;
  c2_tracker: string | null;
  reputation_sources: string[];
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const QUICK_IPS = [
  { ip: "8.8.8.8", label: "Google Public DNS" },
  { ip: "1.1.1.1", label: "Cloudflare DNS" },
];

const MOCK_IP_DATA: Record<string, IPReputationData> = {
  "8.8.8.8": {
    ip: "8.8.8.8",
    asn: "AS15169",
    organization: "Google LLC",
    country: "United States",
    country_code: "US",
    open_ports: [53, 443],
    hostnames: ["dns.google", "google-dns-a.google.com"],
    known_cves: [],
    abuse_confidence_score: 0,
    is_c2: false,
    c2_tracker: null,
    reputation_sources: ["GOOGLE", "ABUSEIPDB"],
  },
  "1.1.1.1": {
    ip: "1.1.1.1",
    asn: "AS13335",
    organization: "Cloudflare Inc.",
    country: "United States",
    country_code: "US",
    open_ports: [53, 443],
    hostnames: ["one.one.one.one"],
    known_cves: [],
    abuse_confidence_score: 0,
    is_c2: false,
    c2_tracker: null,
    reputation_sources: ["CLOUDFLARE", "ABUSEIPDB"],
  },
};

const COUNTRY_FLAGS: Record<string, string> = {
  US: "🇺🇸",
  GB: "🇬🇧",
  DE: "🇩🇪",
  FR: "🇫🇷",
  RU: "🇷🇺",
  CN: "🇨🇳",
  KP: "🇰🇵",
  IR: "🇮🇷",
  SY: "🇸🇾",
  CU: "🇨🇺",
};

// ═══════════════════════════════════════════════════════════
// Helper functions
// ═══════════════════════════════════════════════════════════

function isValidIP(ip: string): boolean {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

function getAbuseConfidenceColor(score: number): string {
  if (score >= 75) return "bg-red-500/20 text-red-700 border-red-500/50";
  if (score >= 50) return "bg-orange-500/20 text-orange-700 border-orange-500/50";
  if (score >= 25) return "bg-yellow-500/20 text-yellow-700 border-yellow-500/50";
  return "bg-green-500/20 text-green-700 border-green-500/50";
}

function getCountryFlag(countryCode: string): string {
  return COUNTRY_FLAGS[countryCode] || "🌍";
}

// ═══════════════════════════════════════════════════════════
// Component
// ═══════════════════════════════════════════════════════════

export default function IPReputation() {
  const [searchInput, setSearchInput] = useState("");
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Fetch IP data from API or mock
  const { data: ipData, isLoading } = useQuery({
    queryKey: ["ip-reputation", selectedIP],
    queryFn: async () => {
      if (!selectedIP) return null;

      // Try API first
      try {
        const response = await fetch(`${API}/api/v1/cve/ip/${selectedIP}`);
        if (response.ok) {
          return await response.json();
        }
      } catch (_err) {
        // Fall back to mock
      }

      // Return mock data if available
      return MOCK_IP_DATA[selectedIP] || null;
    },
    enabled: !!selectedIP,
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = searchInput.trim();
    if (trimmed && isValidIP(trimmed)) {
      setSelectedIP(trimmed);
    }
  };

  const handleQuickSelect = (ip: string) => {
    setSearchInput(ip);
    setSelectedIP(ip);
  };

  const handleCheckMyIP = async () => {
    try {
      const response = await fetch("https://api.ipify.org?format=json");
      const data = await response.json();
      if (data.ip) {
        setSearchInput(data.ip);
        setSelectedIP(data.ip);
      }
    } catch (_err) {
      // Fallback: use a placeholder
      setSearchInput("your-ip-here");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 px-4 py-8">
      <PageHeader
        title="IP Reputation Lookup"
        description="Search IP addresses and view threat intelligence, open ports, and C2 status"
        icon={<Globe className="w-8 h-8" />}
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
              <CardTitle className="text-lg">Search IP Address</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Search input */}
              <form onSubmit={handleSearch} className="flex gap-2">
                <Input
                  placeholder="Enter IP address (e.g. 8.8.8.8)"
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

              {/* Quick access buttons */}
              <div className="space-y-2">
                <p className="text-sm text-slate-400">Quick look:</p>
                <div className="flex flex-wrap gap-2">
                  {QUICK_IPS.map((item) => (
                    <button
                      key={item.ip}
                      onClick={() => handleQuickSelect(item.ip)}
                      className={cn(
                        "px-3 py-1 rounded-full text-sm font-medium transition-all",
                        selectedIP === item.ip
                          ? "bg-blue-600 text-white"
                          : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                      )}
                    >
                      {item.label}
                    </button>
                  ))}
                  <button
                    onClick={handleCheckMyIP}
                    className="px-3 py-1 rounded-full text-sm font-medium bg-slate-800 text-slate-300 hover:bg-slate-700 transition-all"
                  >
                    Check My IP
                  </button>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Results Section */}
        <AnimatePresence mode="wait">
          {isLoading && selectedIP && (
            <motion.div
              key="loading"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex items-center justify-center py-12"
            >
              <div className="flex flex-col items-center gap-4">
                <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                <p className="text-slate-400">Loading IP data...</p>
              </div>
            </motion.div>
          )}

          {ipData && !isLoading && (
            <motion.div
              key={selectedIP}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="space-y-6"
            >
              {/* IP Header Card */}
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader className="pb-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <CardTitle className="text-2xl font-mono">{ipData.ip}</CardTitle>
                        <span className="text-2xl">{getCountryFlag(ipData.country_code)}</span>
                      </div>
                      <p className="text-sm text-slate-400">
                        {ipData.organization} • {ipData.country} ({ipData.country_code})
                      </p>
                      <p className="text-sm text-slate-500 mt-1 font-mono">{ipData.asn}</p>
                    </div>
                    <button
                      onClick={() => copyToClipboard(ipData.ip)}
                      className="p-2 hover:bg-slate-800 rounded transition"
                    >
                      {copied ? (
                        <Check className="w-5 h-5 text-green-500" />
                      ) : (
                        <Copy className="w-5 h-5 text-slate-400" />
                      )}
                    </button>
                  </div>
                </CardHeader>
              </Card>

              {/* Risk Metrics Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Abuse Confidence Score */}
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                      <AlertCircle className="w-4 h-4" />
                      Abuse Confidence
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div
                      className={cn(
                        "px-4 py-3 rounded-lg border text-center font-bold text-xl",
                        getAbuseConfidenceColor(ipData.abuse_confidence_score)
                      )}
                    >
                      {ipData.abuse_confidence_score}%
                    </div>
                    <p className="text-xs text-slate-400 text-center">AbuseIPDB reputation</p>
                  </CardContent>
                </Card>

                {/* C2 Status */}
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium text-slate-400 flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      C2 Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {ipData.is_c2 ? (
                      <Badge className="w-full justify-center py-2 bg-red-500 text-white">
                        KNOWN C2
                      </Badge>
                    ) : (
                      <Badge className="w-full justify-center py-2 bg-green-500 text-white">
                        NOT IN C2 TRACKER
                      </Badge>
                    )}
                    {ipData.c2_tracker && (
                      <p className="text-xs text-slate-400 text-center">
                        Tracker: {ipData.c2_tracker}
                      </p>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Open Ports */}
              {ipData.open_ports.length > 0 && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Network className="w-4 h-4" />
                      Open Ports ({ipData.open_ports.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {ipData.open_ports.map((port) => (
                        <Badge
                          key={port}
                          className="bg-slate-800 text-blue-400 border border-slate-700 px-3 py-1"
                        >
                          :{port}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Hostnames */}
              {ipData.hostnames.length > 0 && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Globe className="w-4 h-4" />
                      Hostnames
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-24">
                      <div className="space-y-2 pr-4">
                        {ipData.hostnames.map((hostname, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between p-2 bg-slate-800 rounded border border-slate-700"
                          >
                            <span className="text-sm text-slate-300 font-mono truncate">
                              {hostname}
                            </span>
                            <button
                              onClick={() => copyToClipboard(hostname)}
                              className="p-1 hover:bg-slate-700 rounded transition flex-shrink-0"
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

              {/* Known CVEs */}
              {ipData.known_cves.length > 0 && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Known CVEs ({ipData.known_cves.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ScrollArea className="h-32">
                      <div className="space-y-2 pr-4">
                        {ipData.known_cves.map((cve, idx) => (
                          <a
                            key={idx}
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center justify-between p-2 bg-slate-800 rounded border border-slate-700 hover:border-red-500 transition group"
                          >
                            <span className="text-sm text-slate-300 font-mono">
                              {cve}
                            </span>
                            <ExternalLink className="w-4 h-4 text-slate-500 flex-shrink-0 group-hover:text-red-500" />
                          </a>
                        ))}
                      </div>
                    </ScrollArea>
                  </CardContent>
                </Card>
              )}

              {ipData.known_cves.length === 0 && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Known CVEs
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-slate-400">No known CVEs associated with this IP</p>
                  </CardContent>
                </Card>
              )}
            </motion.div>
          )}

          {!selectedIP && !isLoading && (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center py-12"
            >
              <Globe className="w-12 h-12 text-slate-700 mx-auto mb-4" />
              <p className="text-slate-400">Enter an IP address or select a quick look to get started</p>
            </motion.div>
          )}

          {selectedIP && !isLoading && !ipData && (
            <motion.div
              key="no-data"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-center py-12"
            >
              <AlertCircle className="w-12 h-12 text-yellow-600 mx-auto mb-4" />
              <p className="text-slate-400">No data available for this IP address</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}
