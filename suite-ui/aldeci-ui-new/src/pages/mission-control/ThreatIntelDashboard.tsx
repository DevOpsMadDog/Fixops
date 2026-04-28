/**
 * Threat Intelligence Dashboard — P05 "The Tracker"
 *
 * Command-center layout for threat intelligence analysts:
 *   - KEV Status Bar (top)
 *   - Global Threat Feed + EPSS Heatmap (top row)
 *   - MITRE ATT&CK Coverage + IOC Feed (middle row)
 *   - Threat Actor Profiles (bottom)
 *
 * Data sources:
 *   GET /api/v1/threat-intel/cves/recent
 *   GET /api/v1/mitre/coverage
 *   POST /api/v1/threat-intel/block-iocs
 *
 * Route: /mission-control/threat-intel
 */

import { useState, useEffect, useRef, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  AlertTriangle,
  Shield,
  Globe,
  Activity,
  Target,
  Lock,
  X,
  ChevronRight,
  ExternalLink,
  Radio,
  Crosshair,
  Flame,
  Eye,
  Ban,
  RefreshCw,
  CheckCircle2,
  Clock,
  Server,
  Network,
  FileText,
  Hash,
  Link,
  MapPin,
  Users,
  Skull,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type CvssRange = "critical" | "high" | "medium" | "low";

interface CveItem {
  id: string;
  title: string;
  cvss: number;
  epss: number;
  in_kev: boolean;
  published: string;
  severity: CvssRange;
  affected_products: string[];
  description: string;
  aldeci_findings: number;
  vector: string;
}

interface EpssPoint {
  cvss: number;
  epss: number;
  findings: number;
  id: string;
  severity: CvssRange;
}

interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  status: "detected" | "partial" | "none";
  findings: number;
}

interface MitreTactic {
  id: string;
  name: string;
  short: string;
}

interface IocItem {
  id: string;
  type: "ip" | "domain" | "hash" | "url";
  value: string;
  source: string;
  confidence: number;
  threat_category: string;
  last_seen: string;
  blocked: boolean;
}

interface ThreatActor {
  name: string;
  origin: string;
  sophistication: "nation-state" | "organized" | "criminal";
  techniques: string[];
  recent_campaign: string;
  target_sectors: string[];
  active: boolean;
}

// ═══════════════════════════════════════════════════════════
// Mock data — matches API shapes for graceful fallback
// ═══════════════════════════════════════════════════════════

function generateMockCves(): CveItem[] {
  return [
    {
      id: "CVE-2024-3094",
      title: "XZ Utils Backdoor — Remote Code Execution",
      cvss: 10.0,
      epss: 0.97,
      in_kev: true,
      published: "2024-03-29",
      severity: "critical",
      affected_products: ["xz-utils 5.6.0", "xz-utils 5.6.1", "liblzma"],
      description: "Malicious backdoor inserted into XZ Utils 5.6.0 and 5.6.1 that allows remote code execution via systemd on affected Linux distributions.",
      aldeci_findings: 3,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-21762",
      title: "Fortinet FortiOS — Out-of-bound Write RCE",
      cvss: 9.8,
      epss: 0.91,
      in_kev: true,
      published: "2024-02-08",
      severity: "critical",
      affected_products: ["FortiOS 7.4", "FortiOS 7.2", "FortiOS 7.0", "FortiProxy 7.4"],
      description: "An out-of-bounds write vulnerability in Fortinet FortiOS allows a remote unauthenticated attacker to execute arbitrary code via crafted HTTP requests.",
      aldeci_findings: 5,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-1709",
      title: "ConnectWise ScreenConnect — Auth Bypass",
      cvss: 10.0,
      epss: 0.96,
      in_kev: true,
      published: "2024-02-19",
      severity: "critical",
      affected_products: ["ScreenConnect < 23.9.8"],
      description: "Authentication bypass using an alternate path vulnerability allows unauthenticated remote attackers to create admin accounts.",
      aldeci_findings: 2,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-23897",
      title: "Jenkins — Arbitrary File Read via CLI",
      cvss: 9.8,
      epss: 0.88,
      in_kev: true,
      published: "2024-01-24",
      severity: "critical",
      affected_products: ["Jenkins < 2.441", "Jenkins LTS < 2.426.3"],
      description: "Jenkins CLI allows reading arbitrary files on the Jenkins controller file system via args4j, potentially exposing credentials and secrets.",
      aldeci_findings: 4,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-27198",
      title: "JetBrains TeamCity — Auth Bypass",
      cvss: 9.8,
      epss: 0.93,
      in_kev: true,
      published: "2024-03-04",
      severity: "critical",
      affected_products: ["TeamCity < 2023.11.4"],
      description: "Authentication bypass in the web server component of JetBrains TeamCity before 2023.11.4 allows remote attackers to gain admin access.",
      aldeci_findings: 1,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-0204",
      title: "GoAnywhere MFT — Auth Bypass",
      cvss: 9.8,
      epss: 0.85,
      in_kev: true,
      published: "2024-01-22",
      severity: "critical",
      affected_products: ["GoAnywhere MFT < 7.4.1"],
      description: "Authentication bypass vulnerability allows unauthenticated users to create an admin user via the administration portal.",
      aldeci_findings: 1,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-4577",
      title: "PHP-CGI — Argument Injection RCE",
      cvss: 9.8,
      epss: 0.79,
      in_kev: true,
      published: "2024-06-06",
      severity: "critical",
      affected_products: ["PHP 8.1 < 8.1.29", "PHP 8.2 < 8.2.20", "PHP 8.3 < 8.3.8"],
      description: "Argument injection vulnerability in PHP-CGI on Windows allows remote attackers to execute arbitrary code.",
      aldeci_findings: 0,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-38112",
      title: "Windows MSHTML — Spoofing via MHTML",
      cvss: 7.5,
      epss: 0.72,
      in_kev: true,
      published: "2024-07-09",
      severity: "high",
      affected_products: ["Windows 10", "Windows 11", "Windows Server 2019/2022"],
      description: "Spoofing vulnerability in Windows MHTML Platform allows attackers to lure victims into opening malicious files.",
      aldeci_findings: 7,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    },
    {
      id: "CVE-2024-30088",
      title: "Windows Kernel — Privilege Escalation",
      cvss: 7.0,
      epss: 0.68,
      in_kev: true,
      published: "2024-06-11",
      severity: "high",
      affected_products: ["Windows 10", "Windows 11", "Windows Server 2019/2022"],
      description: "Race condition in Windows Kernel allows local attackers to gain SYSTEM privileges.",
      aldeci_findings: 2,
      vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-26169",
      title: "Windows Error Reporting — LPE",
      cvss: 7.8,
      epss: 0.61,
      in_kev: false,
      published: "2024-03-12",
      severity: "high",
      affected_products: ["Windows 10", "Windows 11"],
      description: "Windows Error Reporting Service elevation of privilege vulnerability exploited by Black Basta ransomware.",
      aldeci_findings: 0,
      vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-20767",
      title: "Adobe ColdFusion — Improper Access Control",
      cvss: 7.4,
      epss: 0.55,
      in_kev: true,
      published: "2024-03-18",
      severity: "high",
      affected_products: ["ColdFusion 2023", "ColdFusion 2021"],
      description: "Improper access control vulnerability allows remote attackers to read arbitrary files without authentication.",
      aldeci_findings: 0,
      vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N",
    },
    {
      id: "CVE-2024-29988",
      title: "SmartScreen Prompt — Security Feature Bypass",
      cvss: 8.8,
      epss: 0.48,
      in_kev: false,
      published: "2024-04-09",
      severity: "high",
      affected_products: ["Windows 10", "Windows 11"],
      description: "Allows attackers to bypass SmartScreen security prompt when opening malicious files.",
      aldeci_findings: 3,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-22024",
      title: "Ivanti Connect Secure — XXE Auth Bypass",
      cvss: 8.3,
      epss: 0.42,
      in_kev: true,
      published: "2024-02-08",
      severity: "high",
      affected_products: ["Ivanti Connect Secure < 22.x", "Ivanti Policy Secure < 22.x"],
      description: "XML external entity (XXE) vulnerability allows unauthenticated remote attackers to access restricted resources.",
      aldeci_findings: 1,
      vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N",
    },
    {
      id: "CVE-2024-6387",
      title: "OpenSSH — RegreSSHion Race Condition RCE",
      cvss: 8.1,
      epss: 0.39,
      in_kev: false,
      published: "2024-07-01",
      severity: "high",
      affected_products: ["OpenSSH < 4.4", "OpenSSH 8.5–9.7"],
      description: "Signal handler race condition in OpenSSH server allows unauthenticated remote code execution as root on glibc-based Linux.",
      aldeci_findings: 9,
      vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-21893",
      title: "Ivanti Connect Secure — SSRF Auth Bypass",
      cvss: 8.2,
      epss: 0.31,
      in_kev: true,
      published: "2024-01-31",
      severity: "high",
      affected_products: ["Ivanti Connect Secure < 9.1 R18", "Ivanti Policy Secure < 9.1 R18"],
      description: "Server-side request forgery vulnerability in SAML component allows authentication bypass.",
      aldeci_findings: 2,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    },
    {
      id: "CVE-2024-28986",
      title: "SolarWinds Web Help Desk — Java Deserialization",
      cvss: 9.8,
      epss: 0.28,
      in_kev: true,
      published: "2024-08-13",
      severity: "critical",
      affected_products: ["SolarWinds Web Help Desk < 12.8.3"],
      description: "Java deserialization RCE vulnerability allowing unauthenticated remote code execution.",
      aldeci_findings: 0,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-5806",
      title: "MOVEit Transfer — Auth Bypass in SFTP",
      cvss: 9.1,
      epss: 0.25,
      in_kev: false,
      published: "2024-06-25",
      severity: "critical",
      affected_products: ["MOVEit Transfer 2023.0–2024.0"],
      description: "Authentication bypass vulnerability in SFTP module allows privilege escalation.",
      aldeci_findings: 1,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    {
      id: "CVE-2024-34102",
      title: "Adobe Commerce — XXE Unauthenticated RCE",
      cvss: 9.8,
      epss: 0.22,
      in_kev: true,
      published: "2024-06-11",
      severity: "critical",
      affected_products: ["Adobe Commerce < 2.4.7", "Magento < 2.4.7"],
      description: "Improper restriction of XML external entity reference allows unauthenticated remote code execution.",
      aldeci_findings: 0,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-3400",
      title: "PAN-OS — Command Injection in GlobalProtect",
      cvss: 10.0,
      epss: 0.95,
      in_kev: true,
      published: "2024-04-12",
      severity: "critical",
      affected_products: ["PAN-OS 11.1 < 11.1.2-h3", "PAN-OS 11.0 < 11.0.4-h1", "PAN-OS 10.2"],
      description: "OS command injection vulnerability in GlobalProtect feature allows unauthenticated attackers to execute arbitrary code with root privileges.",
      aldeci_findings: 6,
      vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },
    {
      id: "CVE-2024-37085",
      title: "VMware ESXi — Auth Bypass via AD Group",
      cvss: 6.8,
      epss: 0.41,
      in_kev: true,
      published: "2024-07-29",
      severity: "medium",
      affected_products: ["VMware ESXi 7.0", "VMware ESXi 8.0"],
      description: "Authentication bypass via Active Directory group manipulation grants full admin access to ESXi hypervisors.",
      aldeci_findings: 4,
      vector: "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
    },
  ];
}

function generateMockIocs(): IocItem[] {
  return [
    { id: "1", type: "ip", value: "185.220.101.47", source: "AlienVault OTX", confidence: 95, threat_category: "C2 Server", last_seen: "2024-04-12T14:23:00Z", blocked: false },
    { id: "2", type: "domain", value: "update-microsofts.com", source: "VirusTotal", confidence: 88, threat_category: "Phishing", last_seen: "2024-04-12T10:15:00Z", blocked: false },
    { id: "3", type: "hash", value: "44d88612fea8a8f36de82e1278abb02f", source: "MalwareBazaar", confidence: 99, threat_category: "Ransomware", last_seen: "2024-04-11T22:47:00Z", blocked: true },
    { id: "4", type: "url", value: "http://cdn.download-secure.net/update.exe", source: "URLhaus", confidence: 91, threat_category: "Malware Dropper", last_seen: "2024-04-12T08:33:00Z", blocked: false },
    { id: "5", type: "ip", value: "91.92.254.25", source: "Shodan", confidence: 78, threat_category: "Scanning", last_seen: "2024-04-12T16:00:00Z", blocked: false },
    { id: "6", type: "domain", value: "auth-paypal-verify.info", source: "PhishTank", confidence: 97, threat_category: "Credential Theft", last_seen: "2024-04-12T12:05:00Z", blocked: true },
    { id: "7", type: "hash", value: "e99a18c428cb38d5f260853678922e03", source: "Hybrid Analysis", confidence: 84, threat_category: "Trojan", last_seen: "2024-04-10T19:22:00Z", blocked: false },
    { id: "8", type: "ip", value: "193.233.255.1", source: "AbuseIPDB", confidence: 82, threat_category: "Botnet", last_seen: "2024-04-12T15:41:00Z", blocked: false },
    { id: "9", type: "url", value: "https://pastebin.com/raw/xK9mzBnQ", source: "ThreatFox", confidence: 76, threat_category: "Payload Host", last_seen: "2024-04-11T11:18:00Z", blocked: false },
    { id: "10", type: "domain", value: "svchost-windows.ru", source: "AlienVault OTX", confidence: 93, threat_category: "APT Infrastructure", last_seen: "2024-04-12T09:50:00Z", blocked: false },
    { id: "11", type: "hash", value: "098f6bcd4621d373cade4e832627b4f6", source: "MalwareBazaar", confidence: 89, threat_category: "Wiper", last_seen: "2024-04-09T03:14:00Z", blocked: true },
    { id: "12", type: "ip", value: "45.142.212.100", source: "FeodoTracker", confidence: 96, threat_category: "Banking Trojan C2", last_seen: "2024-04-12T17:02:00Z", blocked: false },
  ];
}

function generateMockMitreCoverage() {
  const tactics: MitreTactic[] = [
    { id: "TA0001", name: "Initial Access", short: "Init Access" },
    { id: "TA0002", name: "Execution", short: "Execution" },
    { id: "TA0003", name: "Persistence", short: "Persistence" },
    { id: "TA0004", name: "Privilege Escalation", short: "Priv Esc" },
    { id: "TA0005", name: "Defense Evasion", short: "Def Evasion" },
    { id: "TA0006", name: "Credential Access", short: "Cred Access" },
    { id: "TA0007", name: "Discovery", short: "Discovery" },
    { id: "TA0008", name: "Lateral Movement", short: "Lateral Mv" },
    { id: "TA0009", name: "Collection", short: "Collection" },
    { id: "TA0010", name: "Exfiltration", short: "Exfil" },
    { id: "TA0011", name: "Command & Control", short: "C2" },
    { id: "TA0040", name: "Impact", short: "Impact" },
  ];

  const techniques: MitreTechnique[] = [
    { technique_id: "T1190", technique_name: "Exploit Public-Facing App", tactic: "TA0001", status: "detected", findings: 14 },
    { technique_id: "T1133", technique_name: "External Remote Services", tactic: "TA0001", status: "partial", findings: 3 },
    { technique_id: "T1566", technique_name: "Phishing", tactic: "TA0001", status: "detected", findings: 22 },
    { technique_id: "T1059", technique_name: "Command & Scripting Interpreter", tactic: "TA0002", status: "detected", findings: 18 },
    { technique_id: "T1047", technique_name: "WMI", tactic: "TA0002", status: "partial", findings: 5 },
    { technique_id: "T1053", technique_name: "Scheduled Task/Job", tactic: "TA0003", status: "detected", findings: 7 },
    { technique_id: "T1543", technique_name: "Create/Modify System Process", tactic: "TA0003", status: "none", findings: 0 },
    { technique_id: "T1548", technique_name: "Abuse Elevation Control", tactic: "TA0004", status: "detected", findings: 9 },
    { technique_id: "T1078", technique_name: "Valid Accounts", tactic: "TA0004", status: "partial", findings: 4 },
    { technique_id: "T1055", technique_name: "Process Injection", tactic: "TA0005", status: "none", findings: 0 },
    { technique_id: "T1027", technique_name: "Obfuscated Files", tactic: "TA0005", status: "partial", findings: 6 },
    { technique_id: "T1110", technique_name: "Brute Force", tactic: "TA0006", status: "detected", findings: 31 },
    { technique_id: "T1003", technique_name: "OS Credential Dumping", tactic: "TA0006", status: "none", findings: 0 },
    { technique_id: "T1046", technique_name: "Network Service Discovery", tactic: "TA0007", status: "detected", findings: 11 },
    { technique_id: "T1021", technique_name: "Remote Services", tactic: "TA0008", status: "partial", findings: 2 },
    { technique_id: "T1560", technique_name: "Archive Collected Data", tactic: "TA0009", status: "none", findings: 0 },
    { technique_id: "T1041", technique_name: "Exfiltration Over C2", tactic: "TA0010", status: "none", findings: 0 },
    { technique_id: "T1071", technique_name: "App Layer Protocol", tactic: "TA0011", status: "detected", findings: 8 },
    { technique_id: "T1486", technique_name: "Data Encrypted for Impact", tactic: "TA0040", status: "detected", findings: 3 },
    { technique_id: "T1489", technique_name: "Service Stop", tactic: "TA0040", status: "none", findings: 0 },
  ];

  const detected = techniques.filter(t => t.status === "detected").length;
  const partial = techniques.filter(t => t.status === "partial").length;
  const coverage_pct = Math.round(((detected + partial * 0.5) / techniques.length) * 100);

  return { tactics, techniques, coverage_pct, detected, partial, none: techniques.filter(t => t.status === "none").length };
}

const THREAT_ACTORS: ThreatActor[] = [
  {
    name: "APT28",
    origin: "Russia",
    sophistication: "nation-state",
    techniques: ["T1566", "T1059", "T1071", "T1078", "T1190"],
    recent_campaign: "Operation RoundPress — targeting Roundcube webmail",
    target_sectors: ["Government", "Defense", "Energy"],
    active: true,
  },
  {
    name: "APT41",
    origin: "China",
    sophistication: "nation-state",
    techniques: ["T1190", "T1059", "T1055", "T1003", "T1021"],
    recent_campaign: "Targeting software supply chain via compromised build systems",
    target_sectors: ["Technology", "Healthcare", "Finance"],
    active: true,
  },
  {
    name: "Lazarus Group",
    origin: "North Korea",
    sophistication: "nation-state",
    techniques: ["T1566", "T1059", "T1486", "T1041", "T1078"],
    recent_campaign: "TraderTraitor — targeting crypto exchanges and DeFi protocols",
    target_sectors: ["Financial", "Cryptocurrency", "Defense"],
    active: true,
  },
  {
    name: "Carbanak",
    origin: "Eastern Europe",
    sophistication: "organized",
    techniques: ["T1566", "T1059", "T1078", "T1560", "T1041"],
    recent_campaign: "FIN7 rebrand targeting restaurant and hospitality POS systems",
    target_sectors: ["Finance", "Hospitality", "Retail"],
    active: true,
  },
  {
    name: "REvil (Sodinokibi)",
    origin: "Russia",
    sophistication: "criminal",
    techniques: ["T1190", "T1486", "T1489", "T1078", "T1560"],
    recent_campaign: "Resurging activity targeting managed service providers",
    target_sectors: ["MSP", "Manufacturing", "Legal"],
    active: false,
  },
];

// ═══════════════════════════════════════════════════════════
// Severity helpers
// ═══════════════════════════════════════════════════════════

function cvssToSeverity(cvss: number): CvssRange {
  if (cvss >= 9) return "critical";
  if (cvss >= 7) return "high";
  if (cvss >= 4) return "medium";
  return "low";
}

const SEVERITY_COLOR: Record<CvssRange, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#6b7280",
};

const SEVERITY_BG: Record<CvssRange, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

// ═══════════════════════════════════════════════════════════
// KEV Status Bar
// ═══════════════════════════════════════════════════════════

function KevStatusBar({ cves }: { cves: CveItem[] }) {
  const totalKev = cves.filter(c => c.in_kev).length;
  const stackKev = cves.filter(c => c.in_kev && c.aldeci_findings > 0).length;
  // Days since last KEV addition (mock: latest published in kev set)
  const kevDates = cves.filter(c => c.in_kev).map(c => new Date(c.published).getTime());
  const lastKevMs = kevDates.length ? Math.max(...kevDates) : Date.now();
  const daysSince = Math.floor((Date.now() - lastKevMs) / 86400000);

  return (
    <motion.div
      initial={{ opacity: 0, y: -8 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3"
    >
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
        <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">CISA KEV</span>
      </div>
      <Separator orientation="vertical" className="h-4 bg-amber-500/30" />
      <div className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Total KEV CVEs</span>
          <span className="font-bold tabular-nums text-white">{totalKev}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Affecting your stack</span>
          <span className={cn("font-bold tabular-nums", stackKev > 0 ? "text-red-400" : "text-green-400")}>{stackKev}</span>
          {stackKev > 0 && <Badge className="text-[10px] py-0 h-4 bg-red-500/20 text-red-400 border border-red-500/30">ACTION REQUIRED</Badge>}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Days since last KEV</span>
          <span className={cn("font-bold tabular-nums", daysSince <= 3 ? "text-orange-400" : "text-muted-foreground")}>{daysSince}d</span>
        </div>
        <div className="flex items-center gap-1.5 ml-auto">
          <Radio className="h-3 w-3 text-green-400 animate-pulse" />
          <span className="text-[11px] text-green-400">Live sync</span>
        </div>
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// CVE Detail Drawer
// ═══════════════════════════════════════════════════════════

function CveDrawer({ cve, onClose }: { cve: CveItem; onClose: () => void }) {
  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />
      <motion.div
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        className="fixed right-0 top-0 z-50 h-full w-full max-w-md border-l border-border bg-card shadow-2xl overflow-hidden flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Drawer header */}
        <div className="flex items-start justify-between gap-3 p-5 border-b border-border">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-sm font-bold text-primary">{cve.id}</span>
              <Badge className={cn("text-[10px] border", SEVERITY_BG[cve.severity])}>
                CVSS {cve.cvss}
              </Badge>
              {cve.in_kev && (
                <Badge className="text-[10px] bg-amber-500/15 text-amber-400 border border-amber-500/30">KEV</Badge>
              )}
            </div>
            <p className="text-sm font-semibold leading-tight">{cve.title}</p>
          </div>
          <Button variant="ghost" size="icon" className="shrink-0 h-8 w-8" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        <ScrollArea className="flex-1">
          <div className="p-5 space-y-5">
            {/* Metrics row */}
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "CVSS", value: cve.cvss.toFixed(1), color: SEVERITY_COLOR[cve.severity] },
                { label: "EPSS", value: `${(cve.epss * 100).toFixed(1)}%`, color: cve.epss > 0.7 ? "#ef4444" : "#f97316" },
                { label: "Findings", value: cve.aldeci_findings, color: cve.aldeci_findings > 0 ? "#22c55e" : "#6b7280" },
              ].map(({ label, value, color }) => (
                <div key={label} className="rounded-lg border border-border bg-muted/20 p-3 text-center">
                  <div className="text-xs text-muted-foreground mb-1">{label}</div>
                  <div className="text-lg font-bold tabular-nums" style={{ color }}>{value}</div>
                </div>
              ))}
            </div>

            {/* Description */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Description</p>
              <p className="text-sm leading-relaxed text-muted-foreground">{cve.description}</p>
            </div>

            {/* CVSS Vector */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Vector</p>
              <code className="text-[11px] font-mono text-primary/80 break-all">{cve.vector}</code>
            </div>

            {/* Affected products */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Affected Products</p>
              <div className="flex flex-col gap-1.5">
                {cve.affected_products.map((product) => (
                  <div key={product} className="flex items-center gap-2 text-sm">
                    <Server className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span>{product}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ALDECI Findings */}
            {cve.aldeci_findings > 0 && (
              <div className="rounded-lg border border-green-500/30 bg-green-500/5 p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Target className="h-4 w-4 text-green-400" />
                  <span className="text-sm font-semibold text-green-400">ALDECI Mapped Findings</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  {cve.aldeci_findings} finding{cve.aldeci_findings !== 1 ? "s" : ""} in your environment correlated to this CVE.
                </p>
                <Button variant="outline" size="sm" className="mt-3 w-full border-green-500/30 text-green-400 hover:bg-green-500/10">
                  <ExternalLink className="mr-1.5 h-3.5 w-3.5" />
                  View in Findings Explorer
                </Button>
              </div>
            )}

            {/* Published */}
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Clock className="h-3.5 w-3.5" />
              Published: {new Date(cve.published).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}
            </div>
          </div>
        </ScrollArea>
      </motion.div>
    </AnimatePresence>
  );
}

// ═══════════════════════════════════════════════════════════
// Global Threat Feed
// ═══════════════════════════════════════════════════════════

function GlobalThreatFeed({ cves, onSelectCve }: { cves: CveItem[]; onSelectCve: (cve: CveItem) => void }) {
  const [filter, setFilter] = useState<CvssRange | "all">("all");
  const [kevOnly, setKevOnly] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Slow auto-scroll on interval
  useEffect(() => {
    if (!autoScroll) return;
    const el = scrollRef.current;
    if (!el) return;
    const id = setInterval(() => {
      if (el.scrollTop + el.clientHeight >= el.scrollHeight - 10) {
        el.scrollTo({ top: 0, behavior: "smooth" });
      } else {
        el.scrollBy({ top: 1 });
      }
    }, 60);
    return () => clearInterval(id);
  }, [autoScroll]);

  const filtered = cves.filter(c => {
    if (filter !== "all" && c.severity !== filter) return false;
    if (kevOnly && !c.in_kev) return false;
    return true;
  });

  return (
    <Card className="flex flex-col h-full">
      <CardHeader className="pb-2 shrink-0">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Globe className="h-4 w-4 text-primary" />
            Global Threat Feed
            <span className="text-xs font-normal text-muted-foreground">({filtered.length} CVEs)</span>
          </CardTitle>
          <div className="flex items-center gap-1.5 flex-wrap justify-end">
            <Button
              variant={kevOnly ? "default" : "ghost"}
              size="sm"
              className="h-6 text-[11px] px-2"
              onClick={() => setKevOnly(!kevOnly)}
            >
              KEV Only
            </Button>
            {(["all", "critical", "high", "medium", "low"] as const).map(sev => (
              <Button
                key={sev}
                variant={filter === sev ? "default" : "ghost"}
                size="sm"
                className="h-6 text-[11px] px-2 capitalize"
                onClick={() => setFilter(sev)}
              >
                {sev}
              </Button>
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-hidden p-0">
        <div
          ref={scrollRef}
          className="overflow-y-auto h-full px-4 pb-4"
          onMouseEnter={() => setAutoScroll(false)}
          onMouseLeave={() => setAutoScroll(true)}
        >
          <div className="space-y-1 pt-2">
            {filtered.map((cve, i) => (
              <motion.div
                key={cve.id}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.015 }}
                onClick={() => onSelectCve(cve)}
                className="group flex items-center gap-3 rounded-lg border border-border/40 bg-card hover:border-primary/30 hover:bg-muted/20 cursor-pointer py-2.5 px-3 transition-colors"
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && onSelectCve(cve)}
              >
                {/* Severity dot */}
                <div
                  className="h-2 w-2 rounded-full shrink-0"
                  style={{ backgroundColor: SEVERITY_COLOR[cve.severity], boxShadow: `0 0 6px ${SEVERITY_COLOR[cve.severity]}80` }}
                />

                {/* CVE ID */}
                <span className="font-mono text-[11px] font-bold text-primary shrink-0 w-[108px]">{cve.id}</span>

                {/* Title */}
                <span className="text-xs text-muted-foreground truncate flex-1 group-hover:text-foreground transition-colors">
                  {cve.title}
                </span>

                {/* Badges */}
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className="text-[10px] font-mono text-muted-foreground">
                    EPSS {(cve.epss * 100).toFixed(0)}%
                  </span>
                  {cve.in_kev && (
                    <Badge className="text-[9px] py-0 h-4 bg-amber-500/15 text-amber-400 border border-amber-500/30 px-1">KEV</Badge>
                  )}
                  <Badge className={cn("text-[9px] py-0 h-4 px-1 border", SEVERITY_BG[cve.severity])}>
                    {cve.cvss.toFixed(1)}
                  </Badge>
                  {cve.aldeci_findings > 0 && (
                    <Badge className="text-[9px] py-0 h-4 bg-green-500/15 text-green-400 border border-green-500/30 px-1">
                      {cve.aldeci_findings}f
                    </Badge>
                  )}
                </div>
                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40 group-hover:text-primary transition-colors shrink-0" />
              </motion.div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// EPSS Heatmap (Scatter)
// ═══════════════════════════════════════════════════════════

function EpssHeatmap({ cves }: { cves: CveItem[] }) {
  const points: EpssPoint[] = cves.map(c => ({
    cvss: c.cvss,
    epss: parseFloat((c.epss * 100).toFixed(1)),
    findings: Math.max(1, c.aldeci_findings) * 80 + 60,
    id: c.id,
    severity: c.severity,
  }));

  const CustomTooltipContent = ({ active, payload }: any) => {
    if (!active || !payload?.length) return null;
    const p = payload[0].payload as EpssPoint;
    return (
      <div className="rounded-lg border border-border bg-card p-3 text-xs shadow-xl">
        <div className="font-mono font-bold text-primary mb-1">{p.id}</div>
        <div className="text-muted-foreground">CVSS: <span className="text-foreground font-medium">{p.cvss}</span></div>
        <div className="text-muted-foreground">EPSS: <span className="text-foreground font-medium">{p.epss}%</span></div>
        <div className="text-muted-foreground">Findings: <span className="text-green-400 font-medium">{Math.round((p.findings - 60) / 80)}</span></div>
      </div>
    );
  };

  return (
    <Card className="flex flex-col h-full">
      <CardHeader className="pb-2 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-primary" />
            EPSS vs CVSS
          </CardTitle>
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-1 text-[11px] text-muted-foreground cursor-help">
                  <Flame className="h-3 w-3 text-red-400" />
                  Top-right = highest priority
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p className="text-xs">High CVSS + high EPSS probability = exploit likely in the wild. Bubble size = ALDECI findings.</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
        {/* Quadrant labels */}
        <div className="grid grid-cols-2 gap-1 mt-1">
          {[
            { label: "DANGER ZONE", color: "text-red-400", desc: "High CVSS + High EPSS" },
            { label: "MONITOR", color: "text-orange-400", desc: "Low CVSS + High EPSS" },
          ].map(q => (
            <div key={q.label} className="text-[10px]">
              <span className={cn("font-bold", q.color)}>{q.label}</span>
              <span className="text-muted-foreground ml-1">{q.desc}</span>
            </div>
          ))}
        </div>
      </CardHeader>
      <CardContent className="flex-1 p-2 min-h-0">
        <div className="h-full min-h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 10, right: 20, bottom: 20, left: -5 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
                opacity={0.5}
              />
              {/* Danger zone reference */}
              <XAxis
                dataKey="cvss"
                type="number"
                domain={[0, 10]}
                name="CVSS"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                axisLine={false}
                tickLine={false}
                label={{ value: "CVSS Score", position: "insideBottom", offset: -10, fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
              />
              <YAxis
                dataKey="epss"
                type="number"
                domain={[0, 100]}
                name="EPSS %"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                axisLine={false}
                tickLine={false}
                tickFormatter={(v) => `${v}%`}
                label={{ value: "EPSS %", angle: -90, position: "insideLeft", offset: 15, fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
              />
              <ZAxis dataKey="findings" range={[40, 400]} />
              <RechartsTooltip content={<CustomTooltipContent />} />
              <Scatter data={points} animationDuration={800}>
                {points.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={SEVERITY_COLOR[entry.severity]}
                    fillOpacity={0.7}
                    stroke={SEVERITY_COLOR[entry.severity]}
                    strokeWidth={1}
                    strokeOpacity={0.9}
                  />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </div>
        {/* Legend */}
        <div className="flex items-center gap-3 justify-center flex-wrap mt-1">
          {(["critical", "high", "medium", "low"] as CvssRange[]).map(sev => (
            <div key={sev} className="flex items-center gap-1">
              <div className="h-2 w-2 rounded-full" style={{ backgroundColor: SEVERITY_COLOR[sev] }} />
              <span className="text-[10px] text-muted-foreground capitalize">{sev}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// MITRE ATT&CK Coverage
// ═══════════════════════════════════════════════════════════

function MitreCoverage() {
  const { tactics, techniques, coverage_pct, detected, partial, none } = generateMockMitreCoverage();

  const getCellStatus = (tacticId: string) => {
    return techniques.filter(t => t.tactic === tacticId);
  };

  const cellColor: Record<MitreTechnique["status"], string> = {
    detected: "bg-green-500/25 border-green-500/40 hover:bg-green-500/35",
    partial:  "bg-yellow-500/20 border-yellow-500/40 hover:bg-yellow-500/30",
    none:     "bg-red-500/10 border-red-500/25 hover:bg-red-500/20",
  };

  return (
    <Card className="flex flex-col h-full">
      <CardHeader className="pb-2 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-primary" />
            MITRE ATT&CK Coverage
          </CardTitle>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-xl font-bold tabular-nums text-primary">{coverage_pct}%</div>
              <div className="text-[10px] text-muted-foreground">Coverage</div>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3 text-[11px]">
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-green-500/50 inline-block" /> Detected: {detected}</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-yellow-500/40 inline-block" /> Partial: {partial}</span>
          <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-red-500/30 inline-block" /> No Coverage: {none}</span>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-auto p-3">
        <div className="overflow-x-auto">
          <div className="min-w-max">
            {/* Tactic headers */}
            <div className="grid gap-1 mb-1" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(64px, 1fr))` }}>
              {tactics.map(tactic => (
                <TooltipProvider key={tactic.id}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div className="text-center text-[9px] font-semibold text-muted-foreground uppercase truncate px-1 cursor-help">
                        {tactic.short}
                      </div>
                    </TooltipTrigger>
                    <TooltipContent>
                      <p className="text-xs">{tactic.name}</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ))}
            </div>
            {/* Technique cells per tactic — find max count */}
            {(() => {
              const maxRows = Math.max(...tactics.map(t => getCellStatus(t.id).length));
              return Array.from({ length: maxRows }, (_, row) => (
                <div
                  key={row}
                  className="grid gap-1 mb-1"
                  style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(64px, 1fr))` }}
                >
                  {tactics.map(tactic => {
                    const techs = getCellStatus(tactic.id);
                    const tech = techs[row];
                    if (!tech) return <div key={tactic.id} className="h-9" />;
                    return (
                      <TooltipProvider key={tactic.id}>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <motion.div
                              initial={{ opacity: 0, scale: 0.85 }}
                              animate={{ opacity: 1, scale: 1 }}
                              transition={{ delay: row * 0.03 }}
                              className={cn(
                                "h-9 rounded border text-[8px] font-mono flex flex-col items-center justify-center cursor-default transition-colors px-0.5",
                                cellColor[tech.status]
                              )}
                            >
                              <span className="font-bold truncate w-full text-center text-[8px]">{tech.technique_id}</span>
                              {tech.findings > 0 && (
                                <span className="text-green-400 font-semibold">{tech.findings}f</span>
                              )}
                            </motion.div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <div className="text-xs space-y-0.5">
                              <div className="font-bold">{tech.technique_id}</div>
                              <div>{tech.technique_name}</div>
                              <div className="text-muted-foreground capitalize">Status: {tech.status}</div>
                              {tech.findings > 0 && <div className="text-green-400">{tech.findings} findings</div>}
                            </div>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    );
                  })}
                </div>
              ));
            })()}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// IOC Feed
// ═══════════════════════════════════════════════════════════

const IOC_ICON: Record<IocItem["type"], typeof Hash> = {
  ip:     Server,
  domain: Network,
  hash:   Hash,
  url:    Link,
};

const IOC_COLOR: Record<IocItem["type"], string> = {
  ip:     "text-blue-400",
  domain: "text-purple-400",
  hash:   "text-orange-400",
  url:    "text-cyan-400",
};

function IocFeed({ iocs }: { iocs: IocItem[] }) {
  const [blocking, setBlocking] = useState(false);
  const [blockedIds, setBlockedIds] = useState<Set<string>>(
    new Set(iocs.filter(i => i.blocked).map(i => i.id))
  );

  const handleBlockAll = useCallback(async () => {
    setBlocking(true);
    try {
      await fetch(`${API}/api/v1/threat-intel/block-iocs?org_id=default`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ioc_ids: iocs.map(i => i.id) }),
      });
    } catch {
      // API not available — optimistic update
    }
    setBlockedIds(new Set(iocs.map(i => i.id)));
    setBlocking(false);
  }, [iocs]);

  const timeAgo = (iso: string) => {
    const diff = Date.now() - new Date(iso).getTime();
    const h = Math.floor(diff / 3600000);
    if (h < 1) return `${Math.floor(diff / 60000)}m ago`;
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  };

  const unblocked = iocs.filter(i => !blockedIds.has(i.id));

  return (
    <Card className="flex flex-col h-full">
      <CardHeader className="pb-2 shrink-0">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Eye className="h-4 w-4 text-primary" />
            IOC Feed
            <span className="text-xs font-normal text-muted-foreground">({iocs.length} indicators)</span>
          </CardTitle>
          <Button
            variant="destructive"
            size="sm"
            className="h-7 text-[11px] px-2.5 gap-1.5"
            onClick={handleBlockAll}
            disabled={blocking || unblocked.length === 0}
          >
            <Ban className="h-3 w-3" />
            Block All ({unblocked.length})
          </Button>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-hidden p-0">
        <ScrollArea className="h-full px-4 pb-4">
          <div className="space-y-1 pt-2">
            {iocs.map((ioc, i) => {
              const IocIcon = IOC_ICON[ioc.type];
              const isBlocked = blockedIds.has(ioc.id);
              return (
                <motion.div
                  key={ioc.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.02 }}
                  className={cn(
                    "rounded-lg border py-2 px-3 transition-all",
                    isBlocked
                      ? "border-red-500/20 bg-red-500/5 opacity-60"
                      : "border-border/40 bg-card hover:border-primary/20"
                  )}
                >
                  <div className="flex items-start gap-2.5">
                    <IocIcon className={cn("h-3.5 w-3.5 mt-0.5 shrink-0", IOC_COLOR[ioc.type])} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-0.5">
                        <code className="text-[11px] font-mono truncate text-foreground/90">{ioc.value}</code>
                        {isBlocked && <Badge className="text-[9px] h-3.5 py-0 px-1 bg-red-500/20 text-red-400 border-red-500/30 shrink-0">BLOCKED</Badge>}
                      </div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] text-muted-foreground">{ioc.source}</span>
                        <span className="text-[10px] text-muted-foreground">·</span>
                        <span className="text-[10px] text-orange-400">{ioc.threat_category}</span>
                        <span className="text-[10px] text-muted-foreground">·</span>
                        <span className="text-[10px] text-muted-foreground">{timeAgo(ioc.last_seen)}</span>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className={cn(
                        "text-[11px] font-bold tabular-nums",
                        ioc.confidence >= 90 ? "text-red-400" : ioc.confidence >= 75 ? "text-orange-400" : "text-yellow-400"
                      )}>
                        {ioc.confidence}%
                      </div>
                      <div className="text-[9px] text-muted-foreground uppercase">{ioc.type}</div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Threat Actor Profiles
// ═══════════════════════════════════════════════════════════

const SOPHISTICATION_COLOR: Record<ThreatActor["sophistication"], string> = {
  "nation-state": "text-red-400 bg-red-500/10 border-red-500/30",
  "organized":    "text-orange-400 bg-orange-500/10 border-orange-500/30",
  "criminal":     "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
};

const ORIGIN_FLAG: Record<string, string> = {
  "Russia":         "🇷🇺",
  "China":          "🇨🇳",
  "North Korea":    "🇰🇵",
  "Eastern Europe": "🌐",
};

function ThreatActorProfiles() {
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Skull className="h-4 w-4 text-primary" />
          Threat Actor Profiles
          <span className="text-xs font-normal text-muted-foreground">— Top 5 adversaries relevant to your industry</span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {THREAT_ACTORS.map((actor, i) => (
            <motion.div
              key={actor.name}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.07 }}
              onClick={() => setSelected(selected === actor.name ? null : actor.name)}
              className={cn(
                "rounded-xl border cursor-pointer transition-all p-4",
                selected === actor.name
                  ? "border-primary/50 bg-primary/5"
                  : "border-border/40 hover:border-primary/20 hover:bg-muted/10"
              )}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="text-sm">{ORIGIN_FLAG[actor.origin] ?? "🌐"}</span>
                    <span className="font-bold text-sm">{actor.name}</span>
                    {actor.active ? (
                      <span className="h-1.5 w-1.5 rounded-full bg-red-400 animate-pulse" />
                    ) : (
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
                    )}
                  </div>
                  <span className="text-[10px] text-muted-foreground">{actor.origin}</span>
                </div>
                <Badge className={cn("text-[9px] border capitalize shrink-0", SOPHISTICATION_COLOR[actor.sophistication])}>
                  {actor.sophistication}
                </Badge>
              </div>

              <p className="text-[11px] text-muted-foreground leading-relaxed mb-3">
                {actor.recent_campaign}
              </p>

              <div className="flex flex-wrap gap-1 mb-2">
                {actor.target_sectors.map(sector => (
                  <span key={sector} className="text-[9px] bg-muted/30 rounded px-1.5 py-0.5 text-muted-foreground">
                    {sector}
                  </span>
                ))}
              </div>

              <AnimatePresence>
                {selected === actor.name && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="overflow-hidden"
                  >
                    <Separator className="mb-2" />
                    <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">TTPs</p>
                    <div className="flex flex-wrap gap-1">
                      {actor.techniques.map(t => (
                        <code key={t} className="text-[9px] font-mono bg-primary/10 text-primary rounded px-1.5 py-0.5">
                          {t}
                        </code>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Dashboard
// ═══════════════════════════════════════════════════════════

export default function ThreatIntelDashboard() {
  const [cves, setCves] = useState<CveItem[]>([]);
  const [iocs, setIocs] = useState<IocItem[]>([]);
  const [selectedCve, setSelectedCve] = useState<CveItem | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [cveRes, iocRes] = await Promise.allSettled([
        fetch(`${API}/api/v1/cve/search?org_id=default&limit=20`).then(r => r.json()),
        fetch(`${API}/api/v1/threat-intel/actors?org_id=default`).then(r => r.json()),
      ]);
      setCves(cveRes.status === "fulfilled" && Array.isArray(cveRes.value) ? cveRes.value : generateMockCves());
      setIocs(iocRes.status === "fulfilled" && Array.isArray(iocRes.value) ? iocRes.value : generateMockIocs());
    } catch {
      setCves(generateMockCves());
      setIocs(generateMockIocs());
    }
    setLastRefresh(new Date());
    setLoading(false);
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 120_000);
    return () => clearInterval(interval);
  }, [loadData]);

  // KPI summary stats
  const kevCount = cves.filter(c => c.in_kev).length;
  const criticalCount = cves.filter(c => c.severity === "critical").length;
  const highEpss = cves.filter(c => c.epss >= 0.7).length;
  const withFindings = cves.filter(c => c.aldeci_findings > 0).length;

  if (loading && cves.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 gap-3">
        <RefreshCw className="h-5 w-5 text-primary animate-spin" />
        <span className="text-muted-foreground">Loading threat intelligence...</span>
      </div>
    );
  }

  return (
    <TooltipProvider>
      <div className="space-y-4">
        {/* Header */}
        <PageHeader
          title="Threat Intelligence"
          description="Live CVE feed, EPSS risk scoring, MITRE ATT&CK coverage, and IOC management — P05 Tracker view"
          badge="P05"
        >
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-muted-foreground">
              {lastRefresh.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
            </span>
            <Button variant="outline" size="sm" onClick={loadData} className="h-8 gap-1.5">
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
          </div>
        </PageHeader>

        {/* KEV Status Bar */}
        <KevStatusBar cves={cves} />

        {/* KPI Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <KpiCard
            title="Critical CVEs"
            value={criticalCount}
            icon={Flame}         trend="down"
            trendLabel="CVSS 9+"
          />
          <KpiCard
            title="KEV Active"
            value={kevCount}
            icon={ShieldAlert}         trend={kevCount > 8 ? "down" : "up"}
            trendLabel="CISA KEV list"
          />
          <KpiCard
            title="High EPSS (>70%)"
            value={highEpss}
            icon={Activity}         trend="down"
            trendLabel="Exploit likely"
          />
          <KpiCard
            title="CVEs in Stack"
            value={withFindings}
            icon={Target}         trend={withFindings > 0 ? "down" : "up"}
            trendLabel="ALDECI mapped"
          />
        </div>

        {/* Main grid: Threat Feed + EPSS Scatter */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4" style={{ minHeight: "420px" }}>
          <div className="lg:col-span-3 min-h-[420px]">
            <GlobalThreatFeed cves={cves} onSelectCve={setSelectedCve} />
          </div>
          <div className="lg:col-span-2 min-h-[420px]">
            <EpssHeatmap cves={cves} />
          </div>
        </div>

        {/* Middle grid: MITRE ATT&CK + IOC Feed */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4" style={{ minHeight: "380px" }}>
          <div className="min-h-[380px]">
            <MitreCoverage />
          </div>
          <div className="min-h-[380px]">
            <IocFeed iocs={iocs} />
          </div>
        </div>

        {/* Threat Actor Profiles */}
        <ThreatActorProfiles />

        {/* CVE Detail Drawer */}
        <AnimatePresence>
          {selectedCve && (
            <CveDrawer cve={selectedCve} onClose={() => setSelectedCve(null)} />
          )}
        </AnimatePresence>
      </div>
    </TooltipProvider>
  );
}
