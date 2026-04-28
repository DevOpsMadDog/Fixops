/**
 * LandingPage — ALDECI Marketing Page
 *
 * Public route: /landing (no auth required)
 *
 * Aesthetic: Dark military-precision.
 * - Background: near-black oklch(0.13) with subtle radial glow
 * - Accent: cyan oklch(0.65 0.15 195) — the system primary
 * - Typography: "Syne" for headings (geometric, distinctive), JetBrains Mono for numerics
 * - The ONE memorable thing: live-counting stat bar on mount
 * - Animations: entrance stagger, hover lift, counter tick
 */

import { useEffect, useRef, useState } from "react";
import { motion, useInView, animate } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Cloud,
  Eye,
  Activity,
  Lock,
  Network,
  Brain,
  BarChart3,
  Cpu,
  Layers,
  ArrowRight,
  Check,
  ChevronDown,
  Zap,
  Globe,
  Terminal,
  Users,
} from "lucide-react";
import { usePageTitle } from "@/hooks/use-page-title";

// ── Fonts (injected via <link> in head) ───────────────────────
// Syne: geometric display — injected once at component mount
function useSyneFontInjection() {
  useEffect(() => {
    if (document.getElementById("syne-font-link")) return;
    const link = document.createElement("link");
    link.id = "syne-font-link";
    link.rel = "stylesheet";
    link.href =
      "https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&display=swap";
    document.head.appendChild(link);
  }, []);
}

// ── Animated counter hook ─────────────────────────────────────
function useCountUp(target: number, duration = 1.6, start = false) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (!start) return;
    const controls = animate(0, target, {
      duration,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setValue(Math.round(v)),
    });
    return () => controls.stop();
  }, [target, duration, start]);
  return value;
}

// ── Stat counter component ────────────────────────────────────
function StatCounter({
  value,
  label,
  suffix = "",
  trigger,
}: {
  value: number;
  label: string;
  suffix?: string;
  trigger: boolean;
}) {
  const count = useCountUp(value, 1.8, trigger);
  return (
    <div className="flex flex-col items-center gap-1">
      <span
        style={{
          fontFamily: "'JetBrains Mono', 'SF Mono', monospace",
          fontVariantNumeric: "tabular-nums",
          fontSize: "clamp(2rem, 4vw, 3.5rem)",
          fontWeight: 700,
          color: "oklch(0.65 0.15 195)",
          lineHeight: 1,
          letterSpacing: "-0.02em",
        }}
      >
        {count.toLocaleString()}
        {suffix}
      </span>
      <span
        style={{
          fontSize: "0.8rem",
          fontWeight: 500,
          letterSpacing: "0.12em",
          textTransform: "uppercase",
          color: "oklch(0.55 0.01 250)",
        }}
      >
        {label}
      </span>
    </div>
  );
}

// ── Feature data ──────────────────────────────────────────────
const FEATURES = [
  {
    icon: Layers,
    title: "ASPM",
    sub: "Application Security Posture",
    desc: "Full software supply chain visibility. SAST, DAST, SCA, SBOM, IaC scanning unified under one risk plane.",
  },
  {
    icon: Cloud,
    title: "CSPM",
    sub: "Cloud Security Posture",
    desc: "Continuous drift detection across AWS, GCP, Azure. CIS benchmarks, IAM analysis, misconfig auto-remediation.",
  },
  {
    icon: Eye,
    title: "CTEM",
    sub: "Continuous Threat Exposure",
    desc: "Attack surface discovery → prioritisation → validation loop. BAS, purple team, and MITRE ATT&CK coverage in one workflow.",
  },
  {
    icon: Activity,
    title: "SOC Operations",
    sub: "24/7 Threat Monitoring",
    desc: "SIEM normalisation, SOAR playbooks, alert triage AI, and MTTR dashboards. SOC T1 workflow built-in.",
  },
  {
    icon: Shield,
    title: "GRC & Compliance",
    sub: "7 Frameworks Automated",
    desc: "SOC 2, ISO 27001, PCI-DSS, HIPAA, GDPR, NIST CSF, CIS. Evidence auto-collection and audit-ready export.",
  },
  {
    icon: Lock,
    title: "Identity & Access",
    sub: "Zero Trust Enforcement",
    desc: "PAM, ITDR, CIEM, privileged session recording, MFA lifecycle, access anomaly detection, and entitlement governance.",
  },
  {
    icon: Network,
    title: "Network Security",
    sub: "East-West + Perimeter",
    desc: "NDR, firewall policy analysis, network segmentation scoring, passive DNS, microsegmentation, and geo-threat mapping.",
  },
  {
    icon: Brain,
    title: "AI-Powered SOC",
    sub: "Karpathy LLM Consensus",
    desc: "4-model council (Qwen, Kimi, Gemma, Opus) for every security decision. No single-model hallucinations.",
  },
  {
    icon: BarChart3,
    title: "Executive Reporting",
    sub: "Board-Ready Intelligence",
    desc: "CISO dashboards, KPI tracking, security ROI, risk quantification (FAIR), and one-click board deck generation.",
  },
  {
    icon: Cpu,
    title: "Advanced Threats",
    sub: "Ransomware · Zero-Day · APT",
    desc: "Dark web monitoring, threat actor tracking, ransomware protection, supply chain attack detection, and deception technologies.",
  },
] as const;

// ── Competitor pricing data ───────────────────────────────────
const COMPETITORS = [
  { name: "Wiz",       price: "$300K–$500K/yr", features: "CSPM only",       highlight: false },
  { name: "Lacework",  price: "$150K–$300K/yr", features: "CSPM + CWPP",     highlight: false },
  { name: "Snyk",      price: "$50K–$150K/yr",  features: "ASPM only",       highlight: false },
  { name: "Rapid7",    price: "$80K–$200K/yr",  features: "VM + SIEM",       highlight: false },
  { name: "ALDECI",    price: "$35–$60/mo",     features: "ALL of the above", highlight: true  },
];

// ── Testimonials ──────────────────────────────────────────────
const TESTIMONIALS = [
  {
    quote:
      "We replaced three $80K/yr tools with ALDECI. Our SOC team now has a single pane of glass for everything from ASPM to dark web monitoring.",
    name: "Director of Security Engineering",
    company: "Series B FinTech, 400 employees",
  },
  {
    quote:
      "The AI consensus engine is unlike anything I've seen. It escalates to Opus only when needed — our false positive rate dropped 68% in the first month.",
    name: "CISO",
    company: "Global Healthcare Network, 12,000 employees",
  },
  {
    quote:
      "Passed our SOC 2 Type II audit in 6 weeks. The evidence auto-collection alone saved us 200 hours. At $35/month, this is embarrassing for the incumbents.",
    name: "Head of Compliance",
    company: "SaaS Platform, 200 employees",
  },
];

// ── Stagger animation variants ────────────────────────────────
const containerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.07 } },
};

const itemVariants = {
  hidden: { opacity: 0, y: 24 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] },
  },
};

// ── Glow background element ───────────────────────────────────
function RadialGlow({
  cx,
  cy,
  color = "oklch(0.65 0.15 195 / 0.07)",
  size = 600,
}: {
  cx: string;
  cy: string;
  color?: string;
  size?: number;
}) {
  return (
    <div
      aria-hidden
      style={{
        position: "absolute",
        left: cx,
        top: cy,
        width: size,
        height: size,
        transform: "translate(-50%, -50%)",
        background: `radial-gradient(circle, ${color} 0%, transparent 70%)`,
        pointerEvents: "none",
        zIndex: 0,
      }}
    />
  );
}

// ── Main component ────────────────────────────────────────────
export default function LandingPage() {
  usePageTitle("Enterprise Security Intelligence");
  useSyneFontInjection();
  const navigate = useNavigate();

  // Stats section trigger
  const statsRef = useRef<HTMLDivElement>(null);
  const statsInView = useInView(statsRef, { once: true, margin: "-80px" });

  // Features section trigger
  const featuresRef = useRef<HTMLDivElement>(null);
  const featuresInView = useInView(featuresRef, { once: true, margin: "-60px" });

  // Pricing section trigger
  const pricingRef = useRef<HTMLDivElement>(null);
  const pricingInView = useInView(pricingRef, { once: true, margin: "-60px" });

  // Testimonials trigger
  const testimonialsRef = useRef<HTMLDivElement>(null);
  const testimonialsInView = useInView(testimonialsRef, { once: true, margin: "-60px" });

  return (
    <div
      style={{
        background: "oklch(0.13 0.01 250)",
        color: "oklch(0.93 0.005 250)",
        minHeight: "100vh",
        overflowX: "hidden",
        fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
      }}
    >
      {/* ── NAV ─────────────────────────────────────────────── */}
      <motion.nav
        initial={{ opacity: 0, y: -16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        style={{
          position: "sticky",
          top: 0,
          zIndex: 50,
          borderBottom: "1px solid oklch(0.22 0.01 250)",
          background: "oklch(0.13 0.01 250 / 0.85)",
          backdropFilter: "blur(16px)",
          WebkitBackdropFilter: "blur(16px)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 clamp(1.5rem, 5vw, 4rem)",
          height: "60px",
        }}
      >
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: 6,
              background: "oklch(0.65 0.15 195)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Shield size={16} color="oklch(0.13 0.01 250)" strokeWidth={2.5} />
          </div>
          <span
            style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 800,
              fontSize: "1.05rem",
              letterSpacing: "-0.01em",
              color: "oklch(0.95 0.005 250)",
            }}
          >
            ALDECI
          </span>
        </div>

        {/* Nav links */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "clamp(1rem, 3vw, 2rem)",
          }}
        >
          {["Features", "Pricing", "Docs"].map((item) => (
            <a
              key={item}
              href={`#${item.toLowerCase()}`}
              style={{
                fontSize: "0.875rem",
                fontWeight: 500,
                color: "oklch(0.6 0.01 250)",
                textDecoration: "none",
                transition: "color 0.15s",
              }}
              onMouseEnter={(e) =>
                ((e.target as HTMLElement).style.color = "oklch(0.93 0.005 250)")
              }
              onMouseLeave={(e) =>
                ((e.target as HTMLElement).style.color = "oklch(0.6 0.01 250)")
              }
            >
              {item}
            </a>
          ))}
          <button
            onClick={() => navigate("/login")}
            style={{
              fontSize: "0.875rem",
              fontWeight: 500,
              color: "oklch(0.6 0.01 250)",
              background: "none",
              border: "none",
              cursor: "pointer",
              padding: 0,
              transition: "color 0.15s",
            }}
            onMouseEnter={(e) =>
              ((e.target as HTMLElement).style.color = "oklch(0.93 0.005 250)")
            }
            onMouseLeave={(e) =>
              ((e.target as HTMLElement).style.color = "oklch(0.6 0.01 250)")
            }
          >
            Sign In
          </button>
          <button
            onClick={() => navigate("/onboarding")}
            style={{
              fontSize: "0.875rem",
              fontWeight: 600,
              color: "oklch(0.13 0.01 250)",
              background: "oklch(0.65 0.15 195)",
              border: "none",
              borderRadius: 8,
              padding: "0.45rem 1.1rem",
              cursor: "pointer",
              transition: "background 0.15s, transform 0.1s",
              whiteSpace: "nowrap",
            }}
            onMouseEnter={(e) => {
              (e.target as HTMLElement).style.background = "oklch(0.72 0.16 195)";
              (e.target as HTMLElement).style.transform = "scale(1.02)";
            }}
            onMouseLeave={(e) => {
              (e.target as HTMLElement).style.background = "oklch(0.65 0.15 195)";
              (e.target as HTMLElement).style.transform = "scale(1)";
            }}
          >
            Start Free Trial
          </button>
        </div>
      </motion.nav>

      {/* ── HERO ────────────────────────────────────────────── */}
      <section
        style={{
          position: "relative",
          overflow: "hidden",
          padding: "clamp(5rem, 12vw, 9rem) clamp(1.5rem, 5vw, 4rem)",
          textAlign: "center",
          minHeight: "80vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <RadialGlow cx="50%" cy="40%" color="oklch(0.65 0.15 195 / 0.08)" size={800} />
        <RadialGlow cx="15%" cy="80%" color="oklch(0.65 0.12 240 / 0.05)" size={500} />

        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
          style={{ position: "relative", zIndex: 1, marginBottom: "1.5rem" }}
        >
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.4rem",
              border: "1px solid oklch(0.65 0.15 195 / 0.4)",
              borderRadius: 9999,
              padding: "0.3rem 0.9rem",
              fontSize: "0.78rem",
              fontWeight: 600,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              color: "oklch(0.65 0.15 195)",
              background: "oklch(0.65 0.15 195 / 0.06)",
            }}
          >
            <Zap size={11} strokeWidth={2.5} />
            ASPM · CSPM · CTEM — Unified
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.18, ease: [0.16, 1, 0.3, 1] }}
          style={{
            position: "relative",
            zIndex: 1,
            fontFamily: "'Syne', sans-serif",
            fontWeight: 800,
            fontSize: "clamp(2.4rem, 6vw, 5.2rem)",
            lineHeight: 1.05,
            letterSpacing: "-0.03em",
            margin: "0 auto 0.75rem",
            maxWidth: "900px",
            color: "oklch(0.97 0.004 250)",
          }}
        >
          Enterprise Security Intelligence
          <br />
          <span style={{ color: "oklch(0.65 0.15 195)" }}>$35 / month.</span>
        </motion.h1>

        {/* Subhead */}
        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.28, ease: [0.16, 1, 0.3, 1] }}
          style={{
            position: "relative",
            zIndex: 1,
            fontSize: "clamp(1rem, 2vw, 1.25rem)",
            lineHeight: 1.6,
            color: "oklch(0.58 0.01 250)",
            maxWidth: "640px",
            margin: "0 auto 2.5rem",
          }}
        >
          The platform that replaces Wiz, Snyk, Rapid7, and your SIEM — for the price of a
          team lunch. Self-hosted, AI-native, and built for teams who refuse to overpay.
        </motion.p>

        {/* CTA buttons */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.38, ease: [0.16, 1, 0.3, 1] }}
          style={{
            position: "relative",
            zIndex: 1,
            display: "flex",
            gap: "0.75rem",
            flexWrap: "wrap",
            justifyContent: "center",
          }}
        >
          <motion.button
            whileHover={{ scale: 1.03, y: -1 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => navigate("/onboarding")}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.45rem",
              background: "oklch(0.65 0.15 195)",
              color: "oklch(0.13 0.01 250)",
              fontWeight: 700,
              fontSize: "0.95rem",
              padding: "0.7rem 1.6rem",
              borderRadius: 10,
              border: "none",
              cursor: "pointer",
              letterSpacing: "-0.01em",
            }}
          >
            Start Free Trial
            <ArrowRight size={16} strokeWidth={2.5} />
          </motion.button>
          <motion.button
            whileHover={{ scale: 1.02, y: -1 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => navigate("/discover")}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.45rem",
              background: "oklch(0.19 0.012 250)",
              color: "oklch(0.85 0.005 250)",
              fontWeight: 600,
              fontSize: "0.95rem",
              padding: "0.7rem 1.6rem",
              borderRadius: 10,
              border: "1px solid oklch(0.28 0.01 250)",
              cursor: "pointer",
            }}
          >
            <Terminal size={15} />
            Explore Platform
          </motion.button>
        </motion.div>

        {/* Scroll indicator */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.2, duration: 0.5 }}
          style={{
            position: "absolute",
            bottom: "2rem",
            left: "50%",
            transform: "translateX(-50%)",
            zIndex: 1,
          }}
        >
          <motion.div
            animate={{ y: [0, 6, 0] }}
            transition={{ repeat: Infinity, duration: 2, ease: "easeInOut" }}
          >
            <ChevronDown size={22} color="oklch(0.38 0.01 250)" />
          </motion.div>
        </motion.div>
      </section>

      {/* ── STATS COUNTER BAR ───────────────────────────────── */}
      <section
        ref={statsRef}
        style={{
          borderTop: "1px solid oklch(0.20 0.01 250)",
          borderBottom: "1px solid oklch(0.20 0.01 250)",
          background: "oklch(0.15 0.01 250)",
          padding: "2.5rem clamp(1.5rem, 5vw, 4rem)",
        }}
      >
        <div
          style={{
            maxWidth: 1100,
            margin: "0 auto",
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
            gap: "2rem",
          }}
        >
          <StatCounter value={344}   label="Engines"   trigger={statsInView} />
          <StatCounter value={574}   label="API Routers" trigger={statsInView} />
          <StatCounter value={8910}  label="Tests Passing" trigger={statsInView} />
          <StatCounter value={296}   label="Frontend Pages" trigger={statsInView} />
          <StatCounter value={30}    label="Personas"   trigger={statsInView} />
          <StatCounter value={35}    label="$/month"    suffix="$" trigger={statsInView} />
        </div>
      </section>

      {/* ── FEATURES GRID ───────────────────────────────────── */}
      <section
        id="features"
        ref={featuresRef}
        style={{
          padding: "clamp(4rem, 8vw, 7rem) clamp(1.5rem, 5vw, 4rem)",
          maxWidth: 1200,
          margin: "0 auto",
        }}
      >
        {/* Section label */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={featuresInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
          style={{ textAlign: "center", marginBottom: "3rem" }}
        >
          <span
            style={{
              fontSize: "0.75rem",
              fontWeight: 600,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "oklch(0.65 0.15 195)",
              display: "block",
              marginBottom: "0.75rem",
            }}
          >
            Platform Capabilities
          </span>
          <h2
            style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 800,
              fontSize: "clamp(1.8rem, 4vw, 3rem)",
              letterSpacing: "-0.025em",
              color: "oklch(0.97 0.004 250)",
              margin: 0,
            }}
          >
            Ten disciplines. One platform.
          </h2>
          <p
            style={{
              marginTop: "0.75rem",
              fontSize: "1rem",
              color: "oklch(0.55 0.01 250)",
              maxWidth: 520,
              margin: "0.75rem auto 0",
            }}
          >
            Every security domain your team needs, deeply integrated — not duct-taped together.
          </p>
        </motion.div>

        {/* Grid */}
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate={featuresInView ? "visible" : "hidden"}
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(310px, 1fr))",
            gap: "1px",
            background: "oklch(0.20 0.01 250)",
            borderRadius: 16,
            overflow: "hidden",
            border: "1px solid oklch(0.20 0.01 250)",
          }}
        >
          {FEATURES.map(({ icon: Icon, title, sub, desc }) => (
            <motion.div
              key={title}
              variants={itemVariants}
              whileHover={{
                background: "oklch(0.19 0.018 250)",
                transition: { duration: 0.15 },
              }}
              style={{
                background: "oklch(0.155 0.01 250)",
                padding: "1.75rem",
                cursor: "default",
                transition: "background 0.15s",
              }}
            >
              <div
                style={{
                  width: 36,
                  height: 36,
                  borderRadius: 9,
                  background: "oklch(0.65 0.15 195 / 0.1)",
                  border: "1px solid oklch(0.65 0.15 195 / 0.2)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  marginBottom: "0.9rem",
                }}
              >
                <Icon size={17} color="oklch(0.65 0.15 195)" strokeWidth={2} />
              </div>
              <div
                style={{
                  fontFamily: "'Syne', sans-serif",
                  fontWeight: 700,
                  fontSize: "1rem",
                  color: "oklch(0.93 0.005 250)",
                  letterSpacing: "-0.01em",
                  marginBottom: "0.15rem",
                }}
              >
                {title}
              </div>
              <div
                style={{
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  letterSpacing: "0.06em",
                  textTransform: "uppercase",
                  color: "oklch(0.65 0.15 195)",
                  marginBottom: "0.6rem",
                }}
              >
                {sub}
              </div>
              <p
                style={{
                  fontSize: "0.875rem",
                  lineHeight: 1.6,
                  color: "oklch(0.55 0.008 250)",
                  margin: 0,
                }}
              >
                {desc}
              </p>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ── PRICING ─────────────────────────────────────────── */}
      <section
        id="pricing"
        ref={pricingRef}
        style={{
          padding: "clamp(4rem, 8vw, 7rem) clamp(1.5rem, 5vw, 4rem)",
          background: "oklch(0.115 0.01 250)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <RadialGlow cx="80%" cy="50%" color="oklch(0.65 0.15 195 / 0.05)" size={600} />

        <div style={{ maxWidth: 1000, margin: "0 auto", position: "relative", zIndex: 1 }}>
          {/* Section header */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={pricingInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            style={{ textAlign: "center", marginBottom: "3rem" }}
          >
            <span
              style={{
                fontSize: "0.75rem",
                fontWeight: 600,
                letterSpacing: "0.14em",
                textTransform: "uppercase",
                color: "oklch(0.65 0.15 195)",
                display: "block",
                marginBottom: "0.75rem",
              }}
            >
              Pricing
            </span>
            <h2
              style={{
                fontFamily: "'Syne', sans-serif",
                fontWeight: 800,
                fontSize: "clamp(1.8rem, 4vw, 3rem)",
                letterSpacing: "-0.025em",
                color: "oklch(0.97 0.004 250)",
                margin: "0 0 0.75rem",
              }}
            >
              $35/month vs. $500K/year.
            </h2>
            <p style={{ fontSize: "1rem", color: "oklch(0.55 0.01 250)", margin: 0 }}>
              The incumbents charge enterprise rents for incumbent-era tools. You shouldn't have to pay them.
            </p>
          </motion.div>

          {/* Comparison table */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={pricingInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
            style={{
              borderRadius: 14,
              overflow: "hidden",
              border: "1px solid oklch(0.22 0.01 250)",
            }}
          >
            {/* Table header */}
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "1fr 1fr 1fr",
                background: "oklch(0.18 0.012 250)",
                borderBottom: "1px solid oklch(0.22 0.01 250)",
                padding: "0.75rem 1.5rem",
              }}
            >
              {["Vendor", "Annual Cost", "Coverage"].map((h) => (
                <span
                  key={h}
                  style={{
                    fontSize: "0.72rem",
                    fontWeight: 600,
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    color: "oklch(0.5 0.01 250)",
                  }}
                >
                  {h}
                </span>
              ))}
            </div>

            {COMPETITORS.map(({ name, price, features, highlight }, i) => (
              <div
                key={name}
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr 1fr",
                  padding: "1rem 1.5rem",
                  alignItems: "center",
                  borderBottom: i < COMPETITORS.length - 1 ? "1px solid oklch(0.18 0.01 250)" : "none",
                  background: highlight
                    ? "oklch(0.65 0.15 195 / 0.07)"
                    : i % 2 === 0
                    ? "oklch(0.155 0.01 250)"
                    : "oklch(0.145 0.01 250)",
                }}
              >
                <span
                  style={{
                    fontFamily: highlight ? "'Syne', sans-serif" : "inherit",
                    fontWeight: highlight ? 800 : 500,
                    fontSize: highlight ? "1rem" : "0.9rem",
                    color: highlight ? "oklch(0.65 0.15 195)" : "oklch(0.7 0.008 250)",
                  }}
                >
                  {name}
                  {highlight && (
                    <span
                      style={{
                        marginLeft: "0.5rem",
                        fontSize: "0.65rem",
                        fontWeight: 700,
                        letterSpacing: "0.08em",
                        textTransform: "uppercase",
                        background: "oklch(0.65 0.15 195 / 0.15)",
                        border: "1px solid oklch(0.65 0.15 195 / 0.3)",
                        borderRadius: 9999,
                        padding: "0.1rem 0.45rem",
                        color: "oklch(0.65 0.15 195)",
                      }}
                    >
                      You
                    </span>
                  )}
                </span>
                <span
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "0.88rem",
                    fontWeight: highlight ? 700 : 400,
                    color: highlight ? "oklch(0.65 0.15 195)" : "oklch(0.55 0.01 250)",
                  }}
                >
                  {price}
                </span>
                <span
                  style={{
                    fontSize: "0.88rem",
                    color: highlight ? "oklch(0.75 0.01 250)" : "oklch(0.5 0.01 250)",
                    fontWeight: highlight ? 600 : 400,
                    display: "flex",
                    alignItems: "center",
                    gap: "0.35rem",
                  }}
                >
                  {highlight && (
                    <Check size={14} color="oklch(0.65 0.15 195)" strokeWidth={2.5} />
                  )}
                  {features}
                </span>
              </div>
            ))}
          </motion.div>

          {/* Pricing cards */}
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={pricingInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.6, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
              gap: "1rem",
              marginTop: "1.5rem",
            }}
          >
            {[
              {
                tier: "Starter",
                price: "$35",
                desc: "Teams up to 50 engineers",
                features: ["All 344 engines", "5 users", "Community support", "Self-hosted"],
                cta: "Start Free Trial",
                primary: false,
              },
              {
                tier: "Professional",
                price: "$60",
                desc: "Teams up to 500 engineers",
                features: ["All 344 engines", "25 users", "Priority support", "Self-hosted + SaaS"],
                cta: "Start Free Trial",
                primary: true,
              },
              {
                tier: "Enterprise",
                price: "Custom",
                desc: "Unlimited scale",
                features: ["All 344 engines", "Unlimited users", "SLA + dedicated CSM", "Air-gap / on-prem"],
                cta: "Contact Sales",
                primary: false,
              },
            ].map(({ tier, price, desc, features: fs, cta, primary }) => (
              <div
                key={tier}
                style={{
                  borderRadius: 12,
                  border: primary
                    ? "1px solid oklch(0.65 0.15 195 / 0.5)"
                    : "1px solid oklch(0.22 0.01 250)",
                  background: primary
                    ? "oklch(0.65 0.15 195 / 0.06)"
                    : "oklch(0.155 0.01 250)",
                  padding: "1.5rem",
                  display: "flex",
                  flexDirection: "column",
                  gap: "0.6rem",
                }}
              >
                <div
                  style={{
                    fontSize: "0.75rem",
                    fontWeight: 700,
                    letterSpacing: "0.1em",
                    textTransform: "uppercase",
                    color: primary ? "oklch(0.65 0.15 195)" : "oklch(0.55 0.01 250)",
                  }}
                >
                  {tier}
                </div>
                <div
                  style={{
                    fontFamily: "'Syne', sans-serif",
                    fontWeight: 800,
                    fontSize: "2rem",
                    letterSpacing: "-0.03em",
                    color: "oklch(0.95 0.005 250)",
                    lineHeight: 1,
                  }}
                >
                  {price}
                  {price !== "Custom" && (
                    <span
                      style={{
                        fontSize: "0.9rem",
                        fontWeight: 500,
                        color: "oklch(0.5 0.01 250)",
                        letterSpacing: 0,
                      }}
                    >
                      /mo
                    </span>
                  )}
                </div>
                <div style={{ fontSize: "0.83rem", color: "oklch(0.55 0.01 250)", marginBottom: "0.5rem" }}>
                  {desc}
                </div>
                {fs.map((f) => (
                  <div
                    key={f}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "0.5rem",
                      fontSize: "0.84rem",
                      color: "oklch(0.68 0.008 250)",
                    }}
                  >
                    <Check size={13} color="oklch(0.65 0.15 195)" strokeWidth={2.5} />
                    {f}
                  </div>
                ))}
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={() => navigate("/onboarding")}
                  style={{
                    marginTop: "0.75rem",
                    padding: "0.6rem 1rem",
                    borderRadius: 8,
                    fontWeight: 600,
                    fontSize: "0.875rem",
                    cursor: "pointer",
                    border: primary ? "none" : "1px solid oklch(0.28 0.01 250)",
                    background: primary ? "oklch(0.65 0.15 195)" : "oklch(0.19 0.012 250)",
                    color: primary ? "oklch(0.13 0.01 250)" : "oklch(0.8 0.005 250)",
                  }}
                >
                  {cta}
                </motion.button>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* ── TESTIMONIALS ────────────────────────────────────── */}
      <section
        ref={testimonialsRef}
        style={{
          padding: "clamp(4rem, 8vw, 7rem) clamp(1.5rem, 5vw, 4rem)",
          maxWidth: 1100,
          margin: "0 auto",
        }}
      >
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={testimonialsInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          style={{ textAlign: "center", marginBottom: "3rem" }}
        >
          <span
            style={{
              fontSize: "0.75rem",
              fontWeight: 600,
              letterSpacing: "0.14em",
              textTransform: "uppercase",
              color: "oklch(0.65 0.15 195)",
              display: "block",
              marginBottom: "0.75rem",
            }}
          >
            Social Proof
          </span>
          <h2
            style={{
              fontFamily: "'Syne', sans-serif",
              fontWeight: 800,
              fontSize: "clamp(1.8rem, 4vw, 3rem)",
              letterSpacing: "-0.025em",
              color: "oklch(0.97 0.004 250)",
              margin: 0,
            }}
          >
            Trusted by security teams
          </h2>
        </motion.div>

        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate={testimonialsInView ? "visible" : "hidden"}
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "1rem",
          }}
        >
          {TESTIMONIALS.map(({ quote, name, company }, i) => (
            <motion.div
              key={i}
              variants={itemVariants}
              style={{
                background: "oklch(0.165 0.012 250)",
                border: "1px solid oklch(0.22 0.01 250)",
                borderRadius: 12,
                padding: "1.5rem",
                display: "flex",
                flexDirection: "column",
                gap: "1rem",
              }}
            >
              {/* Quote mark */}
              <span
                style={{
                  fontFamily: "Georgia, serif",
                  fontSize: "2.5rem",
                  lineHeight: 1,
                  color: "oklch(0.65 0.15 195 / 0.4)",
                  marginTop: "-0.5rem",
                }}
              >
                "
              </span>
              <p
                style={{
                  fontSize: "0.9rem",
                  lineHeight: 1.65,
                  color: "oklch(0.68 0.008 250)",
                  margin: 0,
                  marginTop: "-1rem",
                }}
              >
                {quote}
              </p>
              <div style={{ marginTop: "auto" }}>
                <div
                  style={{
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    color: "oklch(0.8 0.005 250)",
                  }}
                >
                  {name}
                </div>
                <div style={{ fontSize: "0.78rem", color: "oklch(0.48 0.01 250)" }}>
                  {company}
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ── FINAL CTA ────────────────────────────────────────── */}
      <section
        style={{
          padding: "clamp(4rem, 8vw, 7rem) clamp(1.5rem, 5vw, 4rem)",
          background: "oklch(0.115 0.01 250)",
          borderTop: "1px solid oklch(0.20 0.01 250)",
          position: "relative",
          overflow: "hidden",
          textAlign: "center",
        }}
      >
        <RadialGlow cx="50%" cy="50%" color="oklch(0.65 0.15 195 / 0.08)" size={700} />
        <div style={{ position: "relative", zIndex: 1, maxWidth: 600, margin: "0 auto" }}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
          >
            <h2
              style={{
                fontFamily: "'Syne', sans-serif",
                fontWeight: 800,
                fontSize: "clamp(1.8rem, 4vw, 3rem)",
                letterSpacing: "-0.025em",
                color: "oklch(0.97 0.004 250)",
                margin: "0 0 1rem",
              }}
            >
              Your security stack costs too much.
            </h2>
            <p
              style={{
                fontSize: "1rem",
                color: "oklch(0.55 0.01 250)",
                lineHeight: 1.6,
                marginBottom: "2rem",
              }}
            >
              Deploy ALDECI in under 10 minutes. No vendor contracts, no per-seat licensing, no
              lock-in. 344 engines. 30 personas. $35/month.
            </p>
            <motion.button
              whileHover={{ scale: 1.04, y: -2 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => navigate("/onboarding")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.5rem",
                background: "oklch(0.65 0.15 195)",
                color: "oklch(0.13 0.01 250)",
                fontWeight: 700,
                fontSize: "1rem",
                padding: "0.8rem 2rem",
                borderRadius: 11,
                border: "none",
                cursor: "pointer",
                letterSpacing: "-0.01em",
              }}
            >
              Start Free Trial — No Credit Card
              <ArrowRight size={17} strokeWidth={2.5} />
            </motion.button>
          </motion.div>
        </div>
      </section>

      {/* ── FOOTER ──────────────────────────────────────────── */}
      <footer
        id="docs"
        style={{
          borderTop: "1px solid oklch(0.18 0.01 250)",
          padding: "2rem clamp(1.5rem, 5vw, 4rem)",
          background: "oklch(0.11 0.01 250)",
        }}
      >
        <div
          style={{
            maxWidth: 1100,
            margin: "0 auto",
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "1.5rem",
          }}
        >
          {/* Brand */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: 24,
                height: 24,
                borderRadius: 5,
                background: "oklch(0.65 0.15 195)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Shield size={13} color="oklch(0.13 0.01 250)" strokeWidth={2.5} />
            </div>
            <span
              style={{
                fontFamily: "'Syne', sans-serif",
                fontWeight: 800,
                fontSize: "0.9rem",
                color: "oklch(0.75 0.005 250)",
              }}
            >
              ALDECI
            </span>
          </div>

          {/* Links */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "1.5rem" }}>
            {[
              { label: "Platform", href: "/discover" },
              { label: "API Docs", href: "/developer" },
              { label: "Compliance", href: "/comply" },
              { label: "Security", href: "/discover" },
              { label: "GitHub", href: "https://github.com/DevOpsMadDog/Fixops" },
            ].map(({ label, href }) => (
              <a
                key={label}
                href={href}
                style={{
                  fontSize: "0.825rem",
                  color: "oklch(0.45 0.01 250)",
                  textDecoration: "none",
                  transition: "color 0.15s",
                }}
                onMouseEnter={(e) =>
                  ((e.target as HTMLElement).style.color = "oklch(0.7 0.008 250)")
                }
                onMouseLeave={(e) =>
                  ((e.target as HTMLElement).style.color = "oklch(0.45 0.01 250)")
                }
              >
                {label}
              </a>
            ))}
          </div>

          {/* Legal */}
          <div
            style={{
              fontSize: "0.78rem",
              color: "oklch(0.38 0.01 250)",
              display: "flex",
              gap: "1rem",
              flexWrap: "wrap",
            }}
          >
            <span>© 2026 ALDECI / DevOpsMadDog</span>
            <span style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
              <Globe size={11} /> Self-hosted. Your data stays yours.
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
