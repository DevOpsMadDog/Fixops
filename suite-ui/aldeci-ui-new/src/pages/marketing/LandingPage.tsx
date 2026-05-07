/**
 * marketing/LandingPage — ALdeci public marketing page
 * Route: /marketing (public, no auth)
 * Multica: #4143
 *
 * Sections (copy from docs/marketing/LANDING_COPY.md @ 489de607):
 *   Hero → Trust Strip → Problem (3 bullets) → Solution (3 pillars) →
 *   How It Works (3 steps) → Pricing (3 tiers) → Social Proof → CTA Bar → Footer
 */

import { useRef, useState } from "react";
import { motion, useInView } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Brain,
  Users,
  Check,
  ArrowRight,
  Lock,
  Zap,
  BarChart3,
  ChevronRight,
  Star,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";

// ── Fade-in-up wrapper ────────────────────────────────────────────────────────
function FadeUp({
  children,
  delay = 0,
  className,
}: {
  children: React.ReactNode;
  delay?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });
  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 28 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.55, delay, ease: [0.16, 1, 0.3, 1] }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

// ── Pricing tier data ─────────────────────────────────────────────────────────
const TIERS = [
  {
    name: "Starter",
    price: "$199",
    period: "/month",
    badge: null,
    description: "Best for startups and small teams learning CTEM.",
    features: [
      "1 organization",
      "Up to 100 assets",
      "All 8 built-in scanners",
      "Basic TrustGraph (10 feeds)",
      "Single-LLM consensus",
      "Community support (Discord)",
      "14-day free trial",
    ],
    cta: "Start free trial",
    variant: "outline" as const,
    highlight: false,
  },
  {
    name: "Pro",
    price: "$499",
    period: "/month",
    badge: "Most popular",
    description: "Best for mid-market DevSecOps and ASPM-ready teams.",
    features: [
      "5 organizations",
      "Unlimited assets",
      "Multi-LLM consensus (3+ models, 85% threshold)",
      "Full TrustGraph (28 feeds + 32 scanners)",
      "MPTE exploit verification",
      "AutoFix (confidence-based apply)",
      "Email support (24h response)",
    ],
    cta: "Start free trial",
    variant: "default" as const,
    highlight: true,
  },
  {
    name: "Enterprise",
    price: "$1,499",
    period: "/month",
    badge: null,
    description: "Best for enterprises and regulated industries.",
    features: [
      "Unlimited organizations & assets",
      "SSO + SAML 2.0",
      "MPTE full (19-phase pen-test)",
      "FAIL chaos engine",
      "Quantum-secure evidence (FIPS 204)",
      "On-premises deploy option",
      "Dedicated CSM · 99.9% SLA",
    ],
    cta: "Contact sales",
    variant: "outline" as const,
    highlight: false,
  },
] as const;

// ── Problem bullets ───────────────────────────────────────────────────────────
const PROBLEMS = [
  {
    icon: BarChart3,
    title: "$500K/year on tools that don't talk to each other",
    body: "You're paying for Snyk + Apiiro + Aikido + Wiz + Nessus — each with its own console, data format, and API. No unified view. No shared context. Your CISO briefs from five dashboards.",
  },
  {
    icon: Zap,
    title: "1,000+ findings per quarter. Your team can act on 5.",
    body: "Security scanners generate noise: 90% of findings are unpatchable, unfixable, or already mitigated. SOC analysts spend 60 days triaging. DevSecOps can't separate signal from noise.",
  },
  {
    icon: Lock,
    title: "Compliance audits eat 6 weeks of engineering time twice a year",
    body: "Every framework (SOC2, PCI-DSS, HIPAA, ISO 27001) demands evidence bundles. Manual export. Manual proof. Manual sign-off. No reproducibility.",
  },
] as const;

// ── Solution pillars ──────────────────────────────────────────────────────────
const PILLARS = [
  {
    icon: Shield,
    title: "Unified Data Plane",
    body: "TrustGraph aggregates 28 threat intelligence feeds + 32 scanner normalizers into a single knowledge graph. Snyk report? Wiz scan? Nessus asset? All normalized, deduplicated, and correlated in seconds. Works air-gapped.",
  },
  {
    icon: Brain,
    title: "AI Consensus, Not Guesswork",
    body: "Multi-LLM council (Claude, GPT, open models) votes on every vulnerability. 3+ LLMs. 85% majority threshold. No single-model hallucinations. Findings scored by exploitability — not just detected, but proven.",
  },
  {
    icon: Users,
    title: "30 Personas. One UI.",
    body: "CISO gets board-ready risk dashboards. SOC Analyst gets prioritized incidents. DevSecOps gets remediation lanes and PR generation. Auditor gets quantum-secure evidence bundles. Every persona, one login.",
  },
] as const;

// ── How it works steps ────────────────────────────────────────────────────────
const STEPS = [
  {
    num: "01",
    title: "Ingest",
    body: "All your scanners (Snyk, Burp, Nessus, SonarQube, ...) pipe findings into ALdeci. Zero rip-and-replace. Works day 1.",
  },
  {
    num: "02",
    title: "Decide",
    body: "Multi-LLM consensus + MPTE exploit verification + risk scoring. Top 5 findings bubble up. 90% noise filtered.",
  },
  {
    num: "03",
    title: "Fix",
    body: "AI-powered remediation: PR generation, auto-apply patches with confidence scores, compliance proof generated automatically.",
  },
] as const;

// ── Main component ────────────────────────────────────────────────────────────
export default function LandingPage() {
  usePageTitle("ALdeci — Replace Your $500K Security Stack");
  const navigate = useNavigate();
  const [email, setEmail] = useState("");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 antialiased">
      {/* ── Nav ── */}
      <header className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <span className="text-lg font-bold tracking-tight text-indigo-400">
            ALdeci
          </span>
          <nav className="hidden items-center gap-6 text-sm text-slate-400 md:flex">
            <a href="#problem" className="hover:text-slate-50 transition-colors">Problem</a>
            <a href="#solution" className="hover:text-slate-50 transition-colors">Solution</a>
            <a href="#pricing" className="hover:text-slate-50 transition-colors">Pricing</a>
            <a href="/docs/poc" className="hover:text-slate-50 transition-colors">Docs</a>
          </nav>
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={() => navigate("/login")}>
              Sign in
            </Button>
            <Button size="sm" onClick={() => navigate("/onboarding")}>
              Start free POC
            </Button>
          </div>
        </div>
      </header>

      {/* ── Hero ── */}
      <section className="relative overflow-hidden px-6 pb-24 pt-20 text-center">
        {/* radial glow */}
        <div
          aria-hidden
          className="pointer-events-none absolute inset-0 flex items-center justify-center"
        >
          <div className="h-[600px] w-[600px] rounded-full bg-indigo-600/10 blur-3xl" />
        </div>

        <FadeUp>
          <Badge
            variant="outline"
            className="mb-6 border-indigo-500/40 bg-indigo-500/10 text-indigo-300"
          >
            ASPM + CTEM + CSPM — unified
          </Badge>
        </FadeUp>

        <FadeUp delay={0.05}>
          <h1 className="mx-auto max-w-3xl text-4xl font-extrabold leading-tight tracking-tight text-slate-50 md:text-6xl">
            Replace your{" "}
            <span className="bg-gradient-to-r from-indigo-400 to-violet-400 bg-clip-text text-transparent">
              $500K security stack
            </span>{" "}
            with a single self-hosted platform
          </h1>
        </FadeUp>

        <FadeUp delay={0.1}>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-400">
            ASPM + CTEM + CSPM unified. AI-native. 30 personas covered.{" "}
            <span className="text-slate-300 font-medium">
              Self-hosted — your data never leaves.
            </span>
          </p>
        </FadeUp>

        <FadeUp delay={0.15} className="mt-8 flex flex-wrap items-center justify-center gap-4">
          <Button size="xl" onClick={() => navigate("/onboarding")}>
            Start free POC <ArrowRight className="ml-1 h-4 w-4" />
          </Button>
          <Button size="xl" variant="outline" onClick={() => navigate("/tour")}>
            View live demo
          </Button>
        </FadeUp>

        {/* Trust strip */}
        <FadeUp delay={0.2}>
          <p className="mt-10 text-sm text-slate-500">
            Self-hosted&nbsp;✓ &nbsp;·&nbsp; GDPR-ready&nbsp;✓ &nbsp;·&nbsp;
            30+ feed integrations&nbsp;✓ &nbsp;·&nbsp; 25+ scanner adapters&nbsp;✓
          </p>
        </FadeUp>
      </section>

      {/* ── Problem ── */}
      <section id="problem" className="bg-slate-900 px-6 py-20">
        <div className="mx-auto max-w-6xl">
          <FadeUp>
            <h2 className="mb-3 text-center text-3xl font-bold text-slate-50">
              The Security Tool Sprawl Killing Your Team
            </h2>
            <p className="mb-12 text-center text-slate-400">
              Three problems. One root cause: fragmented tools.
            </p>
          </FadeUp>
          <div className="grid gap-6 md:grid-cols-3">
            {PROBLEMS.map(({ icon: Icon, title, body }, i) => (
              <FadeUp key={title} delay={i * 0.08}>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 h-full">
                  <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-red-500/10">
                    <Icon className="h-5 w-5 text-red-400" />
                  </div>
                  <h3 className="mb-2 font-semibold text-slate-100">{title}</h3>
                  <p className="text-sm leading-relaxed text-slate-400">{body}</p>
                </div>
              </FadeUp>
            ))}
          </div>
        </div>
      </section>

      {/* ── Solution ── */}
      <section id="solution" className="px-6 py-20">
        <div className="mx-auto max-w-6xl">
          <FadeUp>
            <h2 className="mb-3 text-center text-3xl font-bold text-slate-50">
              Three Pillars. One Platform.
            </h2>
            <p className="mb-12 text-center text-slate-400">
              ALdeci replaces the stack — not just wraps it.
            </p>
          </FadeUp>
          <div className="grid gap-6 md:grid-cols-3">
            {PILLARS.map(({ icon: Icon, title, body }, i) => (
              <FadeUp key={title} delay={i * 0.08}>
                <div className="rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-6 h-full">
                  <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-500/15">
                    <Icon className="h-5 w-5 text-indigo-400" />
                  </div>
                  <h3 className="mb-2 font-semibold text-slate-100">{title}</h3>
                  <p className="text-sm leading-relaxed text-slate-400">{body}</p>
                </div>
              </FadeUp>
            ))}
          </div>
        </div>
      </section>

      {/* ── How It Works ── */}
      <section className="bg-slate-900 px-6 py-20">
        <div className="mx-auto max-w-4xl">
          <FadeUp>
            <h2 className="mb-12 text-center text-3xl font-bold text-slate-50">
              Working in 3 steps
            </h2>
          </FadeUp>
          <div className="grid gap-8 md:grid-cols-3">
            {STEPS.map(({ num, title, body }, i) => (
              <FadeUp key={num} delay={i * 0.08}>
                <div className="flex flex-col items-start">
                  <span className="mb-3 font-mono text-4xl font-black text-indigo-500/30">
                    {num}
                  </span>
                  <h3 className="mb-2 text-lg font-semibold text-slate-100">{title}</h3>
                  <p className="text-sm leading-relaxed text-slate-400">{body}</p>
                </div>
              </FadeUp>
            ))}
          </div>
        </div>
      </section>

      {/* ── Pricing ── */}
      <section id="pricing" className="px-6 py-20">
        <div className="mx-auto max-w-6xl">
          <FadeUp>
            <h2 className="mb-2 text-center text-3xl font-bold text-slate-50">
              Transparent pricing. No surprises.
            </h2>
            <p className="mb-2 text-center text-slate-400">
              No seat licenses. No per-scan overages. Annual billing saves 2 months.
            </p>
            <p className="mb-12 text-center text-sm text-slate-500">
              14-day free trial · No credit card · Cancel anytime
            </p>
          </FadeUp>

          <div className="grid gap-6 md:grid-cols-3">
            {TIERS.map((tier, i) => (
              <FadeUp key={tier.name} delay={i * 0.08}>
                <div
                  className={cn(
                    "relative flex flex-col rounded-2xl border p-8 h-full",
                    tier.highlight
                      ? "border-indigo-500 bg-indigo-500/5 shadow-lg shadow-indigo-500/10"
                      : "border-slate-800 bg-slate-950/60"
                  )}
                >
                  {tier.badge && (
                    <Badge className="absolute -top-3 left-1/2 -translate-x-1/2 bg-indigo-500 text-white text-xs">
                      {tier.badge}
                    </Badge>
                  )}
                  <div className="mb-6">
                    <h3 className="mb-1 text-xl font-bold text-slate-50">
                      {tier.name}
                    </h3>
                    <div className="flex items-end gap-1">
                      <span className="text-4xl font-black text-slate-50">
                        {tier.price}
                      </span>
                      <span className="mb-1 text-slate-400 text-sm">{tier.period}</span>
                    </div>
                    <p className="mt-2 text-sm text-slate-400">{tier.description}</p>
                  </div>

                  <ul className="mb-8 flex flex-col gap-3 flex-1">
                    {tier.features.map((f) => (
                      <li key={f} className="flex items-start gap-2 text-sm text-slate-300">
                        <Check className="mt-0.5 h-4 w-4 shrink-0 text-green-400" />
                        {f}
                      </li>
                    ))}
                  </ul>

                  <Button
                    variant={tier.variant}
                    className="w-full"
                    onClick={() =>
                      tier.name === "Enterprise"
                        ? (window.location.href = "mailto:hello@aldeci.com")
                        : navigate("/onboarding")
                    }
                  >
                    {tier.cta}
                    <ChevronRight className="ml-1 h-4 w-4" />
                  </Button>
                </div>
              </FadeUp>
            ))}
          </div>

          {/* All-tiers note */}
          <FadeUp delay={0.25}>
            <p className="mt-8 text-center text-sm text-slate-500">
              All tiers: self-hosted (your data, your VPC) · Zero vendor lock-in · Annual billing: 2 months free
            </p>
          </FadeUp>
        </div>
      </section>

      {/* ── Social Proof ── */}
      <section className="bg-slate-900 px-6 py-16">
        <div className="mx-auto max-w-3xl text-center">
          <FadeUp>
            <div className="mb-4 flex justify-center gap-1">
              {[...Array(5)].map((_, i) => (
                <Star key={i} className="h-5 w-5 fill-amber-400 text-amber-400" />
              ))}
            </div>
            <p className="mb-6 text-lg text-slate-300 italic">
              "Used by [LOGOS PLACEHOLDER] — we're looking for 3 design partners to beta test."
            </p>
            <Badge variant="outline" className="border-amber-500/40 bg-amber-500/10 text-amber-300">
              Join the pilot — limited spots
            </Badge>
          </FadeUp>
        </div>
      </section>

      {/* ── CTA Bar ── */}
      <section className="px-6 py-20">
        <div className="mx-auto max-w-2xl text-center">
          <FadeUp>
            <h2 className="mb-3 text-3xl font-bold text-slate-50">
              Get a working POC in 1 day.
            </h2>
            <p className="mb-8 text-slate-400">
              No credit card. No setup hassle.
            </p>
          </FadeUp>
          <FadeUp delay={0.05}>
            <form
              className="flex flex-col items-center gap-3 sm:flex-row sm:justify-center"
              onSubmit={(e) => {
                e.preventDefault();
                navigate(`/onboarding${email ? `?email=${encodeURIComponent(email)}` : ""}`);
              }}
            >
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="h-10 w-full max-w-xs rounded-lg border border-slate-700 bg-slate-800 px-4 text-sm text-slate-50 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 sm:w-72"
                aria-label="Work email"
              />
              <Button type="submit" size="default">
                Start POC <ArrowRight className="ml-1 h-4 w-4" />
              </Button>
            </form>
            <div className="mt-4 flex justify-center gap-6 text-sm text-slate-500">
              <button onClick={() => navigate("/tour")} className="hover:text-slate-300 transition-colors underline underline-offset-2">
                View live demo
              </button>
              <a href="/docs/poc" className="hover:text-slate-300 transition-colors underline underline-offset-2">
                Read the docs
              </a>
              <a href="/security" className="hover:text-slate-300 transition-colors underline underline-offset-2">
                Security &amp; compliance
              </a>
            </div>
          </FadeUp>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-slate-800 bg-slate-900 px-6 py-10">
        <div className="mx-auto max-w-6xl">
          <div className="mb-8 flex flex-wrap justify-center gap-x-8 gap-y-3 text-sm text-slate-400">
            <a href="/docs/tos" className="hover:text-slate-50 transition-colors">Terms of Service</a>
            <a href="/docs/privacy" className="hover:text-slate-50 transition-colors">Privacy Policy</a>
            <a href="/docs/dpa" className="hover:text-slate-50 transition-colors">DPA</a>
            <a href="/docs/poc" className="hover:text-slate-50 transition-colors">Documentation</a>
            <a href="/security" className="hover:text-slate-50 transition-colors">Security &amp; Compliance</a>
            <a href="/status" className="hover:text-slate-50 transition-colors">Status</a>
            <a
              href="https://github.com/DevOpsMadDog/Fixops"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-slate-50 transition-colors"
            >
              GitHub
            </a>
            <a href="mailto:hello@aldeci.com" className="hover:text-slate-50 transition-colors">
              hello@aldeci.com
            </a>
          </div>
          <p className="text-center text-xs text-slate-600">
            &copy; {new Date().getFullYear()} ALdeci. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
