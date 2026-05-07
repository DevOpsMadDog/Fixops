/**
 * PricingPage — Public landing page pricing tier cards
 * Route: /pricing (public, no auth required)
 * Multica: #4116
 *
 * 3-tier pricing: Starter $199, Pro $499, Enterprise $1499
 * Click → opens UpgradeDialog modal
 * Design: Apple HIG + shadcn/ui, dark mode first
 */

import { useState } from "react";
import { Check, Zap, Shield, Building2, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { UpgradeDialog } from "@/components/billing/UpgradeDialog";
import { cn } from "@/lib/utils";

interface PricingTier {
  id: "starter" | "pro" | "enterprise";
  name: string;
  price: number;
  icon: React.ElementType;
  color: string;
  borderColor: string;
  badgeText: string;
  description: string;
  features: string[];
  cta: string;
  popular?: boolean;
}

const PRICING_TIERS: PricingTier[] = [
  {
    id: "starter",
    name: "Starter",
    price: 199,
    icon: Zap,
    color: "text-zinc-400",
    borderColor: "border-zinc-600/40",
    badgeText: "For startups",
    description: "Perfect for small teams learning CTEM",
    features: [
      "1 organization",
      "Up to 100 assets",
      "All 8 built-in scanners",
      "Basic TrustGraph (10 feeds)",
      "Single-LLM consensus",
      "Community support (Discord)",
      "30-day evidence retention",
    ],
    cta: "Start free POC",
  },
  {
    id: "pro",
    name: "Pro",
    price: 499,
    icon: Shield,
    color: "text-blue-400",
    borderColor: "border-blue-500/40",
    badgeText: "Most popular",
    description: "For mid-market DevSecOps teams",
    features: [
      "5 organizations",
      "Unlimited assets",
      "Multi-LLM consensus (3+ models)",
      "Full TrustGraph (28 feeds + 32 scanners)",
      "MPTE exploit verification (basic)",
      "AutoFix with confidence scoring",
      "90-day evidence retention",
      "Email support (24h response)",
    ],
    cta: "Start free POC",
    popular: true,
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: 1499,
    icon: Building2,
    color: "text-amber-400",
    borderColor: "border-amber-500/40",
    badgeText: "For enterprises",
    description: "Unlimited scale + compliance",
    features: [
      "Unlimited organizations",
      "Unlimited assets",
      "Everything in Pro",
      "MPTE full (19-phase pen-test)",
      "FAIL chaos engine",
      "Quantum-safe evidence (FIPS 204)",
      "Air-gapped deployment option",
      "Multi-tenant isolation",
      "SSO + SAML 2.0",
      "Dedicated CSM",
      "SLA: 99.9% uptime",
    ],
    cta: "Contact sales",
  },
];

const COMMON_FEATURES = [
  "Self-hosted (your data never leaves)",
  "Zero vendor lock-in",
  "Annual billing: 2 months free",
  "14-day free trial (no credit card)",
  "Cancel anytime",
];

export default function PricingPage() {
  const [upgradeOpen, setUpgradeOpen] = useState(false);
  const [selectedTier, setSelectedTier] = useState<"starter" | "pro" | "enterprise" | null>(null);

  const handleUpgrade = (tierId: "starter" | "pro" | "enterprise") => {
    setSelectedTier(tierId);
    setUpgradeOpen(true);
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950">
      {/* Header */}
      <div className="mx-auto max-w-6xl px-6 py-20 sm:px-8 lg:px-12">
        <div className="text-center">
          <h1 className="text-4xl font-bold tracking-tight text-slate-50 sm:text-5xl lg:text-6xl">
            Simple, transparent pricing
          </h1>
          <p className="mt-6 text-lg text-slate-400">
            Replace your $500K security stack with ALdeci. Pay for what you use, cancel anytime.
          </p>
        </div>

        {/* Toggle: Monthly / Annual */}
        <div className="mt-12 flex justify-center items-center gap-4">
          <span className="text-sm text-slate-400">Monthly</span>
          <div className="flex h-8 rounded-full border border-slate-700 bg-slate-800/50 p-1">
            <button className="flex-1 rounded-full bg-slate-700 px-4 py-1 text-xs font-semibold text-slate-50 transition-all">
              Monthly
            </button>
            <button className="flex-1 rounded-full px-4 py-1 text-xs font-semibold text-slate-400 transition-all hover:text-slate-300">
              Annual (Save 17%)
            </button>
          </div>
          <span className="text-xs text-green-400 font-semibold">2 months free</span>
        </div>

        {/* Pricing Cards */}
        <div className="mt-16 grid gap-8 lg:grid-cols-3">
          {PRICING_TIERS.map((tier) => {
            const Icon = tier.icon;
            return (
              <div
                key={tier.id}
                className={cn(
                  "relative flex flex-col rounded-2xl border transition-all duration-300",
                  "hover:shadow-2xl hover:shadow-slate-900/50",
                  tier.borderColor,
                  tier.popular
                    ? "bg-gradient-to-b from-blue-500/5 to-blue-500/0 ring-1 ring-blue-500/30 lg:scale-105"
                    : "bg-slate-800/30 backdrop-blur-sm"
                )}
              >
                {/* Badge */}
                {tier.popular && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full border border-blue-500/30 bg-gradient-to-r from-blue-500/20 to-blue-600/10 px-3 py-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-blue-400">
                      {tier.badgeText}
                    </span>
                  </div>
                )}

                {!tier.popular && (
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 px-6 pt-6">
                    {tier.badgeText}
                  </div>
                )}

                {/* Header */}
                <div className={cn("px-6", tier.popular ? "pt-8" : "pt-6")}>
                  <div className="flex items-center gap-3 mb-3">
                    <div
                      className={cn(
                        "flex h-8 w-8 items-center justify-center rounded-lg border",
                        tier.borderColor,
                        "bg-slate-800/40"
                      )}
                    >
                      <Icon className={cn("h-4 w-4", tier.color)} />
                    </div>
                    <h3 className="text-xl font-bold text-slate-50">{tier.name}</h3>
                  </div>
                  <p className="text-sm text-slate-400">{tier.description}</p>
                </div>

                {/* Price */}
                <div className="px-6 py-6">
                  <div className="flex items-baseline gap-1">
                    <span className="text-5xl font-bold text-slate-50">${tier.price}</span>
                    <span className="text-sm font-medium text-slate-500">/month</span>
                  </div>
                  <p className="mt-2 text-xs text-slate-500">
                    Billed monthly • Annual: 2 months free
                  </p>
                </div>

                {/* CTA */}
                <div className="px-6 pb-6">
                  <Button
                    onClick={() => handleUpgrade(tier.id)}
                    className={cn(
                      "w-full group transition-all duration-200",
                      tier.popular
                        ? "bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-500 hover:to-blue-600 text-white"
                        : "bg-slate-700 hover:bg-slate-600 text-slate-50 border border-slate-600"
                    )}
                  >
                    {tier.cta}
                    <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" />
                  </Button>
                </div>

                {/* Features */}
                <div className="flex-1 border-t border-slate-700/50 px-6 py-6">
                  <div className="space-y-4">
                    {tier.features.map((feature) => (
                      <div key={feature} className="flex items-start gap-3">
                        <Check className="h-5 w-5 shrink-0 text-green-400 mt-0.5" />
                        <span className="text-sm text-slate-300">{feature}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Common Features */}
        <div className="mt-20 rounded-2xl border border-slate-700/50 bg-slate-800/30 p-8">
          <h3 className="text-center text-lg font-semibold text-slate-50 mb-8">
            Included in all plans
          </h3>
          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-5">
            {COMMON_FEATURES.map((feature) => (
              <div key={feature} className="flex items-start gap-3">
                <Check className="h-5 w-5 shrink-0 text-green-400 mt-0.5" />
                <span className="text-sm text-slate-300">{feature}</span>
              </div>
            ))}
          </div>
        </div>

        {/* FAQ */}
        <div className="mt-20 max-w-3xl mx-auto">
          <h2 className="text-3xl font-bold text-slate-50 text-center mb-12">
            Frequently asked questions
          </h2>
          <div className="space-y-6">
            {[
              {
                q: "Do you offer a free trial?",
                a: "Yes! All plans include a 14-day free trial with no credit card required. Start a POC and see ALdeci in action.",
              },
              {
                q: "Can I change plans later?",
                a: "Absolutely. Upgrade or downgrade anytime. If you downgrade mid-cycle, we'll prorate the difference.",
              },
              {
                q: "What about self-hosted?",
                a: "Self-hosted deployment is available on all plans. Your data never leaves your VPC. GDPR-ready out of the box.",
              },
              {
                q: "Do you charge per scanner or asset?",
                a: "No hidden fees. We charge per organization + tier, not per scan or asset. Unlimited assets on Pro/Enterprise.",
              },
              {
                q: "Is there an annual discount?",
                a: "Yes! Annual billing gives you 2 months free. Pro ($5,988/yr) and Enterprise ($17,988/yr) are the best values.",
              },
            ].map((item, i) => (
              <div key={i} className="rounded-lg border border-slate-700/50 bg-slate-800/20 p-6">
                <h4 className="font-semibold text-slate-50 mb-2">{item.q}</h4>
                <p className="text-sm text-slate-400">{item.a}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom CTA */}
        <div className="mt-20 rounded-2xl border border-slate-700/50 bg-gradient-to-r from-slate-800/50 to-slate-900/50 p-12 text-center">
          <h2 className="text-2xl font-bold text-slate-50 mb-4">
            Get a working POC in 1 day
          </h2>
          <p className="text-slate-400 mb-8 max-w-2xl mx-auto">
            No credit card. No setup hassle. See how ALdeci can replace your entire security stack.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Button
              onClick={() => handleUpgrade("pro")}
              className="bg-blue-600 hover:bg-blue-700 text-white"
            >
              Start free POC
            </Button>
            <Button variant="outline" className="border-slate-600 hover:bg-slate-800">
              View live demo
            </Button>
          </div>
          <p className="text-xs text-slate-500 mt-6">
            All plans include a 14-day money-back guarantee. Cancel anytime.
          </p>
        </div>
      </div>

      {/* Upgrade Dialog */}
      <UpgradeDialog
        open={upgradeOpen}
        onOpenChange={setUpgradeOpen}
        currentTier={selectedTier || "starter"}
      />
    </div>
  );
}
