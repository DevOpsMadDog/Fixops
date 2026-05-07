import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { X, Zap, Shield, Building2, Check } from "lucide-react";
import { billingApi, type BillingTier } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// ── Tier card definitions ──────────────────────────────────────────────────

interface TierDef {
  id: BillingTier;
  name: string;
  price: number;
  icon: React.ElementType;
  color: string;
  borderColor: string;
  badgeClass: string;
  features: string[];
}

const TIERS: TierDef[] = [
  {
    id: "starter",
    name: "Starter",
    price: 199,
    icon: Zap,
    color: "text-zinc-400",
    borderColor: "border-zinc-600/40",
    badgeClass: "bg-zinc-700/50 text-zinc-300 border-zinc-600/40",
    features: [
      "5 repositories",
      "SAST + Secrets scanning",
      "1 compliance framework",
      "Community support",
      "30-day evidence retention",
    ],
  },
  {
    id: "pro",
    name: "Pro",
    price: 499,
    icon: Shield,
    color: "text-blue-400",
    borderColor: "border-blue-500/40",
    badgeClass: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    features: [
      "Unlimited repositories",
      "All 8 native scanners",
      "3 compliance frameworks",
      "MPTE offensive validation",
      "90-day evidence retention",
      "Priority support",
    ],
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: 1499,
    icon: Building2,
    color: "text-amber-400",
    borderColor: "border-amber-500/40",
    badgeClass: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    features: [
      "Everything in Pro",
      "Air-gapped deployment",
      "All 7 compliance frameworks",
      "Multi-tenant isolation",
      "Unlimited evidence retention",
      "Quantum-safe signatures",
      "Dedicated CSM",
    ],
  },
];

// ── Component ──────────────────────────────────────────────────────────────

interface UpgradeDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentTier: BillingTier;
}

export function UpgradeDialog({ open, onOpenChange, currentTier }: UpgradeDialogProps) {
  const [selectedTier, setSelectedTier] = useState<BillingTier | null>(null);
  const [error, setError] = useState<string | null>(null);

  const upgradeMutation = useMutation({
    mutationFn: (target: BillingTier) => billingApi.upgrade(target),
    onSuccess: (res) => {
      const url = res.data?.checkout_url;
      if (url) window.open(url, "_blank");
      onOpenChange(false);
    },
    onError: () => {
      setError("Failed to start checkout. Please try again.");
    },
  });

  const handleUpgrade = (tier: BillingTier) => {
    setError(null);
    setSelectedTier(tier);
    upgradeMutation.mutate(tier);
  };

  const isDowngrade = (tier: BillingTier) => {
    const order: BillingTier[] = ["starter", "pro", "enterprise"];
    return order.indexOf(tier) <= order.indexOf(currentTier);
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-full max-w-3xl -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-border bg-card p-6 shadow-2xl data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95">
          {/* Header */}
          <div className="flex items-start justify-between mb-6">
            <div>
              <Dialog.Title className="text-lg font-semibold text-foreground">
                Upgrade Your Plan
              </Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-muted-foreground">
                Unlock more scanners, frameworks, and enterprise features.
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <button className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors">
                <X className="h-4 w-4" />
              </button>
            </Dialog.Close>
          </div>

          {/* Tier cards */}
          <div className="grid grid-cols-3 gap-4">
            {TIERS.map((tier) => {
              const isCurrent = tier.id === currentTier;
              const downgrade = isDowngrade(tier.id) && !isCurrent;
              const isLoading = upgradeMutation.isPending && selectedTier === tier.id;

              return (
                <div
                  key={tier.id}
                  className={cn(
                    "relative flex flex-col rounded-xl border p-4 transition-all",
                    tier.borderColor,
                    isCurrent
                      ? "bg-accent/30 ring-1 ring-inset ring-cyan-500/30"
                      : "bg-background/60 hover:bg-accent/20"
                  )}
                >
                  {isCurrent && (
                    <span className="absolute -top-2.5 left-1/2 -translate-x-1/2 rounded-full border border-cyan-500/30 bg-cyan-500/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-400">
                      Current
                    </span>
                  )}

                  {/* Tier header */}
                  <div className="flex items-center gap-2 mb-3">
                    <div className={cn("flex h-7 w-7 items-center justify-center rounded-lg border", tier.borderColor, "bg-background/40")}>
                      <tier.icon className={cn("h-3.5 w-3.5", tier.color)} />
                    </div>
                    <div>
                      <div className="text-sm font-semibold text-foreground">{tier.name}</div>
                      <Badge className={cn("text-[9px] font-bold uppercase tracking-wider border", tier.badgeClass)}>
                        {tier.name}
                      </Badge>
                    </div>
                  </div>

                  {/* Price */}
                  <div className="mb-4">
                    <span className="text-2xl font-bold text-foreground">${tier.price}</span>
                    <span className="text-xs text-muted-foreground">/mo</span>
                  </div>

                  {/* Features */}
                  <ul className="flex-1 space-y-1.5 mb-4">
                    {tier.features.map((f) => (
                      <li key={f} className="flex items-start gap-1.5 text-[11px] text-muted-foreground">
                        <Check className="mt-0.5 h-3 w-3 shrink-0 text-green-400" />
                        {f}
                      </li>
                    ))}
                  </ul>

                  {/* CTA */}
                  <Button
                    size="sm"
                    disabled={isCurrent || downgrade || upgradeMutation.isPending}
                    onClick={() => handleUpgrade(tier.id)}
                    className={cn(
                      "w-full text-xs font-semibold",
                      tier.id === "enterprise"
                        ? "bg-amber-500/20 text-amber-400 border border-amber-500/30 hover:bg-amber-500/30"
                        : tier.id === "pro"
                        ? "bg-blue-500/20 text-blue-400 border border-blue-500/30 hover:bg-blue-500/30"
                        : ""
                    )}
                    variant={isCurrent || downgrade ? "outline" : "default"}
                  >
                    {isLoading
                      ? "Redirecting..."
                      : isCurrent
                      ? "Current plan"
                      : downgrade
                      ? "Downgrade"
                      : `Upgrade to ${tier.name}`}
                  </Button>
                </div>
              );
            })}
          </div>

          {error && (
            <p className="mt-4 text-xs text-destructive text-center">{error}</p>
          )}

          <p className="mt-4 text-center text-[10px] text-muted-foreground/60">
            All plans include a 14-day money-back guarantee. Billing is monthly, cancel anytime.
          </p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
