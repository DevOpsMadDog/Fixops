/**
 * FirstLoginWizard — onboarding bug fix 2026-04-27.
 *
 * Surfaced by the 4-app non-tech customer playbook (commit 682a7437): a
 * freshly installed admin lands on the empty Command hero with no prompts
 * and assumes ALDECI is broken. This modal fires on first admin login,
 * walks them through 3 steps (Create Org → Connect SCM → Trigger Sync),
 * is dismissible, and tracks completion via a real backend SQLite store
 * at /api/v1/admin/wizard-state — NOT localStorage. localStorage-only
 * tracking would (a) regress on a different browser, (b) regress on a
 * cleared profile, and (c) violate the no-mocks rule.
 *
 * State machine
 * -------------
 *   GET  /api/v1/admin/wizard-state         on mount
 *     -> if completed=true → render nothing
 *     -> else open the modal at completed_steps.length-th step
 *   POST /api/v1/admin/wizard-state         when user clicks Next
 *     body: {step}
 *   POST /api/v1/admin/wizard-state         when user clicks Finish
 *     body: {step, completed:true}
 *
 * The component renders nothing while loading state so the user never sees
 * a flash-of-modal that immediately closes.
 */

import { useEffect, useState } from "react";
import { Building2, GitBranch, PlayCircle, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface WizardState {
  completed: boolean;
  first_seen_at: string | null;
  completed_at: string | null;
  completed_steps: string[];
}

interface WizardStep {
  key: string;
  title: string;
  description: string;
  cta: string;
  ctaHref: string;
  icon: typeof Building2;
}

// ─────────────────────────────────────────────────────────────────────────────
// Steps — the 3-step CTEM onboarding spine. The hrefs are deep links into
// the existing Admin pages so the modal hands off to real screens (no inline
// form duplication, no risk of state drift).
// ─────────────────────────────────────────────────────────────────────────────

const STEPS: WizardStep[] = [
  {
    key: "create_org",
    title: "Step 1 — Create your organisation",
    description:
      "Every scan, finding, and policy in ALDECI is scoped to an org. " +
      "Open Admin → Organizations and add your first org to enable everything else.",
    cta: "Open Admin → Organizations",
    ctaHref: "/admin/organizations",
    icon: Building2,
  },
  {
    key: "connect_scm",
    title: "Step 2 — Connect a source-control system",
    description:
      "Plug in GitHub, GitLab, or Bitbucket so ALDECI can pull repositories " +
      "and run scanners. You can add more connectors later from Admin → Integrations.",
    cta: "Open Admin → Integrations",
    ctaHref: "/admin/integrations",
    icon: GitBranch,
  },
  {
    key: "trigger_sync",
    title: "Step 3 — Trigger your first sync",
    description:
      "Kick off the Brain Pipeline against an enrolled repo. Within a few " +
      "minutes you will see findings populate the Issues dashboard automatically.",
    cta: "Open Pipeline runner",
    ctaHref: "/pipeline",
    icon: PlayCircle,
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// API helpers — keep them local so this component is drop-in everywhere.
// ─────────────────────────────────────────────────────────────────────────────

async function fetchWizardState(): Promise<WizardState | null> {
  try {
    const res = await fetch(buildApiUrl("/api/v1/admin/wizard-state"), {
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
    });
    if (!res.ok) return null;
    return (await res.json()) as WizardState;
  } catch (err) {
    // Don't block the page if the backend is mid-restart — just skip the
    // wizard for this session and try again next mount.
    console.warn("[FirstLoginWizard] wizard-state fetch failed:", err);
    return null;
  }
}

async function postWizardState(
  step: string,
  completed = false,
): Promise<WizardState | null> {
  try {
    const res = await fetch(buildApiUrl("/api/v1/admin/wizard-state"), {
      method: "POST",
      headers: {
        "X-API-Key": getStoredAuthToken(),
        "X-Org-ID": getStoredOrgId(),
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ step, completed }),
    });
    if (!res.ok) return null;
    return (await res.json()) as WizardState;
  } catch (err) {
    console.warn("[FirstLoginWizard] wizard-state POST failed:", err);
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function FirstLoginWizard() {
  const [state, setState] = useState<WizardState | null>(null);
  const [open, setOpen] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [busy, setBusy] = useState(false);

  // Fetch state on mount — this is the deterministic first-login signal.
  useEffect(() => {
    let alive = true;
    fetchWizardState().then((s) => {
      if (!alive) return;
      setState(s);
      if (s && !s.completed) {
        // Resume at the first step the user hasn't completed yet so they
        // can refresh the page mid-wizard without losing progress.
        const resumeIdx = Math.min(s.completed_steps.length, STEPS.length - 1);
        setStepIdx(resumeIdx);
        setOpen(true);
      }
    });
    return () => {
      alive = false;
    };
  }, []);

  if (!state || state.completed) {
    // Render nothing if state hasn't loaded yet OR the wizard is already
    // done. No flash, no skeleton — invisible until ready.
    return null;
  }

  const step = STEPS[stepIdx];
  const StepIcon = step.icon;
  const isLast = stepIdx === STEPS.length - 1;

  const handleNext = async () => {
    setBusy(true);
    const updated = await postWizardState(step.key, isLast);
    setBusy(false);
    if (updated) setState(updated);
    if (isLast) {
      setOpen(false);
    } else {
      setStepIdx((i) => Math.min(i + 1, STEPS.length - 1));
    }
  };

  const handleSkip = () => {
    // Dismissible per the spec — but mark *completed=true* so the modal
    // never re-fires for the same admin. Customers who want to revisit can
    // hit Admin → System → "Replay onboarding wizard" which calls the
    // /reset endpoint.
    postWizardState("dismissed", true).then((updated) => {
      if (updated) setState(updated);
      setOpen(false);
    });
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) handleSkip();
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <StepIcon className="h-5 w-5 text-primary" />
            Welcome to ALDECI
          </DialogTitle>
          <DialogDescription>
            3-step setup. You can dismiss this any time and finish later.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3 py-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            {STEPS.map((s, i) => (
              <span
                key={s.key}
                className={
                  "h-1.5 flex-1 rounded-full " +
                  (i < stepIdx
                    ? "bg-primary"
                    : i === stepIdx
                      ? "bg-primary/70"
                      : "bg-muted")
                }
              />
            ))}
          </div>
          <h3 className="text-base font-medium">{step.title}</h3>
          <p className="text-sm text-muted-foreground">{step.description}</p>
          <a
            href={step.ctaHref}
            className="inline-flex items-center gap-1.5 text-sm font-medium text-primary underline-offset-4 hover:underline"
          >
            {step.cta} →
          </a>
        </div>

        <DialogFooter className="gap-2 sm:gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={handleSkip}
            disabled={busy}
          >
            <X className="mr-1.5 h-4 w-4" />
            Dismiss
          </Button>
          <Button onClick={handleNext} disabled={busy} size="sm">
            {isLast ? "Finish" : "Next"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
