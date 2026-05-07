import { useState, useCallback } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { motion } from "framer-motion";
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  Loader2,
  AlertCircle,
  CheckCircle2,
  ArrowLeft,
  ArrowRight,
} from "lucide-react";
import { buildApiUrl } from "@/lib/api";
import { usePageTitle } from "@/hooks/use-page-title";

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 20 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1], delay },
});

const MIN_PASSWORD_LENGTH = 8;

export default function ResetPasswordPage() {
  usePageTitle("Reset Password");
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);

      if (!token) {
        setError("Invalid reset link. Request a new one.");
        return;
      }
      if (password.length < MIN_PASSWORD_LENGTH) {
        setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
        return;
      }
      if (password !== confirm) {
        setError("Passwords do not match.");
        return;
      }

      setLoading(true);
      try {
        const res = await fetch(buildApiUrl("/api/v1/auth/reset-password"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, new_password: password }),
        });
        if (res.ok) {
          setDone(true);
        } else {
          const data = await res.json().catch(() => ({}));
          setError(
            (data as { detail?: string }).detail ??
              "Reset failed. The link may have expired — request a new one.",
          );
        }
      } catch {
        setError("Network error. Check your connection and try again.");
      } finally {
        setLoading(false);
      }
    },
    [token, password, confirm],
  );

  return (
    <div
      className="flex min-h-screen items-center justify-center px-6 py-12"
      style={{
        background:
          "linear-gradient(135deg, oklch(0.08 0.025 240) 0%, oklch(0.05 0.01 250) 50%, oklch(0.04 0.005 260) 100%)",
      }}
    >
      <motion.div {...fadeUp(0)} className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex items-center gap-3 mb-10 justify-center">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-xl"
            style={{
              background:
                "linear-gradient(135deg, oklch(0.55 0.18 195) 0%, oklch(0.42 0.14 210) 100%)",
              boxShadow: "0 4px 24px oklch(0.65 0.15 195 / 0.35)",
            }}
          >
            <Shield className="h-5 w-5 text-white" strokeWidth={1.5} />
          </div>
          <span className="text-base font-bold" style={{ color: "oklch(0.96 0.005 250)" }}>
            ALDECI
          </span>
        </div>

        <div
          className="rounded-2xl p-8"
          style={{
            background: "oklch(0.07 0.008 250 / 0.95)",
            border: "1px solid oklch(0.20 0.01 250 / 0.6)",
          }}
        >
          {done ? (
            <motion.div {...fadeUp(0)} className="text-center space-y-4">
              <CheckCircle2
                className="mx-auto h-12 w-12"
                style={{ color: "oklch(0.65 0.18 155)" }}
                strokeWidth={1.5}
              />
              <h2
                className="text-xl font-bold"
                style={{ color: "oklch(0.96 0.005 250)", letterSpacing: "-0.02em" }}
              >
                Password updated
              </h2>
              <p className="text-sm leading-relaxed" style={{ color: "oklch(0.55 0.01 250)" }}>
                Your password has been changed. You can now sign in with your new credentials.
              </p>
              <Button
                className="w-full h-11 font-semibold text-sm mt-2"
                onClick={() => navigate("/login", { replace: true })}
                style={{
                  background:
                    "linear-gradient(135deg, oklch(0.58 0.18 195) 0%, oklch(0.48 0.14 210) 100%)",
                  boxShadow: "0 4px 16px oklch(0.65 0.15 195 / 0.30)",
                  border: "none",
                  color: "oklch(0.98 0.002 195)",
                }}
              >
                Sign in
                <ArrowRight className="ml-auto h-4 w-4 opacity-70" />
              </Button>
            </motion.div>
          ) : (
            <>
              <div className="mb-6">
                <h2
                  className="text-2xl font-bold tracking-tight mb-1"
                  style={{ color: "oklch(0.96 0.005 250)", letterSpacing: "-0.02em" }}
                >
                  New password
                </h2>
                <p className="text-sm" style={{ color: "oklch(0.50 0.01 250)" }}>
                  Choose a strong password of at least {MIN_PASSWORD_LENGTH} characters.
                </p>
              </div>

              {error && (
                <div
                  className="flex items-start gap-2.5 rounded-xl p-3 text-sm mb-5"
                  style={{
                    background: "oklch(0.55 0.2 25 / 0.10)",
                    border: "1px solid oklch(0.55 0.2 25 / 0.25)",
                    color: "oklch(0.72 0.15 25)",
                  }}
                >
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <Label
                    htmlFor="password"
                    className="text-xs font-semibold uppercase tracking-wide"
                    style={{ color: "oklch(0.55 0.01 250)" }}
                  >
                    New Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••••••"
                      autoComplete="new-password"
                      autoFocus
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={loading}
                      className="h-11 pr-10"
                      style={{
                        background: "oklch(0.10 0.01 250)",
                        border: "1px solid oklch(0.22 0.01 250)",
                        color: "oklch(0.93 0.005 250)",
                      }}
                    />
                    <button
                      type="button"
                      className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors duration-150"
                      style={{ color: "oklch(0.45 0.01 250)" }}
                      onClick={() => setShowPassword((v) => !v)}
                      tabIndex={-1}
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label
                    htmlFor="confirm"
                    className="text-xs font-semibold uppercase tracking-wide"
                    style={{ color: "oklch(0.55 0.01 250)" }}
                  >
                    Confirm Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="confirm"
                      type={showConfirm ? "text" : "password"}
                      placeholder="••••••••••••"
                      autoComplete="new-password"
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                      disabled={loading}
                      className="h-11 pr-10"
                      style={{
                        background: "oklch(0.10 0.01 250)",
                        border: "1px solid oklch(0.22 0.01 250)",
                        color: "oklch(0.93 0.005 250)",
                      }}
                    />
                    <button
                      type="button"
                      className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors duration-150"
                      style={{ color: "oklch(0.45 0.01 250)" }}
                      onClick={() => setShowConfirm((v) => !v)}
                      tabIndex={-1}
                      aria-label={showConfirm ? "Hide password" : "Show password"}
                    >
                      {showConfirm ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>

                <div className="pt-2">
                  <Button
                    type="submit"
                    className="w-full h-11 font-semibold text-sm"
                    disabled={loading}
                    style={{
                      background: loading
                        ? "oklch(0.35 0.10 195)"
                        : "linear-gradient(135deg, oklch(0.58 0.18 195) 0%, oklch(0.48 0.14 210) 100%)",
                      boxShadow: loading ? "none" : "0 4px 16px oklch(0.65 0.15 195 / 0.30)",
                      border: "none",
                      color: "oklch(0.98 0.002 195)",
                    }}
                  >
                    {loading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Updating…
                      </>
                    ) : (
                      <>
                        <Lock className="mr-2 h-4 w-4" />
                        Set new password
                        <ArrowRight className="ml-auto h-4 w-4 opacity-70" />
                      </>
                    )}
                  </Button>
                </div>
              </form>
            </>
          )}

          {!done && (
            <div className="mt-6 text-center">
              <Link
                to="/forgot-password"
                className="inline-flex items-center gap-1.5 text-xs transition-colors duration-150"
                style={{ color: "oklch(0.55 0.12 195)" }}
              >
                <ArrowLeft className="h-3 w-3" />
                Request a new link
              </Link>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
