import { useState, useCallback } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  LogIn,
  Loader2,
  AlertCircle,
  Eye,
  EyeOff,
  Key,
  ExternalLink,
  CheckCircle2,
  Zap,
  Users,
  Cpu,
  Lock,
  ArrowRight,
} from "lucide-react";
import { useAuth } from "@/lib/auth";
import {
  setStoredAuthStrategy,
  setStoredAuthToken,
  buildApiUrl,
} from "@/lib/api";
import { usePageTitle } from "@/hooks/use-page-title";

// ── Types ─────────────────────────────────────────────────────────────────────

type Tab = "credentials" | "sso" | "apikey";

interface SSOProvider {
  name: string;
  display_name: string;
  provider_type: "saml" | "oidc";
  login_url: string;
}

// ── Feature bullets ───────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: Zap,
    label: "Replace $50K/yr tools",
    sub: "Self-hosted for $35–60/month",
  },
  {
    icon: Users,
    label: "30 Personas, 6 RBAC roles",
    sub: "CISO to SOC T1 analyst",
  },
  {
    icon: Cpu,
    label: "344+ Engines",
    sub: "ASPM · CTEM · CSPM unified",
  },
  {
    icon: Lock,
    label: "Karpathy LLM Consensus",
    sub: "4 free models + Opus escalation",
  },
];

const STAT_PILLS = [
  { value: "574+", label: "API Routers" },
  { value: "8,910+", label: "Tests" },
  { value: "296+", label: "UI Pages" },
];

const TRUSTED_BY = [
  "Fortune 500",
  "Gov Contractors",
  "FinServ",
  "HealthTech",
  "SaaS Unicorns",
];

// ── Animations ────────────────────────────────────────────────────────────────

const fadeUp = (delay = 0) => ({
  initial: { opacity: 0, y: 20 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1], delay },
});

const fadeIn = (delay = 0) => ({
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  transition: { duration: 0.4, ease: "easeOut", delay },
});

// ── Component ─────────────────────────────────────────────────────────────────

export default function LoginPage() {
  usePageTitle("Sign In");
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login, loading } = useAuth();

  const [activeTab, setActiveTab] = useState<Tab>("credentials");
  const [error, setError] = useState<string | null>(null);

  // Credentials
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // SSO
  const [ssoLoading, setSsoLoading] = useState(false);
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [providersLoaded, setProvidersLoaded] = useState(false);

  // API key
  const [apiKey, setApiKey] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);

  // ── Handlers ────────────────────────────────────────────────────────────────

  const handleCredentialsSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      if (!email.trim() || !password) {
        setError("Email and password are required.");
        return;
      }
      try {
        await login(email.trim(), password);
        const next = searchParams.get("next") ?? "/executive";
        navigate(next, { replace: true });
      } catch (err: unknown) {
        const msg =
          (err as { response?: { data?: { detail?: string } } })?.response?.data
            ?.detail ?? "Login failed. Check your credentials.";
        setError(msg);
      }
    },
    [email, password, login, navigate],
  );

  const handleTabChange = useCallback(
    async (tab: Tab) => {
      setError(null);
      setActiveTab(tab);
      if (tab === "sso" && !providersLoaded) {
        setSsoLoading(true);
        try {
          const url = buildApiUrl("/api/v1/auth/sso/providers");
          const res = await fetch(url);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const data = await res.json();
          setProviders(data.providers ?? []);
        } catch {
          setProviders([]);
        } finally {
          setSsoLoading(false);
          setProvidersLoaded(true);
        }
      }
    },
    [providersLoaded],
  );

  const handleSSOLogin = useCallback((provider: SSOProvider) => {
    window.location.href = provider.login_url;
  }, []);

  const handleApiKeySubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      setError(null);
      const trimmed = apiKey.trim();
      if (!trimmed) {
        setError("API key is required.");
        return;
      }
      setStoredAuthStrategy("token");
      setStoredAuthToken(trimmed);
      navigate("/", { replace: true });
    },
    [apiKey, navigate],
  );

  const handleQuickSSO = useCallback(async () => {
    setError(null);
    const defaultIdp = import.meta.env.VITE_SAML_DEFAULT_IDP;
    const idpName = defaultIdp || prompt("Enter IdP name (e.g., okta, azure, google):");
    if (!idpName?.trim()) return;

    try {
      const url = buildApiUrl(`/api/v1/auth/saml/${idpName.trim()}/initiate`);
      const res = await fetch(url, { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.redirect_url) {
        window.location.href = data.redirect_url;
      }
    } catch (err: unknown) {
      const msg = (err as Error)?.message || "SSO initiation failed.";
      setError(msg);
    }
  }, []);

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div
      className="flex min-h-screen overflow-hidden"
      style={{
        background:
          "linear-gradient(135deg, oklch(0.08 0.025 240) 0%, oklch(0.05 0.01 250) 50%, oklch(0.04 0.005 260) 100%)",
      }}
    >
      {/* ── Left panel: Branding ── */}
      <div className="relative hidden lg:flex lg:w-[52%] xl:w-[55%] flex-col justify-between overflow-hidden p-12">
        {/* Mesh gradient background */}
        <div
          className="absolute inset-0 pointer-events-none"
          aria-hidden="true"
          style={{
            background:
              "radial-gradient(ellipse 80% 60% at 20% 30%, oklch(0.30 0.12 195 / 0.18) 0%, transparent 60%), " +
              "radial-gradient(ellipse 60% 50% at 80% 70%, oklch(0.25 0.08 220 / 0.12) 0%, transparent 55%), " +
              "radial-gradient(ellipse 40% 40% at 50% 90%, oklch(0.20 0.06 200 / 0.10) 0%, transparent 50%)",
          }}
        />

        {/* Subtle grid overlay */}
        <div
          className="absolute inset-0 pointer-events-none opacity-[0.03]"
          aria-hidden="true"
          style={{
            backgroundImage:
              "linear-gradient(oklch(0.9 0 0) 1px, transparent 1px), linear-gradient(90deg, oklch(0.9 0 0) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />

        {/* Top: Logo + tagline */}
        <motion.div {...fadeUp(0)} className="relative z-10">
          <div className="flex items-center gap-3 mb-8">
            {/* Shield with pulse ring */}
            <div className="relative">
              <motion.div
                className="absolute inset-0 rounded-2xl"
                style={{
                  boxShadow: "0 0 0 0 oklch(0.65 0.15 195 / 0.5)",
                }}
                animate={{
                  boxShadow: [
                    "0 0 0 0px oklch(0.65 0.15 195 / 0.5)",
                    "0 0 0 14px oklch(0.65 0.15 195 / 0.0)",
                  ],
                }}
                transition={{ duration: 2.2, repeat: Infinity, ease: "easeOut" }}
              />
              <div
                className="relative flex h-14 w-14 items-center justify-center rounded-2xl"
                style={{
                  background:
                    "linear-gradient(135deg, oklch(0.55 0.18 195) 0%, oklch(0.42 0.14 210) 100%)",
                  boxShadow: "0 4px 24px oklch(0.65 0.15 195 / 0.35)",
                }}
              >
                <Shield className="h-7 w-7 text-white" strokeWidth={1.5} />
              </div>
            </div>

            <div>
              <h1
                className="text-2xl font-bold tracking-tight"
                style={{ color: "oklch(0.96 0.005 250)" }}
              >
                ALDECI
              </h1>
              <p
                className="text-xs font-medium tracking-[0.12em] uppercase"
                style={{ color: "oklch(0.65 0.15 195)" }}
              >
                Enterprise Security Intelligence
              </p>
            </div>
          </div>

          {/* Headline */}
          <motion.div {...fadeUp(0.1)} className="mb-12 max-w-md">
            <h2
              className="text-4xl font-bold leading-tight mb-4"
              style={{
                color: "oklch(0.96 0.005 250)",
                letterSpacing: "-0.02em",
              }}
            >
              Unified security
              <br />
              <span
                style={{
                  background:
                    "linear-gradient(90deg, oklch(0.72 0.16 185), oklch(0.68 0.18 195), oklch(0.62 0.14 210))",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  backgroundClip: "text",
                }}
              >
                intelligence platform
              </span>
            </h2>
            <p style={{ color: "oklch(0.60 0.01 250)" }} className="text-base leading-relaxed">
              ASPM · CTEM · CSPM converged into a single self-hosted platform.
              AI-native from day one.
            </p>
          </motion.div>
        </motion.div>

        {/* Middle: Feature list */}
        <div className="relative z-10 flex-1 flex flex-col justify-center">
          <div className="space-y-4 mb-10">
            {FEATURES.map((f, i) => (
              <motion.div
                key={f.label}
                {...fadeUp(0.15 + i * 0.08)}
                className="flex items-start gap-4 group"
              >
                <div
                  className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl transition-all duration-200 group-hover:scale-105"
                  style={{
                    background: "oklch(0.65 0.15 195 / 0.12)",
                    border: "1px solid oklch(0.65 0.15 195 / 0.20)",
                  }}
                >
                  <f.icon
                    className="h-4 w-4"
                    style={{ color: "oklch(0.72 0.16 185)" }}
                    strokeWidth={1.75}
                  />
                </div>
                <div>
                  <p
                    className="text-sm font-semibold"
                    style={{ color: "oklch(0.90 0.005 250)" }}
                  >
                    {f.label}
                  </p>
                  <p className="text-xs mt-0.5" style={{ color: "oklch(0.55 0.01 250)" }}>
                    {f.sub}
                  </p>
                </div>
                <CheckCircle2
                  className="ml-auto h-4 w-4 shrink-0 mt-0.5"
                  style={{ color: "oklch(0.65 0.18 155)" }}
                  strokeWidth={2}
                />
              </motion.div>
            ))}
          </div>

          {/* Stat pills */}
          <motion.div {...fadeUp(0.55)} className="flex gap-3 flex-wrap">
            {STAT_PILLS.map((s) => (
              <div
                key={s.label}
                className="flex flex-col items-center rounded-xl px-4 py-3"
                style={{
                  background: "oklch(0.15 0.015 250 / 0.6)",
                  border: "1px solid oklch(0.30 0.02 250 / 0.5)",
                  backdropFilter: "blur(8px)",
                }}
              >
                <span
                  className="text-xl font-bold tabular-nums"
                  style={{ color: "oklch(0.72 0.16 185)" }}
                >
                  {s.value}
                </span>
                <span className="text-xs mt-0.5" style={{ color: "oklch(0.50 0.01 250)" }}>
                  {s.label}
                </span>
              </div>
            ))}
          </motion.div>
        </div>

        {/* Bottom: Social proof */}
        <motion.div {...fadeUp(0.65)} className="relative z-10 pt-8 border-t" style={{ borderColor: "oklch(0.22 0.01 250 / 0.6)" }}>
          <p className="text-xs mb-3" style={{ color: "oklch(0.45 0.01 250)" }}>
            Trusted by enterprise security teams in
          </p>
          <div className="flex flex-wrap gap-2">
            {TRUSTED_BY.map((label) => (
              <span
                key={label}
                className="rounded-md px-2.5 py-1 text-xs font-medium"
                style={{
                  background: "oklch(0.18 0.01 250 / 0.8)",
                  color: "oklch(0.65 0.01 250)",
                  border: "1px solid oklch(0.28 0.01 250 / 0.5)",
                }}
              >
                {label}
              </span>
            ))}
          </div>
        </motion.div>
      </div>

      {/* ── Right panel: Login form ── */}
      <div
        className="flex flex-1 flex-col items-center justify-center px-6 py-12 lg:px-10"
        style={{
          background: "oklch(0.07 0.008 250 / 0.95)",
          borderLeft: "1px solid oklch(0.20 0.01 250 / 0.6)",
        }}
      >
        {/* Mobile-only logo */}
        <motion.div {...fadeUp(0)} className="flex lg:hidden items-center gap-3 mb-8">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-xl"
            style={{
              background:
                "linear-gradient(135deg, oklch(0.55 0.18 195) 0%, oklch(0.42 0.14 210) 100%)",
            }}
          >
            <Shield className="h-5 w-5 text-white" strokeWidth={1.5} />
          </div>
          <div>
            <span className="text-base font-bold" style={{ color: "oklch(0.96 0.005 250)" }}>
              ALDECI
            </span>
            <p className="text-xs" style={{ color: "oklch(0.65 0.15 195)" }}>
              Enterprise Security Intelligence
            </p>
          </div>
        </motion.div>

        <motion.div {...fadeUp(0.05)} className="w-full max-w-sm">
          {/* Form header */}
          <div className="mb-8">
            <h2
              className="text-2xl font-bold tracking-tight mb-1"
              style={{ color: "oklch(0.96 0.005 250)", letterSpacing: "-0.02em" }}
            >
              Sign in
            </h2>
            <p className="text-sm" style={{ color: "oklch(0.50 0.01 250)" }}>
              Choose your authentication method
            </p>
          </div>

          {/* Tab switcher */}
          <motion.div {...fadeUp(0.10)}>
            <div
              className="mb-6 flex gap-1 rounded-xl p-1"
              style={{
                background: "oklch(0.11 0.01 250)",
                border: "1px solid oklch(0.20 0.01 250 / 0.7)",
              }}
            >
              {(
                [
                  { id: "credentials", label: "Password" },
                  { id: "sso", label: "SSO" },
                  { id: "apikey", label: "API Key" },
                ] as const
              ).map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => handleTabChange(id)}
                  className="flex-1 rounded-lg px-3 py-2 text-xs font-semibold transition-all duration-200"
                  style={
                    activeTab === id
                      ? {
                          background:
                            "linear-gradient(135deg, oklch(0.55 0.18 195) 0%, oklch(0.45 0.14 210) 100%)",
                          color: "oklch(0.98 0.002 195)",
                          boxShadow: "0 2px 8px oklch(0.65 0.15 195 / 0.25)",
                        }
                      : {
                          color: "oklch(0.50 0.01 250)",
                        }
                  }
                >
                  {label}
                </button>
              ))}
            </div>
          </motion.div>

          {/* Error banner */}
          <AnimatePresence>
            {error && (
              <motion.div
                key="error"
                initial={{ opacity: 0, height: 0, marginBottom: 0 }}
                animate={{ opacity: 1, height: "auto", marginBottom: 16 }}
                exit={{ opacity: 0, height: 0, marginBottom: 0 }}
                className="flex items-start gap-2.5 rounded-xl p-3 text-sm"
                style={{
                  background: "oklch(0.55 0.2 25 / 0.10)",
                  border: "1px solid oklch(0.55 0.2 25 / 0.25)",
                  color: "oklch(0.72 0.15 25)",
                }}
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </motion.div>
            )}
          </AnimatePresence>

          {/* ── Credentials tab ── */}
          <AnimatePresence mode="wait">
            {activeTab === "credentials" && (
              <motion.form
                key="credentials"
                {...fadeIn(0)}
                onSubmit={handleCredentialsSubmit}
                className="space-y-4"
              >
                <div className="space-y-1.5">
                  <Label
                    htmlFor="email"
                    className="text-xs font-semibold uppercase tracking-wide"
                    style={{ color: "oklch(0.55 0.01 250)" }}
                  >
                    Work Email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="you@company.com"
                    autoComplete="email"
                    autoFocus
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={loading}
                    className="h-11"
                    style={{
                      background: "oklch(0.10 0.01 250)",
                      border: "1px solid oklch(0.22 0.01 250)",
                      color: "oklch(0.93 0.005 250)",
                    }}
                  />
                </div>

                <div className="space-y-1.5">
                  <Label
                    htmlFor="password"
                    className="text-xs font-semibold uppercase tracking-wide"
                    style={{ color: "oklch(0.55 0.01 250)" }}
                  >
                    Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••••••"
                      autoComplete="current-password"
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
                      {showPassword ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
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
                      boxShadow: loading
                        ? "none"
                        : "0 4px 16px oklch(0.65 0.15 195 / 0.30)",
                      border: "none",
                      color: "oklch(0.98 0.002 195)",
                    }}
                  >
                    {loading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Authenticating…
                      </>
                    ) : (
                      <>
                        <LogIn className="mr-2 h-4 w-4" />
                        Sign in to ALDECI
                        <ArrowRight className="ml-auto h-4 w-4 opacity-70" />
                      </>
                    )}
                  </Button>
                </div>

                <div className="pt-2">
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full h-11 font-semibold text-sm"
                    onClick={handleQuickSSO}
                    style={{
                      background: "oklch(0.11 0.01 250)",
                      border: "1px solid oklch(0.22 0.01 250)",
                      color: "oklch(0.85 0.005 250)",
                    }}
                  >
                    <Shield className="mr-2 h-4 w-4" style={{ color: "oklch(0.65 0.15 195)" }} />
                    Sign in with SSO
                  </Button>
                </div>
              </motion.form>
            )}

            {/* ── SSO / SAML tab ── */}
            {activeTab === "sso" && (
              <motion.div key="sso" {...fadeIn(0)} className="space-y-3">
                {ssoLoading && (
                  <div
                    className="flex items-center justify-center gap-2 py-10 text-sm rounded-xl"
                    style={{ color: "oklch(0.50 0.01 250)" }}
                  >
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading providers…
                  </div>
                )}

                {!ssoLoading && providers.length === 0 && (
                  <div
                    className="rounded-xl p-6 text-center text-sm"
                    style={{
                      background: "oklch(0.10 0.01 250)",
                      border: "1px solid oklch(0.22 0.01 250)",
                    }}
                  >
                    <Shield
                      className="mx-auto mb-3 h-8 w-8"
                      style={{ color: "oklch(0.35 0.01 250)" }}
                      strokeWidth={1.5}
                    />
                    <p className="font-semibold mb-1" style={{ color: "oklch(0.80 0.005 250)" }}>
                      No SSO providers configured
                    </p>
                    <p className="text-xs" style={{ color: "oklch(0.45 0.01 250)" }}>
                      Ask your administrator to configure a SAML or OIDC provider.
                    </p>
                    <p
                      className="mt-3 text-xs rounded-lg px-3 py-2 inline-block font-mono"
                      style={{
                        background: "oklch(0.14 0.01 250)",
                        color: "oklch(0.60 0.01 250)",
                        border: "1px solid oklch(0.22 0.01 250)",
                      }}
                    >
                      FIXOPS_SSO_PROVIDER
                    </p>
                  </div>
                )}

                {!ssoLoading &&
                  providers.map((provider) => (
                    <button
                      key={provider.name}
                      type="button"
                      className="w-full flex items-center justify-between rounded-xl px-4 py-3 text-sm font-medium transition-all duration-200 hover:scale-[1.01]"
                      style={{
                        background: "oklch(0.11 0.01 250)",
                        border: "1px solid oklch(0.22 0.01 250)",
                        color: "oklch(0.85 0.005 250)",
                      }}
                      onClick={() => handleSSOLogin(provider)}
                    >
                      <span className="flex items-center gap-2">
                        <Shield
                          className="h-4 w-4"
                          style={{ color: "oklch(0.65 0.15 195)" }}
                        />
                        {provider.display_name}
                        <span
                          className="rounded-md px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide"
                          style={{
                            background: "oklch(0.65 0.15 195 / 0.12)",
                            color: "oklch(0.65 0.15 195)",
                          }}
                        >
                          {provider.provider_type}
                        </span>
                      </span>
                      <ExternalLink className="h-3.5 w-3.5" style={{ color: "oklch(0.40 0.01 250)" }} />
                    </button>
                  ))}

                <p className="pt-1 text-center text-xs" style={{ color: "oklch(0.40 0.01 250)" }}>
                  You will be redirected to your identity provider to complete sign-in.
                </p>
              </motion.div>
            )}

            {/* ── API Key tab ── */}
            {activeTab === "apikey" && (
              <motion.form key="apikey" {...fadeIn(0)} onSubmit={handleApiKeySubmit} className="space-y-4">
                <div className="space-y-1.5">
                  <Label
                    htmlFor="apikey"
                    className="text-xs font-semibold uppercase tracking-wide"
                    style={{ color: "oklch(0.55 0.01 250)" }}
                  >
                    API Key
                  </Label>
                  <div className="relative">
                    <Input
                      id="apikey"
                      type={showApiKey ? "text" : "password"}
                      placeholder="aldeci_••••••••••••••••"
                      autoComplete="off"
                      autoFocus
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      className="h-11 pr-10 font-mono text-sm"
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
                      onClick={() => setShowApiKey((v) => !v)}
                      tabIndex={-1}
                      aria-label={showApiKey ? "Hide key" : "Show key"}
                    >
                      {showApiKey ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <p className="text-xs" style={{ color: "oklch(0.40 0.01 250)" }}>
                    Generate keys in{" "}
                    <button
                      type="button"
                      className="underline underline-offset-2 transition-colors duration-150"
                      style={{ color: "oklch(0.60 0.12 195)" }}
                      onClick={() => navigate("/settings")}
                    >
                      Settings → API Keys
                    </button>
                    .
                  </p>
                </div>

                <div className="pt-2">
                  <Button
                    type="submit"
                    className="w-full h-11 font-semibold text-sm"
                    style={{
                      background:
                        "linear-gradient(135deg, oklch(0.58 0.18 195) 0%, oklch(0.48 0.14 210) 100%)",
                      boxShadow: "0 4px 16px oklch(0.65 0.15 195 / 0.30)",
                      border: "none",
                      color: "oklch(0.98 0.002 195)",
                    }}
                  >
                    <Key className="mr-2 h-4 w-4" />
                    Continue with API Key
                    <ArrowRight className="ml-auto h-4 w-4 opacity-70" />
                  </Button>
                </div>
              </motion.form>
            )}
          </AnimatePresence>

          {/* Footer note */}
          <motion.p
            {...fadeUp(0.30)}
            className="mt-6 text-center text-xs"
            style={{ color: "oklch(0.38 0.01 250)" }}
          >
            First time?{" "}
            <span style={{ color: "oklch(0.55 0.01 250)" }}>
              Ask your admin to create an account or configure SSO.
            </span>
          </motion.p>
        </motion.div>

        {/* Bottom security badge */}
        <motion.div
          {...fadeIn(0.45)}
          className="mt-8 flex items-center gap-2 text-xs"
          style={{ color: "oklch(0.32 0.01 250)" }}
        >
          <Lock className="h-3 w-3" />
          <span>256-bit TLS · SOC 2 ready · Self-hosted</span>
        </motion.div>
      </div>
    </div>
  );
}
