import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, LogIn, Loader2, AlertCircle, Eye, EyeOff, Key, ExternalLink } from "lucide-react";
import { useAuth } from "@/lib/auth";
import {
  setStoredAuthStrategy,
  setStoredAuthToken,
  buildApiUrl,
} from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────────────────────

type Tab = "credentials" | "sso" | "apikey";

interface SSOProvider {
  name: string;
  display_name: string;
  provider_type: "saml" | "oidc";
  login_url: string;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function LoginPage() {
  const navigate = useNavigate();
  const { login, loading } = useAuth();

  // Shared
  const [activeTab, setActiveTab] = useState<Tab>("credentials");
  const [error, setError] = useState<string | null>(null);

  // Credentials tab
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // SSO tab
  const [ssoLoading, setSsoLoading] = useState(false);
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [providersLoaded, setProvidersLoaded] = useState(false);

  // API key tab
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
        navigate("/", { replace: true });
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

      // Lazily load SSO providers the first time the SSO tab is activated
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
    // Redirect browser to the backend initiation endpoint.
    // The backend will redirect to IdP; on callback it issues a JWT.
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

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="w-full max-w-md"
      >
        {/* Brand */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-primary/10">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">ALdeci</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            CTEM+ Decision Intelligence Platform
          </p>
        </div>

        <Card className="border-border/50 bg-card/80 backdrop-blur-sm">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg">Sign in</CardTitle>
            <CardDescription>Choose your authentication method</CardDescription>
          </CardHeader>

          <CardContent className="pt-4">
            {/* Tab switcher */}
            <div className="mb-6 flex gap-1 rounded-lg bg-muted p-1">
              {(
                [
                  { id: "credentials", label: "Credentials" },
                  { id: "sso", label: "SSO / SAML" },
                  { id: "apikey", label: "API Key" },
                ] as const
              ).map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => handleTabChange(id)}
                  className={[
                    "flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-all",
                    activeTab === id
                      ? "bg-background text-foreground shadow-sm"
                      : "text-muted-foreground hover:text-foreground",
                  ].join(" ")}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Error banner */}
            <AnimatePresence>
              {error && (
                <motion.div
                  key="error"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="mb-4 flex items-start gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive"
                >
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{error}</span>
                </motion.div>
              )}
            </AnimatePresence>

            {/* ── Credentials tab ── */}
            {activeTab === "credentials" && (
              <form onSubmit={handleCredentialsSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="you@company.com"
                    autoComplete="email"
                    autoFocus
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={loading}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={loading}
                      className="pr-10"
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
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

                <Button type="submit" className="w-full" disabled={loading}>
                  {loading ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Signing in…
                    </>
                  ) : (
                    <>
                      <LogIn className="mr-2 h-4 w-4" />
                      Sign in
                    </>
                  )}
                </Button>
              </form>
            )}

            {/* ── SSO / SAML tab ── */}
            {activeTab === "sso" && (
              <div className="space-y-3">
                {ssoLoading && (
                  <div className="flex items-center justify-center gap-2 py-8 text-sm text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading providers…
                  </div>
                )}

                {!ssoLoading && providers.length === 0 && (
                  <div className="rounded-md border border-border/50 bg-muted/30 p-4 text-center text-sm text-muted-foreground">
                    <p className="font-medium text-foreground">No SSO providers configured</p>
                    <p className="mt-1">
                      Ask your administrator to configure a SAML or OIDC provider.
                    </p>
                    <p className="mt-3 text-xs">
                      Backend env var:{" "}
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                        FIXOPS_SSO_PROVIDER
                      </code>
                    </p>
                  </div>
                )}

                {!ssoLoading &&
                  providers.map((provider) => (
                    <Button
                      key={provider.name}
                      variant="outline"
                      className="w-full justify-between"
                      onClick={() => handleSSOLogin(provider)}
                    >
                      <span className="flex items-center gap-2">
                        <Shield className="h-4 w-4 text-primary" />
                        {provider.display_name}
                        <span className="rounded bg-muted px-1.5 py-0.5 text-xs font-normal uppercase tracking-wide text-muted-foreground">
                          {provider.provider_type}
                        </span>
                      </span>
                      <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  ))}

                <p className="pt-2 text-center text-xs text-muted-foreground">
                  You will be redirected to your identity provider to complete sign-in.
                </p>
              </div>
            )}

            {/* ── API Key tab ── */}
            {activeTab === "apikey" && (
              <form onSubmit={handleApiKeySubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="apikey">API Key</Label>
                  <div className="relative">
                    <Input
                      id="apikey"
                      type={showApiKey ? "text" : "password"}
                      placeholder="aldeci_••••••••••••••••"
                      autoComplete="off"
                      autoFocus
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                      className="pr-10 font-mono text-sm"
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
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
                  <p className="text-xs text-muted-foreground">
                    Generate keys in{" "}
                    <button
                      type="button"
                      className="underline underline-offset-2 hover:text-foreground"
                      onClick={() => navigate("/settings")}
                    >
                      Settings → API Keys
                    </button>
                    .
                  </p>
                </div>

                <Button type="submit" className="w-full">
                  <Key className="mr-2 h-4 w-4" />
                  Continue with API Key
                </Button>
              </form>
            )}
          </CardContent>
        </Card>

        <p className="mt-4 text-center text-xs text-muted-foreground">
          First time? Ask your admin to create an account or configure SSO.
        </p>
      </motion.div>
    </div>
  );
}
