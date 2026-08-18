/**
 * AuthContext — JWT session management for ALdeci.
 *
 * Stores decoded JWT claims in React context so every component can
 * check `isAuthenticated`, read `user.role`, and call `login` / `logout`.
 *
 * Roles:  admin | security_analyst | developer | viewer
 * Scopes: derived from role (admin gets everything).
 */
import React, { createContext, useContext, useState, useCallback, useEffect, useMemo } from "react";
import { Navigate, useLocation } from "react-router-dom";
import {
  authApi,
  buildApiUrl,
  setStoredAuthToken,
  setStoredAuthStrategy,
  getStoredAuthToken,
  getStoredAuthStrategy,
  setStoredOrgId,
  getStoredOrgId,
  setJwtAccessToken,
  setJwtRefreshToken,
  clearJwtTokens,
} from "@/lib/api";

// ── Dev-bypass helpers ──
//
// When running under Vite dev (`import.meta.env.DEV`) we treat the session as
// authenticated with a sensible default org so deep-link visual verification
// (Playwright, manual browsing, screenshot scripts) does not get bounced to
// `/login` for every protected route.
//
// `import.meta.env.DEV` is statically replaced with `false` by Vite at build
// time, so this entire branch is dead code in production bundles. There is
// intentionally NO localStorage escape hatch — a stale localStorage key set
// by a Playwright session or operator would otherwise activate the bypass on
// the production deployment.

const DEV_BYPASS_ORG_ID = "juice-shop-corp";

const DEV_BYPASS_USER: AuthUser = {
  id: "dev-user",
  email: "dev@verify",
  first_name: "Dev",
  last_name: "Verify",
  role: "admin",
  department: "platform",
};

export function isDevBypassActive(): boolean {
  // Strictly Vite dev mode only. import.meta.env.DEV === false in prod builds,
  // so this function always returns false in production — no runtime escape.
  return import.meta.env.DEV === true;
}

function ensureDevBypassOrg() {
  // Pin org_id to a populated tenant so dashboards see real data
  // when the bypass is active. We only set it if the operator has
  // not already chosen one explicitly.
  try {
    const current = getStoredOrgId();
    if (!current || current === "default") {
      setStoredOrgId(DEV_BYPASS_ORG_ID);
    }
  } catch {
    /* no-op */
  }
}

// ── Types ──

export type UserRole = "admin" | "security_analyst" | "developer" | "viewer";

export interface AuthUser {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  role: UserRole;
  department?: string;
}

interface AuthState {
  /** Currently authenticated user (null when logged out) */
  user: AuthUser | null;
  /** True when a login/logout operation is in-flight */
  loading: boolean;
  /** True when the user holds a valid session */
  isAuthenticated: boolean;
  /** Perform email+password login.  Stores JWT on success. */
  login: (email: string, password: string) => Promise<void>;
  /** Validate + activate an API key session.  Throws if the key is rejected. */
  loginWithApiKey: (apiKey: string) => Promise<void>;
  /** Clear the session and redirect to /login. */
  logout: () => void;
  /** Check whether the current user has the required role(s). */
  hasRole: (...roles: UserRole[]) => boolean;
  /** Check whether the current user has at least one of the given scopes. */
  hasScope: (...scopes: string[]) => boolean;
}

const ROLE_SCOPES: Record<UserRole, string[]> = {
  admin: ["admin:all", "read:findings", "write:findings", "read:sbom", "write:sbom", "read:users", "write:users", "read:policies", "write:policies"],
  security_analyst: ["read:findings", "write:findings", "read:sbom", "read:users", "read:policies", "write:policies"],
  developer: ["read:findings", "read:sbom"],
  viewer: ["read:findings", "read:sbom"],
};

// ── Helpers ──

function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.replace(/^Bearer\s+/i, "").split(".");
    if (parts.length !== 3) return null;
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

function isTokenExpired(token: string): boolean {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== "number") return true;
  return payload.exp * 1000 < Date.now();
}

function userFromStorage(): AuthUser | null {
  const raw = typeof window !== "undefined" ? window.localStorage.getItem("aldeci.authUser") : null;
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthUser;
  } catch {
    return null;
  }
}

function persistUser(user: AuthUser | null) {
  if (typeof window === "undefined") return;
  if (user) {
    window.localStorage.setItem("aldeci.authUser", JSON.stringify(user));
  } else {
    window.localStorage.removeItem("aldeci.authUser");
  }
}

// ── Context ──

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(() => {
    // Dev-bypass short-circuit — see isDevBypassActive() docstring above.
    if (isDevBypassActive()) {
      ensureDevBypassOrg();
      // Persist the dev API key to localStorage so BOTH the axios interceptor and
      // components that read getStoredAuthToken() directly send X-API-Key. Without
      // this, dashboard widgets 401 in dev (the bypass set the React user but left
      // the token unset → "failed to load"). DEV-only; tree-shaken out of prod.
      const devKey = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
      if (devKey && !getStoredAuthToken()) {
        setStoredAuthStrategy("token");
        setStoredAuthToken(devKey);
      }
      return userFromStorage() ?? DEV_BYPASS_USER;
    }
    // Restore session from localStorage if the token is valid
    const strategy = getStoredAuthStrategy();
    if (strategy === "jwt") {
      const token = getStoredAuthToken();
      if (token && !isTokenExpired(token)) {
        return userFromStorage();
      }
      // Token expired — clear
      setStoredAuthToken(null);
      persistUser(null);
      return null;
    }
    // Token-based auth (API key) — treat as authenticated only when a real
    // token exists in localStorage or is provided via VITE_API_KEY at build
    // time. VITE_API_KEY is intentionally blank in .env.production, so a fresh
    // prod visitor with nothing in localStorage correctly gets null here and is
    // redirected to /login. No hardcoded sentinel fallback.
    const apiKey = getStoredAuthToken() || import.meta.env.VITE_API_KEY || "";
    if (apiKey) {
      // Persist to localStorage so subsequent requests and reloads use it
      if (!getStoredAuthToken()) {
        setStoredAuthStrategy("token");
        setStoredAuthToken(apiKey);
      }
      return userFromStorage() ?? { id: "api-key", email: "", first_name: "API", last_name: "User", role: "admin" as UserRole };
    }
    return null;
  });
  const [loading, setLoading] = useState(false);

  const isAuthenticated = user !== null;

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    try {
      const { data } = await authApi.login({ email, password });
      const accessToken = data.access_token;
      const refreshToken = data.refresh_token;
      const userData = data.user as AuthUser | undefined;
      // Absence here is a real failure, not a blank profile. Without it,
      // persistUser(undefined) CLEARS the stored user while isAuthenticated
      // stays true, so hasRole()/hasScope() answer false for everything and the
      // whole role-gated product renders empty with no error shown anywhere.
      // Fail loudly instead of logging someone into a product that isn't there.
      if (!userData || !userData.role) {
        throw new Error(
          "Signed in, but the server did not return your profile — the session cannot be trusted. Please try again or contact your administrator.",
        );
      }

      // Access token: memory only (XSS-safe)
      setJwtAccessToken(accessToken);
      // Refresh token: localStorage (survives reload, 7d TTL)
      setJwtRefreshToken(refreshToken);
      // Legacy token store kept in sync for interceptors that read getStoredAuthToken()
      setStoredAuthStrategy("jwt");
      setStoredAuthToken(accessToken);
      persistUser(userData);
      setUser(userData);
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * API-key login.  Previously the LoginPage wrote the key straight to
   * localStorage and navigated — which never updated this provider's React
   * state, so RequireAuth immediately bounced the user back to /login with NO
   * error shown (the product was effectively un-loginable via API key).
   *
   * Now we VALIDATE the key against the API first and only then activate the
   * session, so a bad key produces a real error instead of a silent bounce.
   */
  const loginWithApiKey = useCallback(async (apiKey: string) => {
    const key = apiKey.trim();
    if (!key) throw new Error("API key is required.");
    setLoading(true);
    try {
      // Ask the server who this key is. /auth/me both VALIDATES the key and
      // returns the identity the API will actually enforce.
      //
      // This previously hit /api/v1/orgs purely as a liveness probe and then
      // hardcoded `role: "admin"`. Any key — analyst, developer, viewer — got
      // the full admin surface, and every privileged control on it failed with
      // a 403 the moment it was used. The client does not get to decide its own
      // role; only the server knows what the credential was granted.
      const res = await fetch(buildApiUrl("/api/v1/auth/me"), {
        headers: { "X-API-Key": key },
      });
      if (res.status === 401 || res.status === 403) {
        throw new Error("That API key was rejected. Check the key and try again.");
      }
      if (!res.ok) {
        throw new Error(`Could not reach the FixOps API (HTTP ${res.status}). Is the server running?`);
      }
      const me = await res.json();
      const apiUser: AuthUser = {
        id: me.id ?? "api-key",
        email: me.email ?? "",
        first_name: me.first_name ?? "API",
        last_name: me.last_name ?? "User",
        role: (me.role ?? "viewer") as UserRole,
      };
      setStoredAuthStrategy("token");
      setStoredAuthToken(key);
      persistUser(apiUser);
      setUser(apiUser);
    } catch (err) {
      // Network failure surfaces as a TypeError from fetch — make it readable.
      if (err instanceof TypeError) {
        throw new Error("Could not reach the FixOps API. Is the server running?");
      }
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    clearJwtTokens();
    setStoredAuthToken(null);
    setStoredAuthStrategy("token");
    persistUser(null);
    setUser(null);
    window.location.assign("/login");
  }, []);

  const hasRole = useCallback((...roles: UserRole[]) => {
    if (!user) return false;
    return roles.includes(user.role);
  }, [user]);

  const hasScope = useCallback((...scopes: string[]) => {
    if (!user) return false;
    const userScopes = ROLE_SCOPES[user.role] ?? [];
    if (userScopes.includes("admin:all")) return true;
    return scopes.some((s) => userScopes.includes(s));
  }, [user]);

  // Auto-logout when token expires (check every 60s)
  useEffect(() => {
    if (!isAuthenticated || getStoredAuthStrategy() !== "jwt") return;
    const interval = setInterval(() => {
      const token = getStoredAuthToken();
      if (!token || isTokenExpired(token)) {
        logout();
      }
    }, 60_000);
    return () => clearInterval(interval);
  }, [isAuthenticated, logout]);

  const value = useMemo<AuthState>(
    () => ({ user, loading, isAuthenticated, login, loginWithApiKey, logout, hasRole, hasScope }),
    [user, loading, isAuthenticated, login, loginWithApiKey, logout, hasRole, hasScope],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Hook to access auth state.  Must be used within <AuthProvider>. */
export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

/** Route guard component — renders children only if authenticated, else redirects to /login. */
export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    // Bypass for dev / visual-verify mode — these flows want every protected
    // route reachable without a real backend session.
    if (isDevBypassActive()) {
      return <>{children}</>;
    }
    // Preserve the deep link so the LoginPage can bounce the user back
    // after a successful login (rather than dumping them on the dashboard).
    const from = encodeURIComponent(`${location.pathname}${location.search}${location.hash}`);
    return <Navigate to={`/login?from=${from}`} replace />;
  }
  return <>{children}</>;
}

/** Role gate — renders children only if the user has one of the required roles. */
export function RequireRole({ roles, fallback, children }: { roles: UserRole[]; fallback?: React.ReactNode; children: React.ReactNode }) {
  const { hasRole } = useAuth();
  if (!hasRole(...roles)) return <>{fallback ?? null}</>;
  return <>{children}</>;
}
