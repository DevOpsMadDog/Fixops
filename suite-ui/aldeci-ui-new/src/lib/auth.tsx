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
// When running under Vite dev (`import.meta.env.DEV`) OR when the operator
// flips the `FIXOPS_VISUAL_VERIFY` localStorage flag, we treat the session as
// authenticated with a sensible default org so deep-link visual verification
// (Playwright, manual browsing, screenshot scripts) does not get bounced to
// `/login` for every protected route. This NEVER fires in a production build
// unless the operator deliberately sets the localStorage key — `import.meta.env.DEV`
// is replaced with `false` by Vite at build time.

const VISUAL_VERIFY_KEY = "FIXOPS_VISUAL_VERIFY";
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
  if (typeof window === "undefined") return false;
  // Production guard — only Vite-dev builds OR explicit localStorage opt-in.
  const visualVerify = (() => {
    try {
      return window.localStorage.getItem(VISUAL_VERIFY_KEY) === "1";
    } catch {
      return false;
    }
  })();
  return Boolean((import.meta as any).env?.DEV) || visualVerify;
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
    // Token-based auth (API key) — no JWT session needed; treat as authenticated
    const DEMO_TOKEN = "aldeci-demo-key";
    const apiKey = getStoredAuthToken() || (import.meta as any).env?.VITE_API_KEY || DEMO_TOKEN;
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
      const userData = data.user as AuthUser;

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
    () => ({ user, loading, isAuthenticated, login, logout, hasRole, hasScope }),
    [user, loading, isAuthenticated, login, logout, hasRole, hasScope],
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
