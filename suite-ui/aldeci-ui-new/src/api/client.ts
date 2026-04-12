/**
 * API Client - Base HTTP client with auth, interceptors, and error handling
 * Provides typed request methods and centralized error handling
 */

import type { ApiError } from "./types";

export class ApiClient {
  private baseUrl: string;
  private defaultHeaders: Record<string, string>;
  private authToken?: string;
  private orgId?: string;

  /**
   * Creates a new API client instance
   * @param baseUrl Base URL for API requests (defaults to current origin)
   * @param authToken Optional auth token (API key or JWT)
   * @param orgId Optional organization ID
   */
  constructor(baseUrl?: string, authToken?: string, orgId?: string) {
    this.baseUrl = baseUrl || this.getDefaultBaseUrl();
    this.authToken = authToken || this.getStoredAuthToken();
    this.orgId = orgId || this.getStoredOrgId();
    this.defaultHeaders = {
      "Content-Type": "application/json",
    };
  }

  private getDefaultBaseUrl(): string {
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      return import.meta.env.VITE_API_URL || window.location.origin;
    }
    return import.meta.env.VITE_API_URL || "http://localhost:8000";
  }

  private getStoredAuthToken(): string {
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      return window.localStorage.getItem("aldeci.authToken") || import.meta.env.VITE_API_KEY || "";
    }
    return import.meta.env.VITE_API_KEY || "";
  }

  private getStoredOrgId(): string {
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      return window.localStorage.getItem("aldeci.orgId") || import.meta.env.VITE_ORG_ID || "default";
    }
    return import.meta.env.VITE_ORG_ID || "default";
  }

  /**
   * Set auth token for subsequent requests
   */
  setAuthToken(token: string): void {
    this.authToken = token;
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      window.localStorage.setItem("aldeci.authToken", token);
    }
  }

  /**
   * Set organization ID for subsequent requests
   */
  setOrgId(orgId: string): void {
    this.orgId = orgId;
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      window.localStorage.setItem("aldeci.orgId", orgId);
    }
  }

  /**
   * Clear authentication
   */
  clearAuth(): void {
    this.authToken = undefined;
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      window.localStorage.removeItem("aldeci.authToken");
    }
  }

  /**
   * Build headers for request with auth
   */
  private buildHeaders(): Record<string, string> {
    const headers = { ...this.defaultHeaders };

    if (this.authToken) {
      const strategy = this.getAuthStrategy();
      if (strategy === "jwt") {
        headers.Authorization = this.authToken.toLowerCase().startsWith("bearer ")
          ? this.authToken
          : `Bearer ${this.authToken}`;
      } else {
        headers["X-API-Key"] = this.authToken;
      }
    }

    if (this.orgId) {
      headers["X-Org-ID"] = this.orgId;
    }

    return headers;
  }

  private getAuthStrategy(): "jwt" | "token" {
    if (typeof window !== "undefined" && typeof window.localStorage !== "undefined") {
      const stored = window.localStorage.getItem("aldeci.authStrategy");
      return stored === "jwt" ? "jwt" : "token";
    }
    return import.meta.env.VITE_AUTH_STRATEGY === "jwt" ? "jwt" : "token";
  }

  /**
   * Build full URL from path and optional query params
   */
  private buildUrl(path: string, params?: Record<string, string | number | boolean>): string {
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    const url = new URL(normalizedPath, this.baseUrl);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
          url.searchParams.set(key, String(value));
        }
      });
    }

    return url.toString();
  }

  /**
   * Handle response and throw typed errors
   */
  private async handleResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      const contentType = response.headers.get("content-type");
      let error: ApiError;

      if (contentType?.includes("application/json")) {
        try {
          const data = await response.json();
          error = {
            code: response.status.toString(),
            message: data.message || data.detail || response.statusText,
            details: data.details || data,
          };
        } catch {
          error = {
            code: response.status.toString(),
            message: response.statusText,
          };
        }
      } else {
        const text = await response.text();
        error = {
          code: response.status.toString(),
          message: text || response.statusText,
        };
      }

      // Handle 401 Unauthorized
      if (response.status === 401) {
        this.clearAuth();
        if (typeof window !== "undefined") {
          window.location.hash = "#/login";
        }
      }

      const err = new Error(error.message) as Error & { statusCode?: number; apiError?: ApiError };
      err.statusCode = response.status;
      err.apiError = error;
      throw err;
    }

    const contentType = response.headers.get("content-type");
    if (!contentType?.includes("application/json")) {
      return (await response.text()) as T;
    }

    return response.json();
  }

  /**
   * GET request
   */
  async get<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = this.buildUrl(path, params);
    const response = await fetch(url, {
      method: "GET",
      headers: this.buildHeaders(),
    });
    return this.handleResponse<T>(response);
  }

  /**
   * POST request
   */
  async post<T>(path: string, body?: unknown, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = this.buildUrl(path, params);
    const response = await fetch(url, {
      method: "POST",
      headers: this.buildHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return this.handleResponse<T>(response);
  }

  /**
   * PUT request
   */
  async put<T>(path: string, body?: unknown, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = this.buildUrl(path, params);
    const response = await fetch(url, {
      method: "PUT",
      headers: this.buildHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return this.handleResponse<T>(response);
  }

  /**
   * PATCH request
   */
  async patch<T>(path: string, body?: unknown, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = this.buildUrl(path, params);
    const response = await fetch(url, {
      method: "PATCH",
      headers: this.buildHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });
    return this.handleResponse<T>(response);
  }

  /**
   * DELETE request
   */
  async delete<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T> {
    const url = this.buildUrl(path, params);
    const response = await fetch(url, {
      method: "DELETE",
      headers: this.buildHeaders(),
    });
    return this.handleResponse<T>(response);
  }

  /**
   * GET request with streaming response
   */
  async getStream(path: string, params?: Record<string, string | number | boolean>): Promise<Response> {
    const url = this.buildUrl(path, params);
    const response = await fetch(url, {
      method: "GET",
      headers: this.buildHeaders(),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return response;
  }
}

/**
 * Default singleton instance
 */
let defaultInstance: ApiClient | null = null;

/**
 * Get or create the default API client instance
 */
export function getApiClient(): ApiClient {
  if (!defaultInstance) {
    defaultInstance = new ApiClient();
  }
  return defaultInstance;
}

/**
 * Create a new API client instance with custom config
 */
export function createApiClient(baseUrl?: string, authToken?: string, orgId?: string): ApiClient {
  return new ApiClient(baseUrl, authToken, orgId);
}

/**
 * Reset the default instance (useful for testing)
 */
export function resetApiClient(): void {
  defaultInstance = null;
}
