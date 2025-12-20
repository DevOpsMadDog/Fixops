/**
 * FixOps API Client Configuration
 * 
 * Handles API base URL resolution and environment detection.
 */

export type SystemMode = 'demo' | 'enterprise';

export interface ApiConfig {
  baseUrl: string;
  apiKey?: string;
  mode: SystemMode;
}

/**
 * Get the API base URL from environment or default.
 * 
 * Priority:
 * 1. NEXT_PUBLIC_FIXOPS_API_URL environment variable
 * 2. Window location origin (for same-origin deployments)
 * 3. Default localhost for development
 */
export function getApiBaseUrl(): string {
  // Check for explicit environment variable
  if (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_FIXOPS_API_URL) {
    return process.env.NEXT_PUBLIC_FIXOPS_API_URL;
  }
  
  // Check for window-based config (set by deployment)
  if (typeof window !== 'undefined') {
    // Check for runtime config
    const runtimeConfig = (window as any).__FIXOPS_CONFIG__;
    if (runtimeConfig?.apiUrl) {
      return runtimeConfig.apiUrl;
    }
  }
  
  // Default to localhost for development
  return 'http://127.0.0.1:8000';
}

/**
 * Get the API key from environment or storage.
 */
export function getApiKey(): string | undefined {
  // Check for environment variable
  if (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_FIXOPS_API_KEY) {
    return process.env.NEXT_PUBLIC_FIXOPS_API_KEY;
  }
  
  // Check for stored token in localStorage
  if (typeof window !== 'undefined') {
    const storedKey = localStorage.getItem('fixops_api_key');
    if (storedKey) {
      return storedKey;
    }
  }
  
  // Default demo token for demo mode
  return 'demo-token';
}

/**
 * Get the current system mode.
 */
export function getSystemMode(): SystemMode {
  // Check for environment variable with validation
  if (typeof process !== 'undefined' && process.env?.NEXT_PUBLIC_FIXOPS_MODE) {
    const envMode = process.env.NEXT_PUBLIC_FIXOPS_MODE;
    if (envMode === 'demo' || envMode === 'enterprise') {
      return envMode;
    }
  }
  
  // Check for stored mode in localStorage
  if (typeof window !== 'undefined') {
    const storedMode = localStorage.getItem('fixops_mode');
    if (storedMode === 'demo' || storedMode === 'enterprise') {
      return storedMode;
    }
  }
  
  // Default to demo mode
  return 'demo';
}

/**
 * Set the system mode.
 */
export function setSystemMode(mode: SystemMode): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('fixops_mode', mode);
  }
}

/**
 * Get the full API configuration.
 */
export function getApiConfig(): ApiConfig {
  return {
    baseUrl: getApiBaseUrl(),
    apiKey: getApiKey(),
    mode: getSystemMode(),
  };
}
