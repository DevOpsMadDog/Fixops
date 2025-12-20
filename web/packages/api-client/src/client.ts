/**
 * FixOps API Client
 * 
 * A unified fetch wrapper for all FixOps API calls.
 */

import { getApiBaseUrl, getApiKey, getSystemMode, SystemMode } from './config';

export interface ApiError {
  status: number;
  message: string;
  detail?: string;
}

export interface ApiResponse<T> {
  data: T | null;
  error: ApiError | null;
  loading: boolean;
}

export interface FetchOptions extends RequestInit {
  params?: Record<string, string | number | boolean | undefined>;
}

/**
 * Build URL with query parameters.
 */
function buildUrl(baseUrl: string, path: string, params?: Record<string, string | number | boolean | undefined>): string {
  const url = new URL(path, baseUrl);
  
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        url.searchParams.append(key, String(value));
      }
    });
  }
  
  return url.toString();
}

/**
 * Main fetch wrapper for FixOps API.
 */
export async function fetchApi<T>(
  path: string,
  options: FetchOptions = {}
): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const apiKey = getApiKey();
  const { params, ...fetchOptions } = options;
  
  const url = buildUrl(baseUrl, path, params);
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
    ...options.headers,
  };
  
  const response = await fetch(url, {
    ...fetchOptions,
    headers,
  });
  
  if (!response.ok) {
    let errorMessage = `API Error: ${response.status}`;
    let detail: string | undefined;
    
    try {
      const errorData = await response.json();
      errorMessage = errorData.message || errorData.detail || errorMessage;
      detail = errorData.detail;
    } catch {
      // Ignore JSON parse errors
    }
    
    const error: ApiError = {
      status: response.status,
      message: errorMessage,
      detail,
    };
    
    throw error;
  }
  
  // Handle empty responses
  const contentType = response.headers.get('content-type');
  if (!contentType || !contentType.includes('application/json')) {
    return {} as T;
  }
  
  return response.json();
}

/**
 * Download a file from the API.
 */
export async function downloadFile(
  path: string,
  filename: string,
  options: FetchOptions = {}
): Promise<void> {
  const baseUrl = getApiBaseUrl();
  const apiKey = getApiKey();
  const { params, ...fetchOptions } = options;
  
  const url = buildUrl(baseUrl, path, params);
  
  const headers: HeadersInit = {
    ...(apiKey ? { 'X-API-Key': apiKey } : {}),
    ...options.headers,
  };
  
  const response = await fetch(url, {
    ...fetchOptions,
    headers,
  });
  
  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }
  
  const blob = await response.blob();
  const downloadUrl = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = downloadUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(downloadUrl);
}

/**
 * API client class for more complex operations.
 * Uses instance properties for baseUrl and apiKey to allow custom configuration.
 */
export class FixOpsApiClient {
  private baseUrl: string;
  private apiKey: string | undefined;
  
  constructor(baseUrl?: string, apiKey?: string) {
    this.baseUrl = baseUrl || getApiBaseUrl();
    this.apiKey = apiKey || getApiKey();
  }

  /**
   * Internal fetch method that uses instance properties.
   */
  private async fetchWithConfig<T>(
    path: string,
    options: FetchOptions = {}
  ): Promise<T> {
    const { params, ...fetchOptions } = options;
    const url = buildUrl(this.baseUrl, path, params);
    
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
      ...options.headers,
    };
    
    const response = await fetch(url, {
      ...fetchOptions,
      headers,
    });
    
    if (!response.ok) {
      let errorMessage = `API Error: ${response.status}`;
      let detail: string | undefined;
      
      try {
        const errorData = await response.json();
        errorMessage = errorData.message || errorData.detail || errorMessage;
        detail = errorData.detail;
      } catch {
        // Ignore JSON parse errors
      }
      
      const error: ApiError = {
        status: response.status,
        message: errorMessage,
        detail,
      };
      
      throw error;
    }
    
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      return {} as T;
    }
    
    return response.json();
  }

  /**
   * Internal download method that uses instance properties.
   */
  private async downloadWithConfig(
    path: string,
    filename: string,
    options: FetchOptions = {}
  ): Promise<void> {
    const { params, ...fetchOptions } = options;
    const url = buildUrl(this.baseUrl, path, params);
    
    const headers: HeadersInit = {
      ...(this.apiKey ? { 'X-API-Key': this.apiKey } : {}),
      ...options.headers,
    };
    
    const response = await fetch(url, {
      ...fetchOptions,
      headers,
    });
    
    if (!response.ok) {
      throw new Error(`Download failed: ${response.status}`);
    }
    
    const blob = await response.blob();
    const downloadUrl = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = downloadUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(downloadUrl);
  }
  
  async get<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.fetchWithConfig<T>(path, { method: 'GET', params });
  }
  
  async post<T>(path: string, body?: unknown, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.fetchWithConfig<T>(path, {
      method: 'POST',
      body: body ? JSON.stringify(body) : undefined,
      params,
    });
  }
  
  async put<T>(path: string, body?: unknown, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.fetchWithConfig<T>(path, {
      method: 'PUT',
      body: body ? JSON.stringify(body) : undefined,
      params,
    });
  }
  
  async delete<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
    return this.fetchWithConfig<T>(path, { method: 'DELETE', params });
  }
  
  async download(path: string, filename: string, params?: Record<string, string | number | boolean | undefined>): Promise<void> {
    return this.downloadWithConfig(path, filename, { params });
  }
  
  /**
   * Get current system mode.
   */
  getMode(): SystemMode {
    return getSystemMode();
  }
}

// Singleton instance
let clientInstance: FixOpsApiClient | null = null;

export function getApiClient(): FixOpsApiClient {
  if (!clientInstance) {
    clientInstance = new FixOpsApiClient();
  }
  return clientInstance;
}
