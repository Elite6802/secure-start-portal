const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:18080";
const ACCESS_TOKEN_KEY = "aegis_access_token";
export const API_BASE_URL = API_BASE;

function extractApiErrorMessage(data: unknown): string {
  if (!data || typeof data !== "object") return "Request failed";
  const asRecord = data as Record<string, unknown>;
  const detail = asRecord.detail;
  if (typeof detail === "string" && detail && detail !== "Validation error.") {
    return detail;
  }

  const errors = asRecord.errors;
  if (errors && typeof errors === "object") {
    const errRecord = errors as Record<string, unknown>;
    for (const [field, value] of Object.entries(errRecord)) {
      if (Array.isArray(value) && value.length > 0 && typeof value[0] === "string") {
        return `${field}: ${value[0]}`;
      }
      if (typeof value === "string" && value) {
        return `${field}: ${value}`;
      }
    }
  }

  if (typeof detail === "string" && detail) {
    return detail;
  }
  return JSON.stringify(data);
}

export type PaginatedResponse<T> = {
  results: T[];
  count?: number;
  next?: string | null;
  previous?: string | null;
};

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function setAccessToken(token: string | null) {
  if (token) {
    localStorage.setItem(ACCESS_TOKEN_KEY, token);
  } else {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
  }
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getAccessToken();
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    setAccessToken(null);
    const isAuthEndpoint = path.startsWith("/auth/login/") || path.startsWith("/auth/refresh/");
    if (!isAuthEndpoint) {
      const inAdmin = window.location.pathname.startsWith("/admin");
      const target = inAdmin ? "/admin/login" : "/login";
      if (window.location.pathname !== target) {
        window.location.assign(target);
      }
    }
    throw new Error("Unauthorized");
  }

  if (!response.ok) {
    let message = "Request failed";
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const data = await response.json();
      message = extractApiErrorMessage(data);
    } else {
      const text = await response.text();
      if (text) message = text;
    }
    throw new Error(message);
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json() as Promise<T>;
}

export async function downloadFile(path: string, filename: string) {
  const token = getAccessToken();
  const headers = new Headers();
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE}${path}`, { headers });

  if (response.status === 401) {
    setAccessToken(null);
    const isAuthEndpoint = path.startsWith("/auth/login/") || path.startsWith("/auth/refresh/");
    if (!isAuthEndpoint) {
      const inAdmin = window.location.pathname.startsWith("/admin");
      const target = inAdmin ? "/admin/login" : "/login";
      if (window.location.pathname !== target) {
        window.location.assign(target);
      }
    }
    throw new Error("Unauthorized");
  }

  if (!response.ok) {
    let message = "Download failed";
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      const data = await response.json();
      message = data?.detail || JSON.stringify(data);
    } else {
      const text = await response.text();
      if (text) message = text;
    }
    throw new Error(message);
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export function unwrapResults<T>(data: unknown): T[] {
  if (data && typeof data === "object" && Array.isArray((data as PaginatedResponse<T>).results)) {
    return (data as PaginatedResponse<T>).results;
  }
  return Array.isArray(data) ? (data as T[]) : [];
}

export async function login(username: string, password: string) {
  const payload = await apiRequest<{ access: string; refresh: string }>("/auth/login/", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  setAccessToken(payload.access);
  return payload;
}

export async function getMe() {
  return apiRequest("/auth/me/");
}
