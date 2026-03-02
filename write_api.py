import pathlib

content = """/**
 * SentinelAI API Client
 *
 * Centralized API communication layer for the dashboard.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1";

class ApiClient {
  private token: string | null = null;

  constructor() {
    if (typeof window !== "undefined") {
      this.token = localStorage.getItem("sentinelai_token");
    }
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof window !== "undefined") {
      if (token) {
        localStorage.setItem("sentinelai_token", token);
      } else {
        localStorage.removeItem("sentinelai_token");
      }
    }
  }

  getToken(): string | null {
    return this.token;
  }

  clearToken() {
    this.setToken(null);
    if (typeof window !== "undefined") {
      localStorage.removeItem("sentinelai_refresh_token");
    }
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers["Authorization"] = BTICK + "Bearer ${this.token}" + BTICK;
    }

    const response = await fetch(BTICK + "${API_BASE}${endpoint}" + BTICK, {
      ...options,
      headers,
    });

    if (!response.ok) {
      if (response.status === 401) {
        this.clearToken();
        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }
      }
      const error = await response.json().catch(() => ({ detail: "Unknown error" }));
      throw new Error(error.detail || BTICK + "API Error: ${response.status}" + BTICK);
    }

    return response.json();
  }

  // --- Auth ---
  async login(username: string, password: string) {
    const data = await this.request<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    this.setToken(data.access_token);
    if (typeof window !== "undefined") {
      localStorage.setItem("sentinelai_refresh_token", data.refresh_token);
    }
    return data;
  }

  async register(username: string, email: string, password: string, fullName?: string) {
    return this.request<{
      id: string;
      email: string;
      username: string;
      full_name: string | null;
      role: string;
    }>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, email, password, full_name: fullName }),
    });
  }

  // --- Dashboard ---
  async getDashboardStats() {
    return this.request<{
      agents: { total: number; online: number; isolated: number };
      alerts: { active: number; critical: number; last_24h: number };
    }>("/dashboard/stats");
  }

  async getRecentAlerts() {
    return this.request<{ alerts: Alert[] }>("/dashboard/recent-alerts");
  }

  // --- Agents ---
  async getAgents(params?: { page?: number; status?: string; search?: string }) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.status) query.set("status", params.status);
    if (params?.search) query.set("search", params.search);
    return this.request<{ agents: Agent[]; total: number }>(BTICK + "/agents?${query}" + BTICK);
  }

  async getAgent(id: string) {
    return this.request<Agent>(BTICK + "/agents/${id}" + BTICK);
  }

  async sendAgentCommand(id: string, command: string, params: Record<string, unknown> = {}) {
    return this.request<{ status: string }>(BTICK + "/agents/${id}/command" + BTICK, {
      method: "POST",
      body: JSON.stringify({ command, parameters: params }),
    });
  }

  // --- Alerts ---
  async getAlerts(params?: { page?: number; severity?: string; status?: string }) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.severity) query.set("severity", params.severity);
    if (params?.status) query.set("status", params.status);
    return this.request<{ alerts: Alert[]; total: number }>(BTICK + "/alerts?${query}" + BTICK);
  }

  async updateAlert(id: string, data: { status?: string; assigned_to?: string }) {
    return this.request<Alert>(BTICK + "/alerts/${id}" + BTICK, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  }

  async triggerAlertAnalysis(id: string) {
    return this.request<{ status: string }>(BTICK + "/alerts/${id}/analyze" + BTICK, {
      method: "POST",
    });
  }

  // --- AI Analysis ---
  async investigate(query: string, context: Record<string, unknown> = {}) {
    return this.request<{
      analysis: string;
      confidence: number;
      recommendations: string[];
      related_techniques: string[];
    }>("/analysis/investigate", {
      method: "POST",
      body: JSON.stringify({ query, context }),
    });
  }

  async threatLookup(type: string, value: string) {
    return this.request<{
      threat_level: string;
      details: Record<string, unknown>;
      recommendations: string[];
    }>("/analysis/threat-lookup", {
      method: "POST",
      body: JSON.stringify({ indicator_type: type, indicator_value: value }),
    });
  }
}

// Export singleton instance
export const api = new ApiClient();

// --- Types ---
export interface Agent {
  id: string;
  hostname: string;
  os_type: string;
  os_version: string;
  status: string;
  is_isolated: boolean;
  cpu_usage: number | null;
  memory_usage: number | null;
  disk_usage: number | null;
  internal_ip: string | null;
  external_ip: string | null;
  agent_version: string;
  last_heartbeat: string | null;
  registered_at: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  status: string;
  detection_source: string;
  mitre_tactics: string[] | null;
  mitre_techniques: string[] | null;
  llm_analysis: string | null;
  detected_at: string;
  agent_id: string;
}
"""

BT = chr(96)  # backtick character
content = content.replace("BTICK + \"", BT).replace("\" + BTICK", BT).replace("BTICK", BT)
pathlib.Path(r"F:\SentinelAI\panel\src\lib\api.ts").write_text(content, encoding="utf-8")
print("Done")
