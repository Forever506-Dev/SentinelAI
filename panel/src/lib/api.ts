/**
 * SentinelAI API Client
 *
 * Centralized API communication layer for the dashboard.
 * 
 * API URL is configurable via NEXT_PUBLIC_API_URL environment variable.
 * Defaults to http://localhost:8000/api/v1 (monolith backend).
 * Set to http://localhost:8080/api/v1 when using the microservice API gateway.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

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
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
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
      // Handle Pydantic validation errors (detail is an array of objects)
      let message: string;
      if (Array.isArray(error.detail)) {
        message = error.detail.map((e: any) => e.msg || JSON.stringify(e)).join("; ");
      } else if (typeof error.detail === "string") {
        message = error.detail;
      } else if (typeof error.detail === "object" && error.detail !== null) {
        message = JSON.stringify(error.detail);
      } else {
        message = `API Error: ${response.status}`;
      }
      throw new Error(message);
    }

    return response.json();
  }

  // --- Auth ---
  async login(username: string, password: string, totpCode?: string) {
    const data = await this.request<{
      access_token: string | null;
      refresh_token: string | null;
      expires_in: number | null;
      requires_2fa?: boolean;
      two_fa_token?: string;
    }>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, totp_code: totpCode || undefined }),
    });

    // If 2FA is required, don't set tokens
    if (data.requires_2fa) {
      return data;
    }

    if (data.access_token) {
      this.setToken(data.access_token);
      if (typeof window !== "undefined" && data.refresh_token) {
        localStorage.setItem("sentinelai_refresh_token", data.refresh_token);
      }
    }
    return data;
  }

  async login2FA(twoFaToken: string, totpCode: string) {
    const data = await this.request<{
      access_token: string;
      refresh_token: string;
      expires_in: number;
    }>("/auth/2fa/login", {
      method: "POST",
      body: JSON.stringify({ two_fa_token: twoFaToken, totp_code: totpCode }),
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

  async forgotPassword(email: string) {
    return this.request<{ message: string }>("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  async resetPassword(email: string, code: string, newPassword: string) {
    return this.request<{ message: string }>("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ email, code, new_password: newPassword }),
    });
  }

  async changePassword(currentPassword: string, newPassword: string) {
    return this.request<{ message: string }>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    });
  }

  async getProfile() {
    return this.request<{
      id: string;
      email: string;
      username: string;
      full_name: string | null;
      role: string;
      is_active: boolean;
      totp_enabled: boolean;
    }>("/auth/me");
  }

  // --- 2FA Setup ---
  async setup2FA() {
    return this.request<{
      secret: string;
      provisioning_uri: string;
      qr_code_base64: string;
    }>("/auth/2fa/setup", { method: "POST" });
  }

  async verify2FA(code: string) {
    return this.request<{ message: string }>("/auth/2fa/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  }

  async disable2FA(code: string) {
    return this.request<{ message: string }>("/auth/2fa/disable", {
      method: "DELETE",
      body: JSON.stringify({ code }),
    });
  }

  // --- Dashboard ---
  async getDashboardStats() {
    return this.request<{
      agents: { total: number; online: number; isolated: number; os_distribution: Record<string, number> };
      alerts: { active: number; critical: number; last_24h: number; severity_breakdown: Record<string, number> };
      telemetry: { events_last_hour: number };
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
    return this.request<{ agents: Agent[]; total: number }>(`/agents?${query}`);
  }

  async getAgent(id: string) {
    return this.request<Agent>(`/agents/${id}`);
  }

  async sendAgentCommand(id: string, command: string, params: Record<string, unknown> = {}) {
    return this.request<CommandResponse>(`/agents/${id}/command`, {
      method: "POST",
      body: JSON.stringify({ command, parameters: params }),
    });
  }

  async decommissionAgent(id: string) {
    return this.request<{ status: string }>(`/agents/${id}`, {
      method: "DELETE",
    });
  }

  // --- Alerts ---
  async getAlerts(params?: { page?: number; severity?: string; status?: string }) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.severity) query.set("severity", params.severity);
    if (params?.status) query.set("status", params.status);
    return this.request<{ alerts: Alert[]; total: number }>(`/alerts?${query}`);
  }

  async updateAlert(id: string, data: { status?: string; assigned_to?: string }) {
    return this.request<Alert>(`/alerts/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  }

  async triggerAlertAnalysis(id: string) {
    return this.request<{ status: string }>(`/alerts/${id}/analyze`, {
      method: "POST",
    });
  }

  // --- AI Analysis ---
  async investigate(query: string, context: Record<string, unknown> = {}) {
    return this.request<{
      status: string;
      analysis: string;
      confidence: number;
      recommendations: string[];
      related_techniques: string[];
      sources: string[];
    }>("/analysis/investigate", {
      method: "POST",
      body: JSON.stringify({ query, context }),
    });
  }

  async analyzeShellOutput(agentId: string, command: string, output: string) {
    return this.request<ShellAnalysisResult>("/analysis/shell-output", {
      method: "POST",
      body: JSON.stringify({ agent_id: agentId, command, output }),
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

  // --- OSINT Tools ---
  async osintWhois(target: string) {
    return this.request<Record<string, unknown>>("/osint/whois", {
      method: "POST",
      body: JSON.stringify({ target }),
    });
  }

  async osintNslookup(domain: string, recordType: string = "A") {
    return this.request<Record<string, unknown>>("/osint/nslookup", {
      method: "POST",
      body: JSON.stringify({ domain, record_type: recordType }),
    });
  }

  async osintIpLookup(ip: string) {
    return this.request<Record<string, unknown>>("/osint/ip-lookup", {
      method: "POST",
      body: JSON.stringify({ ip }),
    });
  }

  async osintHttpCheck(url: string) {
    return this.request<Record<string, unknown>>("/osint/http-check", {
      method: "POST",
      body: JSON.stringify({ url }),
    });
  }

  // --- Remediation / Firewall ---
  async getFirewallRules(agentId: string) {
    return this.request<FirewallRulesResponse>(`/remediation/${agentId}/rules`);
  }

  async addFirewallRule(agentId: string, rule: AddFirewallRuleRequest) {
    return this.request<RemediationResponse>(`/remediation/${agentId}/rules`, {
      method: "POST",
      body: JSON.stringify(rule),
    });
  }

  async deleteFirewallRule(agentId: string, rule: DeleteFirewallRuleRequest) {
    return this.request<RemediationResponse>(`/remediation/${agentId}/rules/delete`, {
      method: "POST",
      body: JSON.stringify(rule),
    });
  }

  async editFirewallRule(agentId: string, rule: EditFirewallRuleRequest) {
    return this.request<RemediationResponse>(`/remediation/${agentId}/rules/edit`, {
      method: "POST",
      body: JSON.stringify(rule),
    });
  }

  async blockIP(agentId: string, ip: string, direction: string = "inbound", reason: string = "") {
    return this.request<RemediationResponse>(`/remediation/${agentId}/block-ip`, {
      method: "POST",
      body: JSON.stringify({ ip, direction, reason }),
    });
  }

  async blockPort(agentId: string, port: string, protocol: string = "tcp", direction: string = "inbound", reason: string = "") {
    return this.request<RemediationResponse>(`/remediation/${agentId}/block-port`, {
      method: "POST",
      body: JSON.stringify({ port, protocol, direction, reason }),
    });
  }

  async getRemediationHistory(params?: { agent_id?: string; action_type?: string; page?: number }) {
    const query = new URLSearchParams();
    if (params?.agent_id) query.set("agent_id", params.agent_id);
    if (params?.action_type) query.set("action_type", params.action_type);
    if (params?.page) query.set("page", String(params.page));
    return this.request<RemediationHistoryResponse>(`/remediation/history?${query}`);
  }

  // --- Firewall Management (Phase 1) ---
  async getTrackedFirewallRules(agentId: string, params?: TrackedRulesFilterParams) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.search) query.set("search", params.search);
    if (params?.direction) query.set("direction", params.direction);
    if (params?.action) query.set("action", params.action);
    if (params?.enabled) query.set("enabled", params.enabled);
    if (params?.profile) query.set("profile", params.profile);
    if (params?.sort_by) query.set("sort_by", params.sort_by);
    if (params?.sort_dir) query.set("sort_dir", params.sort_dir);
    return this.request<TrackedFirewallRulesResponse>(`/firewall/${agentId}/rules?${query}`);
  }

  async createTrackedFirewallRule(agentId: string, rule: CreateTrackedRuleRequest) {
    return this.request<TrackedFirewallRuleResponse>(`/firewall/${agentId}/rules`, {
      method: "POST",
      body: JSON.stringify(rule),
    });
  }

  async editTrackedFirewallRule(agentId: string, ruleId: string, rule: EditTrackedRuleRequest) {
    return this.request<TrackedFirewallRuleResponse>(`/firewall/${agentId}/rules/${ruleId}`, {
      method: "PUT",
      body: JSON.stringify(rule),
    });
  }

  async deleteTrackedFirewallRule(agentId: string, ruleId: string) {
    return this.request<{ status: string }>(`/firewall/${agentId}/rules/${ruleId}`, {
      method: "DELETE",
    });
  }

  async toggleFirewallRule(agentId: string, ruleId: string, enabled: boolean) {
    return this.request<TrackedFirewallRuleResponse>(`/firewall/${agentId}/rules/${ruleId}/toggle`, {
      method: "POST",
      body: JSON.stringify({ enabled }),
    });
  }

  async snapshotFirewallRules(agentId: string) {
    return this.request<FirewallSnapshotResponse>(`/firewall/${agentId}/snapshot`, {
      method: "POST",
    });
  }

  async getFirewallPolicies() {
    return this.request<FirewallPoliciesResponse>(`/firewall/policies`);
  }

  async createFirewallPolicy(policy: CreateFirewallPolicyRequest) {
    return this.request<FirewallPolicyResponse>(`/firewall/policies`, {
      method: "POST",
      body: JSON.stringify(policy),
    });
  }

  // --- Approvals ---
  async getPendingApprovalCount() {
    return this.request<{ pending_count: number }>(`/approvals/pending/count`);
  }

  async getPendingApprovals() {
    return this.request<PendingApprovalsResponse>(`/approvals/pending`);
  }

  async decideApproval(approvalId: string, decision: ApprovalDecision) {
    return this.request<ApprovalResponse>(`/approvals/${approvalId}/decide`, {
      method: "POST",
      body: JSON.stringify(decision),
    });
  }

  async getApprovalHistory(params?: { page?: number; page_size?: number }) {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    return this.request<ApprovalHistoryResponse>(`/approvals/history?${query}`);
  }
}

// Export singleton instance
export const api = new ApiClient();

// --- Types ---
export interface Agent {
  id: string;
  hostname: string;
  display_name: string | null;
  os_type: string;
  os_version: string;
  architecture: string;
  status: string;
  is_isolated: boolean;
  cpu_usage: number | null;
  memory_usage: number | null;
  disk_usage: number | null;
  uptime_seconds: number | null;
  internal_ip: string | null;
  external_ip: string | null;
  agent_version: string;
  last_heartbeat: string | null;
  registered_at: string;
  tags: Record<string, unknown> | null;
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
  llm_recommendation: string | null;
  detected_at: string;
  agent_id: string;
}

export interface CommandResponse {
  command_id: string;
  agent_id: string;
  command: string;
  status: string;
  output: string;
  data?: Record<string, unknown> | null;
  exit_code?: number | null;
}

export interface ShellFinding {
  title: string;
  severity: string;
  description: string;
  mitre_technique?: string;
  evidence?: string;
}

export interface ShellAnalysisResult {
  status: string;
  agent_id: string;
  command: string;
  summary: string;
  risk_level: string;
  findings: ShellFinding[];
  recommendations: string[];
  mitre_techniques: string[];
  confidence: number;
}

// --- Remediation / Firewall Types ---
export interface FirewallRulesResponse {
  agent_id: string;
  hostname: string;
  os_type: string;
  status: string;
  output: string;
  rules: Record<string, unknown>[];
  total: number;
}

export interface RemediationResponse {
  remediation_id: string;
  agent_id: string;
  status: string;
  output: string;
}

export interface AddFirewallRuleRequest {
  name: string;
  direction: "inbound" | "outbound";
  action: "allow" | "block";
  protocol: "tcp" | "udp" | "any" | "icmp";
  port: string;
  remote_address: string;
  profiles?: string[];
  reason: string;
}

export interface DeleteFirewallRuleRequest {
  name: string;
  chain?: string;
  rule_number?: number;
  protocol?: string;
  port?: string;
  remote_address?: string;
  action?: string;
  reason?: string;
}

export interface EditFirewallRuleRequest {
  name: string;
  direction?: string;
  action?: string;
  protocol?: string;
  port?: string;
  remote_address?: string;
  profiles?: string[];
  reason?: string;
}

export interface RemediationActionRecord {
  id: string;
  agent_id: string;
  action_type: string;
  rule_name: string | null;
  direction: string | null;
  action: string | null;
  protocol: string | null;
  port: string | null;
  remote_address: string | null;
  status: string;
  result_output: string | null;
  error_message: string | null;
  reason: string | null;
  created_at: string | null;
  applied_at: string | null;
}

export interface RemediationHistoryResponse {
  actions: RemediationActionRecord[];
  total: number;
  page: number;
  page_size: number;
}

// --- Firewall Management Types (Phase 1) ---
export interface TrackedFirewallRule {
  id: string;
  agent_id: string;
  name: string;
  direction: string;
  action: string;
  protocol: string;
  port: string | null;
  remote_address: string | null;
  enabled: boolean;
  profile: string;
  profiles: string[];
  policy_id: string | null;
  synced_at: string | null;
  drift_detected: boolean;
  current_version: number;
  created_at: string;
}

export interface TrackedFirewallRulesResponse {
  rules: TrackedFirewallRule[];
  total: number;
  page: number;
  page_size: number;
  filters_applied: Record<string, string>;
}

export interface TrackedRulesFilterParams {
  page?: number;
  page_size?: number;
  search?: string;
  direction?: string;
  action?: string;
  enabled?: string;
  profile?: string;
  sort_by?: string;
  sort_dir?: string;
}

export interface TrackedFirewallRuleResponse {
  rule: TrackedFirewallRule;
  approval_required?: boolean;
  approval_id?: string;
}

export interface CreateTrackedRuleRequest {
  name: string;
  direction: "inbound" | "outbound";
  action: "block" | "allow";
  protocol: "tcp" | "udp" | "any" | "icmp";
  port?: string;
  remote_address?: string;
  enabled?: boolean;
  profile?: string;
  profiles?: string[];
}

export interface EditTrackedRuleRequest {
  name?: string;
  direction?: string;
  action?: string;
  protocol?: string;
  port?: string;
  remote_address?: string;
  enabled?: boolean;
  profile?: string;
  profiles?: string[];
  reason?: string;
}

export interface FirewallSnapshotResponse {
  agent_id: string;
  status: string;
  rules_count: number;
  drift_count: number;
  snapshot_at: string;
}

export interface FirewallPolicy {
  id: string;
  name: string;
  description: string | null;
  rules: Record<string, unknown>[];
  default_inbound_action: string;
  default_outbound_action: string;
  assigned_agent_count: number;
  created_at: string;
}

export interface FirewallPoliciesResponse {
  policies: FirewallPolicy[];
  total: number;
}

export interface FirewallPolicyResponse {
  policy: FirewallPolicy;
}

export interface CreateFirewallPolicyRequest {
  name: string;
  description?: string;
  rules?: Record<string, unknown>[];
  default_inbound_action?: string;
  default_outbound_action?: string;
}

// --- Approval Types ---
export interface Approval {
  id: string;
  remediation_id: string | null;
  requested_by: string | null;
  approved_by: string | null;
  status: "pending" | "approved" | "rejected" | "expired" | "auto_approved";
  request_reason: string | null;
  approval_note: string | null;
  expires_at: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface PendingApproval extends Approval {
  agent_hostname?: string;
  agent_id?: string;
  action_type?: string;
  requester_username?: string;
  rule_name?: string;
  direction?: string;
  protocol?: string;
  port?: string;
  remote_address?: string;
}

export interface PendingApprovalsResponse {
  approvals: PendingApproval[];
  total: number;
}

export interface ApprovalDecision {
  decision: "approve" | "reject";
  note?: string;
}

export interface ApprovalResponse {
  approval: Approval;
}

export interface ApprovalHistoryResponse {
  approvals: Approval[];
  total: number;
  page: number;
  page_size: number;
}
