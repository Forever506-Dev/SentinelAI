"use client";

import { useState, useEffect } from "react";
import { Settings, Server, Shield, Wrench, RefreshCw, CheckCircle, XCircle, Loader2, Activity, Database, Cpu, Globe } from "lucide-react";
import { api } from "@/lib/api";

type Tab = "general" | "integrations" | "system" | "devtools";

interface HealthStatus {
  status: string;
  version?: string;
  services?: Record<string, string>;
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>("general");
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [ollamaStatus, setOllamaStatus] = useState<string>("unknown");
  const [ollamaLoading, setOllamaLoading] = useState(false);

  const tabs: { id: Tab; label: string; icon: typeof Settings }[] = [
    { id: "general", label: "General", icon: Settings },
    { id: "integrations", label: "Integrations", icon: Globe },
    { id: "system", label: "System", icon: Server },
    { id: "devtools", label: "Dev Tools", icon: Wrench },
  ];

  const checkHealth = async () => {
    setHealthLoading(true);
    try {
      const baseUrl = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080").replace(/\/api\/v\d+$/, "");
      const res = await fetch(baseUrl + "/health");
      const data = await res.json();
      setHealth(data);
    } catch {
      setHealth({ status: "unreachable" });
    } finally {
      setHealthLoading(false);
    }
  };

  const checkOllama = async () => {
    setOllamaLoading(true);
    try {
      const res = await fetch((process.env.NEXT_PUBLIC_OLLAMA_URL || "http://localhost:11434") + "/api/tags");
      if (res.ok) {
        const data = await res.json();
        const models = (data.models || []).map((m: { name: string }) => m.name);
        setOllamaStatus("online (" + models.length + " models: " + models.join(", ") + ")");
      } else {
        setOllamaStatus("error (HTTP " + res.status + ")");
      }
    } catch {
      setOllamaStatus("offline");
    } finally {
      setOllamaLoading(false);
    }
  };

  useEffect(() => {
    checkHealth();
    checkOllama();
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Settings className="w-6 h-6 text-sentinel-400" />
          Settings
        </h1>
        <p className="text-sm text-cyber-muted mt-1">Platform configuration and diagnostics</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 bg-cyber-surface p-1 rounded-lg border border-cyber-border w-fit">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={
              "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all " +
              (activeTab === tab.id
                ? "bg-sentinel-600 text-white shadow-lg shadow-sentinel-600/20"
                : "text-cyber-muted hover:text-white hover:bg-cyber-hover")
            }
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="card-cyber">
        {activeTab === "general" && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold text-white">General Settings</h3>
            <div className="grid gap-4">
              <div>
                <label className="block text-sm text-cyber-muted mb-1.5">API Endpoint</label>
                <input
                  type="text"
                  defaultValue={process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1"}
                  className="input-terminal"
                  readOnly
                />
              </div>
              <div>
                <label className="block text-sm text-cyber-muted mb-1.5">WebSocket Endpoint</label>
                <input
                  type="text"
                  defaultValue={(process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1").replace(/^http/, "ws") + "/dashboard/ws/live"}
                  className="input-terminal"
                  readOnly
                />
              </div>
              <div>
                <label className="block text-sm text-cyber-muted mb-1.5">Panel Version</label>
                <span className="text-sm text-white">v0.1.0 (Next.js 16 + React 19)</span>
              </div>
            </div>
          </div>
        )}

        {activeTab === "integrations" && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold text-white">Integrations</h3>

            {/* Ollama */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-3">
                  <Cpu className="w-5 h-5 text-sentinel-400" />
                  <div>
                    <h4 className="text-sm font-medium text-white">Ollama LLM</h4>
                    <p className="text-xs text-cyber-muted">Local AI inference engine</p>
                  </div>
                </div>
                <button onClick={checkOllama} disabled={ollamaLoading} className="btn-secondary text-xs flex items-center gap-1.5 px-3 py-1.5">
                  {ollamaLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                  Test
                </button>
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-cyber-muted">URL:</span>
                  <span className="text-white ml-2">{process.env.NEXT_PUBLIC_OLLAMA_URL || "http://localhost:11434"}</span>
                </div>
                <div>
                  <span className="text-cyber-muted">Model:</span>
                  <span className="text-white ml-2">{process.env.NEXT_PUBLIC_OLLAMA_MODEL || "bjoernb/claude-opus-4-5"}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-cyber-muted">Status:</span>
                  <span className={"ml-2 " + (ollamaStatus.startsWith("online") ? "text-green-400" : ollamaStatus === "unknown" ? "text-yellow-400" : "text-red-400")}>
                    {ollamaStatus}
                  </span>
                </div>
              </div>
            </div>

            {/* Database */}
            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4">
              <div className="flex items-center gap-3">
                <Database className="w-5 h-5 text-blue-400" />
                <div>
                  <h4 className="text-sm font-medium text-white">PostgreSQL</h4>
                  <p className="text-xs text-cyber-muted">{process.env.NEXT_PUBLIC_DB_HOST || "localhost:5432/sentinelai"}</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === "system" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">System Health</h3>
              <button onClick={checkHealth} disabled={healthLoading} className="btn-secondary text-xs flex items-center gap-1.5 px-3 py-1.5">
                {healthLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                Refresh
              </button>
            </div>

            {health ? (
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-4 bg-cyber-bg rounded-lg border border-cyber-border">
                  {health.status === "healthy" ? (
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                  <div>
                    <p className="text-sm font-medium text-white">Backend: {health.status}</p>
                    {health.version && <p className="text-xs text-cyber-muted">Version: {health.version}</p>}
                  </div>
                </div>
                {health.services && Object.entries(health.services).map(([svc, status]) => (
                  <div key={svc} className="flex items-center gap-3 px-4 py-3 bg-cyber-bg rounded-lg border border-cyber-border">
                    {status === "connected" || status === "healthy" ? (
                      <CheckCircle className="w-4 h-4 text-green-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400" />
                    )}
                    <span className="text-sm text-white capitalize">{svc}</span>
                    <span className="text-xs text-cyber-muted ml-auto">{status}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-cyber-muted">Loading health data...</p>
            )}
          </div>
        )}

        {activeTab === "devtools" && (
          <div className="space-y-6">
            <h3 className="text-lg font-semibold text-white">Developer Tools</h3>
            <div className="space-y-4">
              <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4">
                <h4 className="text-sm font-medium text-white mb-2">JWT Token</h4>
                <pre className="text-xs text-cyber-muted bg-black/30 p-3 rounded-lg overflow-x-auto break-all">
                  {typeof window !== "undefined" ? localStorage.getItem("sentinel_token") || "No token" : "SSR"}
                </pre>
              </div>
              <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4">
                <h4 className="text-sm font-medium text-white mb-2">Quick API Test</h4>
                <div className="flex gap-2">
                  <button
                    onClick={async () => {
                      try {
                        const data = await api.getDashboardStats();
                        alert("Dashboard Stats:\n" + JSON.stringify(data, null, 2));
                      } catch (err: any) {
                        alert("Error: " + err.message);
                      }
                    }}
                    className="btn-secondary text-xs px-3 py-1.5"
                  >
                    Test Dashboard API
                  </button>
                  <button
                    onClick={async () => {
                      try {
                        const data = await api.getAgents();
                        alert("Agents:\n" + JSON.stringify(data, null, 2));
                      } catch (err: any) {
                        alert("Error: " + err.message);
                      }
                    }}
                    className="btn-secondary text-xs px-3 py-1.5"
                  >
                    Test Agents API
                  </button>
                </div>
              </div>
              <div className="bg-cyber-bg border border-cyber-border rounded-lg p-4">
                <h4 className="text-sm font-medium text-white mb-2">Environment</h4>
                <div className="text-xs text-cyber-muted space-y-1">
                  <p>API URL: {process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080/api/v1"}</p>
                  <p>Node Env: {process.env.NODE_ENV}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
