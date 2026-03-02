"use client";

import { useEffect, useState } from "react";
import { Monitor, Search, Shield, ShieldAlert, Wifi, WifiOff, Loader2, Trash2, Clock, Cpu, HardDrive, MemoryStick } from "lucide-react";
import { api, Agent } from "@/lib/api";

const osIcons: Record<string, string> = {
  windows: "\ud83e\udea7", linux: "\ud83d\udc27", macos: "\ud83c\udf4e", android: "\ud83e\udd16",
};

function StatusBadge({ status }: { status: string }) {
  const styles: Record<string, string> = {
    online: "bg-green-500/20 text-green-400 border-green-500/30",
    offline: "bg-gray-500/20 text-gray-400 border-gray-500/30",
    isolated: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return (
    <span className={"inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border " + (styles[status] || styles.offline)}>
      {status === "online" ? <Wifi className="w-3 h-3" /> : status === "isolated" ? <ShieldAlert className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function UsageBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="w-full bg-cyber-bg rounded-full h-1.5">
      <div className={"h-1.5 rounded-full transition-all duration-500 " + color} style={{ width: Math.min(value, 100) + "%" }} />
    </div>
  );
}

function formatUptime(seconds: number | null): string {
  if (!seconds) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");

  const fetchAgents = async () => {
    try {
      const params: Record<string, string> = {};
      if (statusFilter !== "all") params.status = statusFilter;
      if (search) params.search = search;
      const data = await api.getAgents(params as any);
      setAgents(data.agents ?? []);
      setTotal(data.total ?? 0);
    } catch {}
    finally { setLoading(false); }
  };

  useEffect(() => { fetchAgents(); }, [statusFilter, search]);
  useEffect(() => {
    const id = setInterval(fetchAgents, 10000);
    return () => clearInterval(id);
  }, [statusFilter, search]);

  const handleDecommission = async (agentId: string, hostname: string) => {
    if (!confirm(`Permanently decommission ${hostname}? This cannot be undone.`)) return;
    try {
      await api.decommissionAgent(agentId);
      setAgents((prev) => prev.filter((a) => a.id !== agentId));
    } catch (err) {
      console.error("Decommission failed:", err);
    }
  };

  const onlineCount = agents.filter((a) => a.status === "online").length;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-sentinel-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Monitor className="w-6 h-6 text-blue-400" />
            Endpoint Fleet
          </h1>
          <p className="text-cyber-muted text-sm mt-1">
            {total} endpoints registered &middot; {onlineCount} online
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
          <input type="text" placeholder="Search hostname, IP..." className="w-full bg-cyber-card border border-cyber-border rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-cyber-muted focus:outline-none focus:border-sentinel-500 transition-colors" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex gap-1.5">
          {["all", "online", "offline", "isolated"].map((s) => (
            <button key={s} onClick={() => setStatusFilter(s)} className={"px-3 py-1.5 rounded-lg text-xs font-medium transition-all " + (statusFilter === s ? "bg-sentinel-600 text-white shadow-lg shadow-sentinel-600/20" : "bg-cyber-card text-cyber-muted hover:bg-cyber-hover border border-cyber-border")}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {agents.length === 0 ? (
        <div className="card-cyber text-center py-12">
          <Monitor className="w-10 h-10 text-cyber-muted/30 mx-auto mb-3" />
          <p className="text-cyber-muted">No agents found.</p>
        </div>
      ) : (
        <div className="card-cyber overflow-hidden p-0">
          <table className="w-full">
            <thead>
              <tr className="border-b border-cyber-border bg-cyber-surface/50">
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Endpoint</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">OS</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Status</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">CPU</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Memory</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Uptime</th>
                <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/50">
              {agents.map((agent) => (
                <tr key={agent.id} className="hover:bg-cyber-hover/30 transition-colors group">
                  <td className="px-6 py-3.5">
                    <div className="flex items-center gap-3">
                      <div className="relative">
                        <span className="text-base">{osIcons[agent.os_type] || "\ud83d\udda5\ufe0f"}</span>
                        <span className={"absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full ring-2 ring-cyber-card " + (agent.status === "online" ? "bg-green-500" : agent.status === "isolated" ? "bg-red-500" : "bg-gray-500")} />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-white">{agent.hostname}</div>
                        <div className="text-[10px] text-cyber-muted font-mono">{agent.internal_ip || "—"}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-3.5">
                    <span className="text-xs text-cyber-muted">{agent.os_version}</span>
                  </td>
                  <td className="px-6 py-3.5"><StatusBadge status={agent.status} /></td>
                  <td className="px-6 py-3.5 w-28">
                    <div className="space-y-1">
                      <div className="text-xs text-cyber-muted">{(agent.cpu_usage ?? 0).toFixed(1)}%</div>
                      <UsageBar value={agent.cpu_usage ?? 0} color={(agent.cpu_usage ?? 0) > 80 ? "bg-red-500" : (agent.cpu_usage ?? 0) > 50 ? "bg-yellow-500" : "bg-sentinel-500"} />
                    </div>
                  </td>
                  <td className="px-6 py-3.5 w-28">
                    <div className="space-y-1">
                      <div className="text-xs text-cyber-muted">{(agent.memory_usage ?? 0).toFixed(1)}%</div>
                      <UsageBar value={agent.memory_usage ?? 0} color={(agent.memory_usage ?? 0) > 80 ? "bg-red-500" : (agent.memory_usage ?? 0) > 50 ? "bg-yellow-500" : "bg-sentinel-500"} />
                    </div>
                  </td>
                  <td className="px-6 py-3.5">
                    <div className="flex items-center gap-1 text-xs text-cyber-muted">
                      <Clock className="w-3 h-3" />
                      {formatUptime(agent.uptime_seconds)}
                    </div>
                  </td>
                  <td className="px-6 py-3.5">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleDecommission(agent.id, agent.hostname)}
                        className="p-1.5 opacity-0 group-hover:opacity-100 hover:bg-red-500/10 rounded-lg transition-all"
                        title="Decommission"
                      >
                        <Trash2 className="w-4 h-4 text-red-400/70" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
