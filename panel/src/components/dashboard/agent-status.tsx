"use client";

import { useEffect, useState } from "react";
import { Monitor, Wifi, WifiOff, ShieldAlert, Shield, Loader2, Trash2, Cpu, HardDrive } from "lucide-react";
import { api, Agent } from "@/lib/api";

const statusColors: Record<string, string> = {
  online: "bg-green-500",
  offline: "bg-gray-500",
  isolated: "bg-red-500",
};
const osEmoji: Record<string, string> = {
  windows: "\ud83e\udea7", linux: "\ud83d\udc27", macos: "\ud83c\udf4e", android: "\ud83e\udd16",
};

function MiniBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="w-12 bg-[#0a0a0a] rounded-full h-1">
      <div className={"h-1 rounded-full transition-all duration-500 " + color} style={{ width: Math.min(value, 100) + "%" }} />
    </div>
  );
}

export function AgentStatusGrid() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchAgents = async () => {
    try {
      const data = await api.getAgents();
      setAgents(data.agents ?? []);
    } catch {}
    finally { setLoading(false); }
  };

  useEffect(() => {
    fetchAgents();
    const id = setInterval(fetchAgents, 10000);
    return () => clearInterval(id);
  }, []);

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
      <div className="card-cyber">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-cyber-hover rounded w-32" />
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-12 bg-cyber-hover/50 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="card-cyber">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Monitor className="w-5 h-5 text-blue-400" />
          Endpoint Fleet
        </h2>
        <span className="text-xs font-mono text-sentinel-400 bg-sentinel-500/10 px-2 py-1 rounded-full">
          {onlineCount}/{agents.length} online
        </span>
      </div>

      {agents.length === 0 ? (
        <div className="text-center py-8">
          <Monitor className="w-8 h-8 text-cyber-muted/30 mx-auto mb-2" />
          <p className="text-sm text-cyber-muted">No active endpoints. Deploy the SentinelAI agent to begin.</p>
        </div>
      ) : (
        <div className="space-y-1.5">
          {agents.map((agent) => (
            <div key={agent.id} className="flex items-center justify-between p-2.5 rounded-lg hover:bg-cyber-hover/50 transition-all duration-200 group">
              <div className="flex items-center gap-3">
                <div className="relative">
                  <span className="text-lg">{osEmoji[agent.os_type] || "\ud83d\udda5\ufe0f"}</span>
                  <span className={"absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ring-2 ring-cyber-card " + (statusColors[agent.status] || "bg-gray-500")} />
                </div>
                <div>
                  <div className="text-sm font-medium text-white">{agent.hostname}</div>
                  <div className="text-[10px] text-cyber-muted">{agent.internal_ip || agent.os_version}</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {agent.status === "online" && (
                  <>
                    <div className="flex items-center gap-1.5 text-[10px] text-cyber-muted">
                      <Cpu className="w-3 h-3" />
                      <span className={(agent.cpu_usage ?? 0) > 80 ? "text-red-400" : (agent.cpu_usage ?? 0) > 50 ? "text-yellow-400" : "text-green-400"}>
                        {(agent.cpu_usage ?? 0).toFixed(0)}%
                      </span>
                      <MiniBar value={agent.cpu_usage ?? 0} color={(agent.cpu_usage ?? 0) > 80 ? "bg-red-500" : (agent.cpu_usage ?? 0) > 50 ? "bg-yellow-500" : "bg-green-500"} />
                    </div>
                    <div className="flex items-center gap-1.5 text-[10px] text-cyber-muted">
                      <HardDrive className="w-3 h-3" />
                      <span>{(agent.memory_usage ?? 0).toFixed(0)}%</span>
                    </div>
                  </>
                )}
                <button
                  onClick={() => handleDecommission(agent.id, agent.hostname)}
                  className="p-1 opacity-0 group-hover:opacity-100 hover:bg-red-500/10 rounded transition-all"
                  title="Decommission"
                >
                  <Trash2 className="w-3.5 h-3.5 text-red-400/70" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
