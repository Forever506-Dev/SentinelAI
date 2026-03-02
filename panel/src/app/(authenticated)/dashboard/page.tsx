"use client";

import { StatsOverview } from "@/components/dashboard/stats-overview";
import { ThreatFeed } from "@/components/dashboard/threat-feed";
import { AgentStatusGrid } from "@/components/dashboard/agent-status";
import { useWebSocket } from "@/lib/use-websocket";
import { Radio, Shield } from "lucide-react";

export default function DashboardPage() {
  const { connected } = useWebSocket();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Shield className="w-6 h-6 text-sentinel-400" />
            Command Center
          </h1>
          <p className="text-sm text-cyber-muted mt-1">
            Real-time threat monitoring and endpoint overview
          </p>
        </div>
        <div className="flex items-center gap-3">
          {connected ? (
            <div className="flex items-center gap-1.5 text-xs bg-green-500/10 text-green-400 px-3 py-1.5 rounded-full border border-green-500/20">
              <Radio className="w-3 h-3 animate-pulse" />
              Live
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-xs bg-yellow-500/10 text-yellow-400 px-3 py-1.5 rounded-full border border-yellow-500/20">
              <Radio className="w-3 h-3" />
              Connecting...
            </div>
          )}
        </div>
      </div>

      <StatsOverview />

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        <div className="lg:col-span-3">
          <ThreatFeed />
        </div>
        <div className="lg:col-span-2">
          <AgentStatusGrid />
        </div>
      </div>
    </div>
  );
}
