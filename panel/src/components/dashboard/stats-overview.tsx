"use client";

import { useEffect, useState } from "react";
import { Shield, Monitor, AlertTriangle, Activity } from "lucide-react";
import { api } from "@/lib/api";

interface DashStats {
  total_agents: number;
  online_agents: number;
  total_alerts: number;
  critical_alerts: number;
  events_per_hour: number;
}

const defaultStats: DashStats = {
  total_agents: 0,
  online_agents: 0,
  total_alerts: 0,
  critical_alerts: 0,
  events_per_hour: 0,
};

export function StatsOverview() {
  const [stats, setStats] = useState<DashStats>(defaultStats);

  useEffect(() => {
    const fetch = async () => {
      try {
        const data = await api.getDashboardStats();
        setStats({
          total_agents: data.agents?.total ?? 0,
          online_agents: data.agents?.online ?? 0,
          total_alerts: data.alerts?.active ?? 0,
          critical_alerts: data.alerts?.critical ?? 0,
          events_per_hour: data.telemetry?.events_last_hour ?? 0,
        });
      } catch {}
    };
    fetch();
    const id = setInterval(fetch, 15000);
    return () => clearInterval(id);
  }, []);

  const cards = [
    {
      label: "Total Endpoints",
      value: stats.total_agents,
      icon: Monitor,
      accent: "text-blue-400",
      bg: "bg-blue-500/10",
      border: "border-blue-500/20",
    },
    {
      label: "Online Agents",
      value: stats.online_agents,
      icon: Shield,
      accent: "text-green-400",
      bg: "bg-green-500/10",
      border: "border-green-500/20",
    },
    {
      label: "Active Alerts",
      value: stats.total_alerts,
      icon: AlertTriangle,
      accent: "text-orange-400",
      bg: "bg-orange-500/10",
      border: "border-orange-500/20",
    },
    {
      label: "Events / Hour",
      value: stats.events_per_hour,
      icon: Activity,
      accent: "text-sentinel-400",
      bg: "bg-sentinel-500/10",
      border: "border-sentinel-500/20",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className={"card-cyber flex items-center gap-4 " + card.border}
        >
          <div className={"p-2.5 rounded-lg " + card.bg}>
            <card.icon className={"w-5 h-5 " + card.accent} />
          </div>
          <div>
            <p className="text-[10px] uppercase tracking-wider text-cyber-muted">
              {card.label}
            </p>
            <p className="text-xl font-bold text-white">{card.value}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
