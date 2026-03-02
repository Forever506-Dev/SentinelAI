"use client";

import { useEffect, useState, useCallback } from "react";
import { AlertTriangle, Brain, Clock, Target, Loader2, Radio, Shield, Wifi } from "lucide-react";
import { api, Alert } from "@/lib/api";
import { useWebSocket } from "@/lib/use-websocket";

const severityColors: Record<string, string> = {
  critical: "border-l-red-500 bg-red-500/5",
  high: "border-l-orange-500 bg-orange-500/5",
  medium: "border-l-yellow-500 bg-yellow-500/5",
  low: "border-l-blue-500 bg-blue-500/5",
  informational: "border-l-gray-500 bg-gray-500/5",
};
const severityDots: Record<string, string> = {
  critical: "bg-red-500 shadow-red-500/50 shadow-sm",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
};

export function ThreatFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [newAlertIds, setNewAlertIds] = useState<Set<string>>(new Set());

  const handleWsMessage = useCallback((msg: Record<string, unknown>) => {
    if (msg.type === "new_alert" && msg.alert) {
      const a = msg.alert as Alert;
      setAlerts((prev) => [a, ...prev].slice(0, 20));
      setNewAlertIds((prev) => new Set(prev).add(a.id));
      setTimeout(() => {
        setNewAlertIds((prev) => {
          const next = new Set(prev);
          next.delete(a.id);
          return next;
        });
      }, 5000);
    }
  }, []);

  const { connected } = useWebSocket(handleWsMessage);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const data = await api.getRecentAlerts();
        if (!cancelled) setAlerts(data.alerts ?? []);
      } catch {}
      finally { if (!cancelled) setLoading(false); }
    })();
    const id = setInterval(async () => {
      try {
        const data = await api.getRecentAlerts();
        if (!cancelled) setAlerts(data.alerts ?? []);
      } catch {}
    }, 15000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  if (loading) {
    return (
      <div className="card-cyber">
        <div className="animate-pulse space-y-3">
          <div className="h-4 bg-cyber-hover rounded w-40" />
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-16 bg-cyber-hover/50 rounded-lg" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="card-cyber">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          Live Threat Feed
        </h2>
        <div className="flex items-center gap-2">
          {connected ? (
            <span className="flex items-center gap-1.5 text-xs text-green-400">
              <Radio className="w-3 h-3 animate-pulse" />
              Real-time
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-xs text-yellow-400">
              <Wifi className="w-3 h-3" />
              Polling
            </span>
          )}
        </div>
      </div>

      {alerts.length === 0 ? (
        <div className="text-center py-8">
          <Shield className="w-8 h-8 text-sentinel-500/30 mx-auto mb-2" />
          <p className="text-sm text-cyber-muted">No threats detected. Your environment is clean.</p>
        </div>
      ) : (
        <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className={
                "border-l-2 " +
                (severityColors[alert.severity] || "") +
                " rounded-r-lg p-3 hover:bg-cyber-hover/50 transition-all duration-300 cursor-pointer" +
                (newAlertIds.has(alert.id) ? " ring-1 ring-sentinel-500/50 animate-pulse" : "")
              }
            >
              <div className="flex items-start justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={"w-2 h-2 rounded-full flex-shrink-0 " + (severityDots[alert.severity] || "bg-gray-500")} />
                    <span className="text-sm font-medium text-white truncate">{alert.title}</span>
                    {alert.confidence > 0 && (
                      <span className="text-[10px] text-cyber-muted bg-cyber-hover px-1.5 py-0.5 rounded-full">
                        {(alert.confidence * 100).toFixed(0)}%
                      </span>
                    )}
                  </div>
                  {alert.llm_analysis && (
                    <div className="flex items-start gap-1.5 mb-1.5 ml-4">
                      <Brain className="w-3 h-3 text-sentinel-400 mt-0.5 flex-shrink-0" />
                      <span className="text-xs text-cyber-muted line-clamp-2">{alert.llm_analysis}</span>
                    </div>
                  )}
                  <div className="flex items-center gap-3 text-xs text-cyber-muted ml-4">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(alert.detected_at).toLocaleTimeString()}
                    </span>
                    <span className="text-cyber-muted/50">{alert.detection_source}</span>
                    {(alert.mitre_techniques ?? []).slice(0, 3).map((t) => (
                      <span key={t} className="font-mono text-sentinel-400 bg-sentinel-500/10 px-1.5 py-0.5 rounded text-[10px]">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
