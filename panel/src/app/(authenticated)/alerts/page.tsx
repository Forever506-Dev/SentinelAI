"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Brain, Clock, Search, Target, Loader2, ChevronDown, ChevronUp, Shield, Radio, X, CheckCircle, Eye, Flag, Activity } from "lucide-react";
import { api, Alert } from "@/lib/api";
import { useWebSocket } from "@/lib/use-websocket";

const severityColors: Record<string, string> = {
  critical: "text-red-400 bg-red-500/20 border-red-500/30",
  high: "text-orange-400 bg-orange-500/20 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/20 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/20 border-blue-500/30",
  informational: "text-gray-400 bg-gray-500/20 border-gray-500/30",
};

const statusConfig: Record<string, { color: string; icon: typeof CheckCircle }> = {
  new: { color: "bg-blue-500/20 text-blue-400 border-blue-500/30", icon: Radio },
  investigating: { color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", icon: Eye },
  resolved: { color: "bg-green-500/20 text-green-400 border-green-500/30", icon: CheckCircle },
  false_positive: { color: "bg-gray-500/20 text-gray-400 border-gray-500/30", icon: X },
  escalated: { color: "bg-red-500/20 text-red-400 border-red-500/30", icon: Flag },
};

function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? "bg-red-500" : pct >= 50 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 bg-cyber-bg rounded-full h-1.5">
        <div className={"h-1.5 rounded-full " + color} style={{ width: pct + "%" }} />
      </div>
      <span className="text-[10px] text-cyber-muted">{pct}%</span>
    </div>
  );
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<string | null>(null);
  const { connected, lastMessage } = useWebSocket();

  const fetchAlerts = async () => {
    try {
      const params: Record<string, string> = {};
      if (severityFilter !== "all") params.severity = severityFilter;
      if (statusFilter !== "all") params.status = statusFilter;
      const data = await api.getAlerts(params as any);
      let list = data.alerts ?? [];
      if (search) {
        const q = search.toLowerCase();
        list = list.filter((a) => a.title.toLowerCase().includes(q) || (a.description || "").toLowerCase().includes(q));
      }
      setAlerts(list);
      setTotal(data.total ?? 0);
    } catch {} finally { setLoading(false); }
  };

  useEffect(() => { fetchAlerts(); }, [severityFilter, statusFilter, search]);
  useEffect(() => { const id = setInterval(fetchAlerts, 12000); return () => clearInterval(id); }, [severityFilter, statusFilter, search]);

  // Real-time: prepend new alerts from WebSocket
  useEffect(() => {
    if (!lastMessage) return;
    try {
      const msg = typeof lastMessage === "string" ? JSON.parse(lastMessage) : lastMessage;
      if (msg.type === "alert" && msg.data) {
        setAlerts((prev) => {
          if (prev.some((a) => a.id === msg.data.id)) return prev;
          return [msg.data, ...prev].slice(0, 100);
        });
      }
    } catch {}
  }, [lastMessage]);

  const handleStatusUpdate = async (alertId: string, newStatus: string) => {
    setUpdatingId(alertId);
    try {
      await api.updateAlert(alertId, { status: newStatus });
      setAlerts((prev) => prev.map((a) => a.id === alertId ? { ...a, status: newStatus } : a));
      if (newStatus === "escalated") {
        // Backend auto-triggers AI analysis on escalation. Refresh shortly.
        setTimeout(fetchAlerts, 2500);
      }
    } catch (err) {
      console.error("Status update failed:", err);
    } finally { setUpdatingId(null); }
  };

  const handleAnalyze = async (alertId: string) => {
    setUpdatingId(alertId);
    try {
      await api.triggerAlertAnalysis(alertId);
      // Refetch to get LLM result
      setTimeout(fetchAlerts, 3000);
    } catch (err) {
      console.error("Analysis failed:", err);
    } finally { setUpdatingId(null); }
  };

  const newCount = alerts.filter((a) => a.status === "new").length;
  const criticalCount = alerts.filter((a) => a.severity === "critical").length;

  if (loading) return (<div className="flex items-center justify-center h-64"><Loader2 className="w-6 h-6 text-sentinel-400 animate-spin" /></div>);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <AlertTriangle className="w-6 h-6 text-orange-400" />
            Alert Management
          </h1>
          <p className="text-cyber-muted text-sm mt-1">
            {total} total &middot; {newCount} new &middot; {criticalCount} critical
          </p>
        </div>
        <div className="flex items-center gap-2">
          {connected ? (
            <span className="flex items-center gap-1 text-[10px] text-green-400 bg-green-500/10 px-2 py-1 rounded-full">
              <Radio className="w-2.5 h-2.5 animate-pulse" />Live
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[10px] text-yellow-400 bg-yellow-500/10 px-2 py-1 rounded-full">
              <Activity className="w-2.5 h-2.5" />Polling
            </span>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
          <input type="text" placeholder="Search alerts..." className="w-full bg-cyber-card border border-cyber-border rounded-lg pl-10 pr-4 py-2 text-sm text-white placeholder-cyber-muted focus:outline-none focus:border-sentinel-500 transition-colors" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div className="flex gap-1.5">
          {["all", "critical", "high", "medium", "low"].map((s) => (
            <button key={s} onClick={() => setSeverityFilter(s)} className={"px-3 py-1.5 rounded-lg text-xs font-medium transition-all " + (severityFilter === s ? "bg-sentinel-600 text-white shadow-lg shadow-sentinel-600/20" : "bg-cyber-card text-cyber-muted hover:bg-cyber-hover border border-cyber-border")}>
              {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <div className="flex gap-1.5">
          {["all", "new", "investigating", "escalated", "resolved"].map((s) => (
            <button key={s} onClick={() => setStatusFilter(s)} className={"px-3 py-1.5 rounded-lg text-xs font-medium transition-all " + (statusFilter === s ? "bg-blue-600 text-white" : "bg-cyber-card text-cyber-muted hover:bg-cyber-hover border border-cyber-border")}>
              {s === "all" ? "All Status" : s.charAt(0).toUpperCase() + s.slice(1).replace("_", " ")}
            </button>
          ))}
        </div>
      </div>

      {/* Alert List */}
      {alerts.length === 0 ? (
        <div className="card-cyber text-center py-16">
          <Shield className="w-12 h-12 text-cyber-muted/20 mx-auto mb-4" />
          <p className="text-cyber-muted text-sm">No alerts match your filters.</p>
          <p className="text-cyber-muted/60 text-xs mt-1">Alerts are created when the detection pipeline flags suspicious telemetry.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {alerts.map((alert) => {
            const isExpanded = expanded === alert.id;
            const StatusIcon = statusConfig[alert.status]?.icon || Radio;
            return (
              <div key={alert.id} className={"card-cyber p-0 overflow-hidden transition-all duration-200 " + (alert.severity === "critical" ? "border-red-500/20" : "")}>
                {/* Main row */}
                <div className="flex items-center gap-4 px-5 py-3.5 cursor-pointer hover:bg-cyber-hover/20 transition-colors" onClick={() => setExpanded(isExpanded ? null : alert.id)}>
                  <AlertTriangle className={"w-4 h-4 flex-shrink-0 " + (alert.severity === "critical" ? "text-red-400" : alert.severity === "high" ? "text-orange-400" : alert.severity === "medium" ? "text-yellow-400" : "text-blue-400")} />

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-white truncate">{alert.title}</span>
                    </div>
                    <div className="flex items-center gap-3 mt-0.5 text-[10px] text-cyber-muted">
                      <span>{new Date(alert.detected_at).toLocaleString()}</span>
                      <span className="font-mono">{alert.agent_id.slice(0, 8)}</span>
                      <span>{alert.detection_source}</span>
                    </div>
                  </div>

                  <ConfidenceMeter value={alert.confidence ?? 0} />

                  <span className={"inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border " + (severityColors[alert.severity] || "")}>
                    {alert.severity}
                  </span>

                  <span className={"inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border " + (statusConfig[alert.status]?.color || "")}>
                    <StatusIcon className="w-2.5 h-2.5" />
                    {alert.status.replace("_", " ")}
                  </span>

                  {isExpanded ? <ChevronUp className="w-4 h-4 text-cyber-muted" /> : <ChevronDown className="w-4 h-4 text-cyber-muted" />}
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="border-t border-cyber-border px-5 py-4 bg-cyber-bg/30 space-y-4">
                    {/* Description */}
                    {alert.description && (
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-cyber-muted mb-1">Description</h4>
                        <p className="text-sm text-cyber-text">{alert.description}</p>
                      </div>
                    )}

                    {/* MITRE */}
                    {(alert.mitre_techniques ?? []).length > 0 && (
                      <div>
                        <h4 className="text-[10px] uppercase tracking-wider text-cyber-muted mb-1.5 flex items-center gap-1">
                          <Target className="w-3 h-3" />MITRE ATT&CK
                        </h4>
                        <div className="flex flex-wrap gap-1.5">
                          {(alert.mitre_techniques ?? []).map((t) => (
                            <span key={t} className="px-2 py-0.5 bg-sentinel-500/10 text-sentinel-400 rounded text-xs font-mono border border-sentinel-500/20">{t}</span>
                          ))}
                          {(alert.mitre_tactics ?? []).map((t) => (
                            <span key={t} className="px-2 py-0.5 bg-purple-500/10 text-purple-400 rounded text-xs font-mono border border-purple-500/20">{t}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* LLM Analysis */}
                    {alert.llm_analysis && (
                      <div className="bg-cyber-card border border-sentinel-500/20 rounded-lg p-4">
                        <div className="flex items-center gap-2 mb-2">
                          <Brain className="w-4 h-4 text-sentinel-400" />
                          <span className="text-xs font-medium text-sentinel-400">AI Analysis</span>
                        </div>
                        <p className="text-sm text-cyber-text leading-relaxed whitespace-pre-wrap">{alert.llm_analysis}</p>
                        {alert.llm_recommendation && (
                          <div className="mt-3 pt-3 border-t border-cyber-border">
                            <span className="text-[10px] uppercase text-cyber-muted">Recommendation</span>
                            <p className="text-sm text-white mt-1">{alert.llm_recommendation}</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Actions */}
                    <div className="flex items-center gap-2 pt-2">
                      {alert.status === "new" && (
                        <button onClick={() => handleStatusUpdate(alert.id, "investigating")} disabled={updatingId === alert.id} className="btn-primary text-xs flex items-center gap-1.5">
                          {updatingId === alert.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Eye className="w-3 h-3" />}
                          Start Investigation
                        </button>
                      )}
                      {alert.status === "investigating" && (
                        <>
                          <button onClick={() => handleStatusUpdate(alert.id, "resolved")} disabled={updatingId === alert.id} className="bg-green-600 hover:bg-green-700 text-white px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5">
                            <CheckCircle className="w-3 h-3" />Resolve
                          </button>
                          <button onClick={() => handleStatusUpdate(alert.id, "false_positive")} disabled={updatingId === alert.id} className="bg-cyber-card border border-cyber-border text-cyber-muted hover:bg-cyber-hover px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5">
                            <X className="w-3 h-3" />False Positive
                          </button>
                          <button onClick={() => handleStatusUpdate(alert.id, "escalated")} disabled={updatingId === alert.id} className="bg-red-600/20 border border-red-500/30 text-red-400 hover:bg-red-600/30 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5">
                            <Flag className="w-3 h-3" />Escalate + Auto AI
                          </button>
                        </>
                      )}
                      {!alert.llm_analysis && (
                        <button onClick={() => handleAnalyze(alert.id)} disabled={updatingId === alert.id} className="ml-auto bg-sentinel-600/20 border border-sentinel-500/30 text-sentinel-400 hover:bg-sentinel-600/30 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5">
                          {updatingId === alert.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Brain className="w-3 h-3" />}
                          Run AI Analysis
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
