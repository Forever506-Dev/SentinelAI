"use client";

import { useState, useEffect, useCallback } from "react";
import {
  ClipboardCheck, CheckCircle, XCircle, Clock, Loader2,
  RefreshCw, ShieldCheck, AlertTriangle, Ban, FileText,
  ArrowDownCircle, ArrowUpCircle, Network, ChevronLeft, ChevronRight,
} from "lucide-react";
import {
  api,
  PendingApproval,
  Approval,
  ApprovalHistoryResponse,
} from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

type Tab = "pending" | "history";

const STATUS_BADGE: Record<string, { bg: string; text: string; icon: React.ElementType }> = {
  pending:       { bg: "bg-yellow-500/20", text: "text-yellow-300", icon: Clock },
  approved:      { bg: "bg-green-500/20",  text: "text-green-300",  icon: CheckCircle },
  auto_approved: { bg: "bg-green-500/20",  text: "text-green-300",  icon: ShieldCheck },
  rejected:      { bg: "bg-red-500/20",    text: "text-red-300",    icon: XCircle },
  expired:       { bg: "bg-cyber-muted/20", text: "text-cyber-muted", icon: Clock },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_BADGE[status] ?? STATUS_BADGE.pending;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium ${cfg.bg} ${cfg.text}`}>
      <Icon className="w-3 h-3" />
      {status.replace("_", " ")}
    </span>
  );
}

function timeAgo(iso: string) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function ApprovalsPage() {
  const { hasRole } = useAuth();

  const [tab, setTab] = useState<Tab>("pending");
  const [loading, setLoading] = useState(true);

  // Pending state
  const [pendingItems, setPendingItems] = useState<PendingApproval[]>([]);
  const [pendingTotal, setPendingTotal] = useState(0);

  // History state
  const [historyItems, setHistoryItems] = useState<Approval[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyPage, setHistoryPage] = useState(1);
  const historyPageSize = 20;

  // Decide state
  const [decidingId, setDecidingId] = useState<string | null>(null);
  const [noteMap, setNoteMap] = useState<Record<string, string>>({});

  // --- Loaders ---
  const loadPending = useCallback(async () => {
    try {
      const data = await api.getPendingApprovals();
      setPendingItems(data.approvals ?? []);
      setPendingTotal(data.total ?? 0);
    } catch { /* ignore */ }
  }, []);

  const loadHistory = useCallback(async () => {
    try {
      const data = await api.getApprovalHistory({ page: historyPage, page_size: historyPageSize });
      setHistoryItems(data.approvals ?? []);
      setHistoryTotal(data.total ?? 0);
    } catch { /* ignore */ }
  }, [historyPage]);

  useEffect(() => {
    setLoading(true);
    const fn = tab === "pending" ? loadPending : loadHistory;
    fn().finally(() => setLoading(false));
  }, [tab, loadPending, loadHistory]);

  const refresh = () => {
    setLoading(true);
    const fn = tab === "pending" ? loadPending : loadHistory;
    fn().finally(() => setLoading(false));
  };

  // --- Decide ---
  const handleDecide = async (id: string, decision: "approve" | "reject") => {
    setDecidingId(id);
    try {
      await api.decideApproval(id, { decision, note: noteMap[id] ?? undefined });
      setPendingItems((prev) => prev.filter((a) => a.id !== id));
      setPendingTotal((t) => Math.max(0, t - 1));
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : "Failed to decide approval");
    } finally {
      setDecidingId(null);
    }
  };

  // --- Helpers ---
  const historyTotalPages = Math.ceil(historyTotal / historyPageSize) || 1;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-sentinel-600/20 border border-sentinel-500/30 rounded-xl">
            <ClipboardCheck className="w-6 h-6 text-sentinel-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">Approval Queue</h1>
            <p className="text-cyber-muted text-xs">Manage and review remediation approval requests</p>
          </div>
        </div>
        <button onClick={refresh}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-surface border border-cyber-border text-cyber-muted hover:text-white rounded-lg text-xs transition-all">
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="flex gap-2">
        <button onClick={() => setTab("pending")}
          className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            tab === "pending"
              ? "bg-sentinel-600/20 text-sentinel-300 border border-sentinel-500/30"
              : "bg-cyber-surface text-cyber-muted border border-cyber-border hover:text-white"
          }`}>
          <Clock className="w-3.5 h-3.5" />
          Pending
          {pendingTotal > 0 && (
            <span className="ml-1 px-1.5 py-0.5 bg-yellow-500/20 text-yellow-300 rounded-full text-[10px] font-bold">{pendingTotal}</span>
          )}
        </button>
        <button onClick={() => setTab("history")}
          className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
            tab === "history"
              ? "bg-sentinel-600/20 text-sentinel-300 border border-sentinel-500/30"
              : "bg-cyber-surface text-cyber-muted border border-cyber-border hover:text-white"
          }`}>
          <FileText className="w-3.5 h-3.5" />
          History
          <span className="ml-1 text-[10px] text-cyber-muted">({historyTotal})</span>
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center py-20 text-cyber-muted text-sm gap-2">
          <Loader2 className="w-5 h-5 animate-spin" /> Loading…
        </div>
      ) : tab === "pending" ? (
        /* ═══════════ PENDING TAB ═══════════ */
        pendingItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-cyber-muted gap-2">
            <CheckCircle className="w-10 h-10 text-green-500/40" />
            <p className="text-sm">No pending approvals</p>
            <p className="text-xs text-cyber-muted/60">All remediation requests have been reviewed</p>
          </div>
        ) : (
          <div className="space-y-3">
            {pendingItems.map((item) => (
              <div key={item.id} className="bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
                {/* Card header */}
                <div className="flex items-center justify-between px-5 py-3 border-b border-cyber-border/50">
                  <div className="flex items-center gap-3">
                    <div className="p-1.5 bg-yellow-500/10 rounded-lg">
                      <AlertTriangle className="w-4 h-4 text-yellow-400" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white capitalize">
                          {(item.action_type ?? "unknown").replace(/_/g, " ")}
                        </span>
                        <StatusBadge status={item.status} />
                      </div>
                      <div className="flex items-center gap-2 text-[11px] text-cyber-muted mt-0.5">
                        <span>by <span className="text-cyber-text">{item.requester_username ?? "unknown"}</span></span>
                        <span>•</span>
                        <span>{timeAgo(item.created_at)}</span>
                        {item.agent_hostname && (
                          <>
                            <span>•</span>
                            <span className="flex items-center gap-1">
                              <Network className="w-3 h-3" /> {item.agent_hostname}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  {item.expires_at && (
                    <div className="text-[10px] text-cyber-muted flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      Expires {timeAgo(item.expires_at)}
                    </div>
                  )}
                </div>

                {/* Card body — rule details */}
                <div className="px-5 py-3 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  {item.rule_name && (
                    <div>
                      <span className="text-cyber-muted text-[10px] uppercase tracking-wider">Rule</span>
                      <p className="text-white font-mono mt-0.5 truncate">{item.rule_name}</p>
                    </div>
                  )}
                  {item.direction && (
                    <div>
                      <span className="text-cyber-muted text-[10px] uppercase tracking-wider">Direction</span>
                      <p className="text-white flex items-center gap-1 mt-0.5">
                        {item.direction === "inbound"
                          ? <ArrowDownCircle className="w-3 h-3 text-blue-400" />
                          : <ArrowUpCircle className="w-3 h-3 text-orange-400" />}
                        {item.direction}
                      </p>
                    </div>
                  )}
                  {item.protocol && (
                    <div>
                      <span className="text-cyber-muted text-[10px] uppercase tracking-wider">Protocol</span>
                      <p className="text-white uppercase mt-0.5">{item.protocol}</p>
                    </div>
                  )}
                  {item.port && (
                    <div>
                      <span className="text-cyber-muted text-[10px] uppercase tracking-wider">Port</span>
                      <p className="text-white font-mono mt-0.5">{item.port}</p>
                    </div>
                  )}
                  {item.remote_address && (
                    <div>
                      <span className="text-cyber-muted text-[10px] uppercase tracking-wider">Remote Addr</span>
                      <p className="text-white font-mono mt-0.5">{item.remote_address}</p>
                    </div>
                  )}
                </div>

                {/* Reason */}
                {item.request_reason && (
                  <div className="px-5 py-2 border-t border-cyber-border/30 text-xs">
                    <span className="text-cyber-muted text-[10px] uppercase tracking-wider">Reason</span>
                    <p className="text-cyber-text mt-0.5">{item.request_reason}</p>
                  </div>
                )}

                {/* Card footer — actions (admin only) */}
                {hasRole("admin") && (
                  <div className="flex items-center gap-3 px-5 py-3 border-t border-cyber-border bg-cyber-bg/50">
                    <input
                      type="text"
                      placeholder="Optional note…"
                      value={noteMap[item.id] ?? ""}
                      onChange={(e) => setNoteMap((m) => ({ ...m, [item.id]: e.target.value }))}
                      className="flex-1 bg-cyber-bg border border-cyber-border rounded-lg px-3 py-1.5 text-xs text-white placeholder-cyber-muted/50 focus:outline-none focus:border-sentinel-600"
                    />
                    <button
                      onClick={() => handleDecide(item.id, "approve")}
                      disabled={decidingId === item.id}
                      className="flex items-center gap-1 px-4 py-1.5 bg-green-600 text-white rounded-lg text-xs font-medium hover:bg-green-700 disabled:opacity-30 transition-all"
                    >
                      {decidingId === item.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3 h-3" />}
                      Approve
                    </button>
                    <button
                      onClick={() => handleDecide(item.id, "reject")}
                      disabled={decidingId === item.id}
                      className="flex items-center gap-1 px-4 py-1.5 bg-red-600/80 text-white rounded-lg text-xs font-medium hover:bg-red-700 disabled:opacity-30 transition-all"
                    >
                      {decidingId === item.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Ban className="w-3 h-3" />}
                      Reject
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )
      ) : (
        /* ═══════════ HISTORY TAB ═══════════ */
        historyItems.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-cyber-muted gap-2">
            <FileText className="w-10 h-10 text-cyber-muted/30" />
            <p className="text-sm">No approval history</p>
          </div>
        ) : (
          <>
            <div className="bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-cyber-border bg-cyber-bg/50 text-[10px] text-cyber-muted uppercase tracking-wider">
                    <th className="px-4 py-3 text-left">Status</th>
                    <th className="px-4 py-3 text-left">Requested</th>
                    <th className="px-4 py-3 text-left">Reason</th>
                    <th className="px-4 py-3 text-left">Decided By</th>
                    <th className="px-4 py-3 text-left">Note</th>
                    <th className="px-4 py-3 text-left">Resolved</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/30">
                  {historyItems.map((a) => (
                    <tr key={a.id} className="hover:bg-cyber-bg/30 transition-colors">
                      <td className="px-4 py-2.5">
                        <StatusBadge status={a.status} />
                      </td>
                      <td className="px-4 py-2.5 text-cyber-muted">
                        {timeAgo(a.created_at)}
                      </td>
                      <td className="px-4 py-2.5 text-cyber-text max-w-[200px] truncate">
                        {a.request_reason ?? "—"}
                      </td>
                      <td className="px-4 py-2.5 text-cyber-muted font-mono">
                        {a.approved_by?.slice(0, 8) ?? "—"}
                      </td>
                      <td className="px-4 py-2.5 text-cyber-muted max-w-[200px] truncate">
                        {a.approval_note ?? "—"}
                      </td>
                      <td className="px-4 py-2.5 text-cyber-muted">
                        {a.resolved_at ? timeAgo(a.resolved_at) : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {historyTotalPages > 1 && (
              <div className="flex items-center justify-center gap-3 text-xs">
                <button
                  onClick={() => setHistoryPage((p) => Math.max(1, p - 1))}
                  disabled={historyPage <= 1}
                  className="flex items-center gap-1 px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-cyber-muted hover:text-white disabled:opacity-30 transition-all"
                >
                  <ChevronLeft className="w-3 h-3" /> Prev
                </button>
                <span className="text-cyber-muted">
                  Page {historyPage} of {historyTotalPages}
                </span>
                <button
                  onClick={() => setHistoryPage((p) => Math.min(historyTotalPages, p + 1))}
                  disabled={historyPage >= historyTotalPages}
                  className="flex items-center gap-1 px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-cyber-muted hover:text-white disabled:opacity-30 transition-all"
                >
                  Next <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            )}
          </>
        )
      )}
    </div>
  );
}
