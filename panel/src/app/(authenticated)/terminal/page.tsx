"use client";

import { useState, useEffect, useRef, KeyboardEvent } from "react";
import {
  Terminal, Send, Loader2, Trash2, Cpu, Network, Shield, HardDrive,
  Users, Clock, ListTree, ScanSearch, BrainCircuit, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle, XCircle, Info, ShieldAlert,
} from "lucide-react";
import { api, Agent, CommandResponse, ShellAnalysisResult, ShellFinding } from "@/lib/api";
import { useTerminalStore, ShellLine } from "@/lib/terminal-store";

/* ───────── Constants ───────── */

const QUICK_COMMANDS = [
  { label: "System Info", cmd: "sysinfo", icon: Cpu, desc: "Full system overview" },
  { label: "Processes", cmd: "ps", icon: ListTree, desc: "List running processes" },
  { label: "Connections", cmd: "netstat", icon: Network, desc: "Active network connections" },
  { label: "Open Ports", cmd: "scan_ports", icon: ScanSearch, desc: "Listening ports" },
  { label: "Software", cmd: "installed_software", icon: HardDrive, desc: "Installed programs" },
  { label: "Users", cmd: "users", icon: Users, desc: "Local user accounts" },
  { label: "Startup", cmd: "startup_items", icon: Clock, desc: "Startup programs" },
  { label: "Full Scan", cmd: "scan", icon: Shield, desc: "Complete system scan" },
];

const RISK_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  clean: "text-green-400 bg-green-500/10 border-green-500/30",
  unknown: "text-gray-400 bg-gray-500/10 border-gray-500/30",
};

const SEVERITY_ICONS: Record<string, typeof AlertTriangle> = {
  critical: XCircle,
  high: ShieldAlert,
  medium: AlertTriangle,
  low: Info,
  informational: Info,
};

/* ───────── Component ───────── */

export default function TerminalPage() {
  /* ── Zustand store (persisted across navigation) ── */
  const {
    history, cmdHistory, historyIdx, command,
    lastCommand, lastOutput,
    analysis, analysisOpen,
    selectedAgent,
    addLine, clearHistory, setCommand, pushCmdHistory, setHistoryIdx,
    setLastCommand, setLastOutput,
    setAnalysis, setAnalysisOpen,
    setSelectedAgent,
  } = useTerminalStore();

  /* ── Local-only state (transient, never persisted) ── */
  const [agents, setAgents] = useState<Agent[]>([]);
  const [sending, setSending] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [hydrated, setHydrated] = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  /* ── Wait for Zustand hydration to avoid SSR mismatch ── */
  useEffect(() => {
    setHydrated(true);
  }, []);

  /* ── Fetch agents once ── */
  useEffect(() => {
    (async () => {
      try {
        const data = await api.getAgents();
        const agentList = data.agents ?? [];
        setAgents(agentList);
        // Auto-select first online agent only if none persisted
        if (!selectedAgent) {
          const online = agentList.filter((a) => a.status === "online");
          if (online.length > 0) setSelectedAgent(online[0].id);
        }
      } catch {}
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── Auto-scroll on new history lines ── */
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [history]);

  const selectedAgentInfo = agents.find((a) => a.id === selectedAgent);

  /* ── Execute command on agent ── */
  const executeCommand = async (cmdType: string, params: Record<string, unknown> = {}) => {
    if (!selectedAgent || sending) return;

    setSending(true);
    setAnalysis(null);
    const displayCmd = cmdType === "shell" ? (params.command as string) : cmdType;

    addLine({ type: "input", text: displayCmd });

    try {
      const result: CommandResponse = await api.sendAgentCommand(selectedAgent, cmdType, params);
      if (result.status === "timeout") {
        addLine({
          type: "error",
          text: "Timeout: " + (result.output || "Agent did not respond within 30 seconds."),
        });
        setLastOutput("");
        setLastCommand("");
      } else if (result.status === "error") {
        addLine({
          type: "error",
          text: result.output || "Command returned an error.",
        });
        setLastOutput("");
        setLastCommand("");
      } else {
        const outputText = result.output || "(no output)";
        addLine({ type: "output", text: outputText, command: displayCmd });
        setLastOutput(outputText);
        setLastCommand(displayCmd);
      }
    } catch (err: any) {
      addLine({
        type: "error",
        text: "Error: " + (err?.message || String(err) || "Command failed"),
      });
      setLastOutput("");
      setLastCommand("");
    } finally {
      setSending(false);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  };

  /* ── AI Analysis ── */
  const handleAnalyze = async () => {
    if (!lastOutput || !selectedAgent || analyzing) return;

    setAnalyzing(true);
    setAnalysisOpen(true);
    addLine({ type: "system", text: `🤖 Analyzing output of "${lastCommand}" with AI...` });

    try {
      const result = await api.analyzeShellOutput(selectedAgent, lastCommand, lastOutput);
      setAnalysis(result);
      addLine({
        type: "system",
        text: `✅ AI analysis complete — Risk: ${result.risk_level?.toUpperCase()} — ${result.findings?.length ?? 0} finding(s)`,
      });
    } catch (err: any) {
      addLine({
        type: "error",
        text: "AI analysis failed: " + (err?.message || String(err)),
      });
    } finally {
      setAnalyzing(false);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  };

  /* ── Input handlers ── */
  const handleSend = async () => {
    if (!command.trim() || !selectedAgent || sending) return;
    const cmd = command.trim();
    pushCmdHistory(cmd);
    await executeCommand("shell", { command: cmd });
  };

  const handleQuickCommand = async (cmdType: string) => {
    await executeCommand(cmdType);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleSend();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (cmdHistory.length > 0) {
        const next = Math.min(historyIdx + 1, cmdHistory.length - 1);
        setHistoryIdx(next);
        setCommand(cmdHistory[next]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx > 0) {
        const next = historyIdx - 1;
        setHistoryIdx(next);
        setCommand(cmdHistory[next]);
      } else {
        setHistoryIdx(-1);
        setCommand("");
      }
    }
  };

  /* ── SSR hydration guard ── */
  if (!hydrated) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-3rem)]">
        <Loader2 className="w-6 h-6 animate-spin text-sentinel-400" />
      </div>
    );
  }

  /* ── Render ── */
  return (
    <div className="flex flex-col h-[calc(100vh-3rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-sentinel-400" />
            Remote Shell
          </h1>
          <p className="text-sm text-cyber-muted mt-1">Execute commands on connected endpoints</p>
        </div>

        {/* Agent picker */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <select
              value={selectedAgent}
              onChange={(e) => {
                setSelectedAgent(e.target.value);
                setAnalysis(null);
                setLastOutput("");
                setLastCommand("");
                const agent = agents.find((a) => a.id === e.target.value);
                addLine({
                  type: "system",
                  text: `Connected to ${agent?.hostname || "unknown"} (${agent?.os_type || "?"})`,
                });
              }}
              className="input-terminal pr-8 text-xs min-w-[200px]"
            >
              <option value="">Select endpoint...</option>
              {agents.filter((a) => a.status === "online").map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname} ({a.os_type}) - {a.internal_ip}
                </option>
              ))}
            </select>
          </div>
          {selectedAgentInfo && (
            <span className="text-xs text-green-400 bg-green-500/10 px-2 py-1 rounded-full border border-green-500/20">
              {selectedAgentInfo.hostname}
            </span>
          )}
          <button
            onClick={clearHistory}
            className="p-2 text-cyber-muted hover:text-white hover:bg-cyber-hover rounded-lg transition-colors"
            title="Clear terminal"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Quick Scan Buttons + AI Analyze */}
      {selectedAgent && (
        <div className="flex flex-wrap items-center gap-2 mb-3">
          {QUICK_COMMANDS.map((qc) => (
            <button
              key={qc.cmd}
              onClick={() => handleQuickCommand(qc.cmd)}
              disabled={sending || analyzing}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyber-surface border border-cyber-border rounded-lg text-xs text-cyber-muted hover:text-sentinel-400 hover:border-sentinel-600/40 transition-all disabled:opacity-30"
              title={qc.desc}
            >
              <qc.icon className="w-3.5 h-3.5" />
              {qc.label}
            </button>
          ))}

          {/* Separator */}
          <div className="w-px h-6 bg-cyber-border mx-1" />

          {/* AI Analyze Button */}
          <button
            onClick={handleAnalyze}
            disabled={!lastOutput || analyzing || sending}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium transition-all
              ${lastOutput && !analyzing && !sending
                ? "bg-purple-600/20 border border-purple-500/40 text-purple-300 hover:bg-purple-600/30 hover:text-purple-200 hover:border-purple-400/60 hover:shadow-lg hover:shadow-purple-500/10"
                : "bg-cyber-surface border border-cyber-border text-cyber-muted/40 cursor-not-allowed"
              }`}
            title={lastOutput ? `Analyze "${lastCommand}" output with AI` : "Run a command first"}
          >
            {analyzing ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <BrainCircuit className="w-3.5 h-3.5" />
            )}
            {analyzing ? "Analyzing..." : "Analyze with AI"}
          </button>
        </div>
      )}

      {/* Main content area: terminal + optional analysis panel side by side */}
      <div className="flex-1 flex gap-3 min-h-0 overflow-hidden">

        {/* Terminal column: output + fixed input bar */}
        <div className="flex-1 min-w-0 flex flex-col min-h-0">
          {/* Scrollable terminal output */}
          <div
            ref={scrollRef}
            className="flex-1 min-h-0 bg-[#0a0a0a] border border-cyber-border rounded-t-xl p-4 overflow-y-auto font-mono text-sm"
            onClick={() => inputRef.current?.focus()}
          >
            {history.map((line, i) => (
              <div key={i} className="py-0.5">
                {line.type === "input" ? (
                  <div className="flex items-start gap-2">
                    <span className="text-sentinel-400 shrink-0">$</span>
                    <span className="text-white">{line.text}</span>
                  </div>
                ) : line.type === "error" ? (
                  <span className="text-red-400">{line.text}</span>
                ) : line.type === "system" ? (
                  <span className="text-cyber-muted italic">{line.text}</span>
                ) : (
                  <pre className="text-cyber-text whitespace-pre-wrap break-all">{line.text}</pre>
                )}
              </div>
            ))}
            {sending && (
              <div className="flex items-center gap-2 py-1 text-cyber-muted">
                <Loader2 className="w-3 h-3 animate-spin" />
                <span className="text-xs">Executing on {selectedAgentInfo?.hostname}...</span>
              </div>
            )}
          </div>

          {/* Input bar — always visible, pinned below terminal */}
          <div className="shrink-0 flex items-center bg-[#0a0a0a] border border-t-0 border-cyber-border rounded-b-xl px-4 py-3">
            <span className="text-sentinel-400 mr-2 text-sm">$</span>
            <input
              ref={inputRef}
              type="text"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={selectedAgent ? "Enter shell command..." : "Select an endpoint first..."}
              disabled={!selectedAgent || sending}
              className="flex-1 bg-transparent text-white text-sm placeholder-cyber-muted/50 focus:outline-none disabled:opacity-50"
              autoFocus
            />
            <button
              onClick={handleSend}
              disabled={!command.trim() || !selectedAgent || sending}
              className="p-1.5 bg-sentinel-600 hover:bg-sentinel-700 disabled:opacity-30 rounded-lg transition-colors ml-2"
            >
              <Send className="w-3.5 h-3.5 text-white" />
            </button>
          </div>
        </div>

        {/* ── AI Analysis Panel ── */}
        {analysis && (
          <div className="w-[420px] shrink-0 flex flex-col min-h-0 bg-cyber-surface border border-cyber-border rounded-xl overflow-hidden">
            {/* Panel header */}
            <div className="shrink-0 flex items-center justify-between px-4 py-3 border-b border-cyber-border bg-cyber-surface/80">
              <div className="flex items-center gap-2">
                <BrainCircuit className="w-4 h-4 text-purple-400" />
                <span className="text-sm font-semibold text-white">AI Analysis</span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${RISK_COLORS[analysis.risk_level] || RISK_COLORS.unknown}`}>
                  {analysis.risk_level}
                </span>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setAnalysisOpen(!analysisOpen)}
                  className="p-1 text-cyber-muted hover:text-white rounded transition-colors"
                >
                  {analysisOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => setAnalysis(null)}
                  className="p-1 text-cyber-muted hover:text-red-400 rounded transition-colors"
                  title="Close analysis"
                >
                  <XCircle className="w-4 h-4" />
                </button>
              </div>
            </div>

            {analysisOpen && (
              <div className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4 text-sm">
                {/* Summary */}
                <div>
                  <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-1">Summary</h3>
                  <p className="text-cyber-text leading-relaxed">{analysis.summary}</p>
                </div>

                {/* Findings */}
                {analysis.findings && analysis.findings.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">
                      Findings ({analysis.findings.length})
                    </h3>
                    <div className="space-y-2">
                      {analysis.findings.map((f: ShellFinding, i: number) => {
                        const SevIcon = SEVERITY_ICONS[f.severity] || Info;
                        return (
                          <div key={i} className={`p-3 rounded-lg border ${RISK_COLORS[f.severity] || RISK_COLORS.unknown}`}>
                            <div className="flex items-start gap-2">
                              <SevIcon className="w-4 h-4 shrink-0 mt-0.5" />
                              <div className="min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="font-medium text-white text-xs">{f.title}</span>
                                  {f.mitre_technique && (
                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/5 text-cyber-muted border border-white/10">
                                      {f.mitre_technique}
                                    </span>
                                  )}
                                </div>
                                <p className="text-xs text-cyber-text/80 mt-1 leading-relaxed">{f.description}</p>
                                {f.evidence && (
                                  <pre className="text-[10px] text-cyber-muted bg-black/30 rounded px-2 py-1 mt-1.5 overflow-x-auto whitespace-pre-wrap break-all">
                                    {f.evidence}
                                  </pre>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* No findings */}
                {analysis.findings && analysis.findings.length === 0 && (
                  <div className="flex items-center gap-2 p-3 rounded-lg bg-green-500/5 border border-green-500/20 text-green-400">
                    <CheckCircle className="w-4 h-4" />
                    <span className="text-xs">No security issues detected.</span>
                  </div>
                )}

                {/* MITRE ATT&CK */}
                {analysis.mitre_techniques && analysis.mitre_techniques.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">MITRE ATT&CK</h3>
                    <div className="flex flex-wrap gap-1.5">
                      {analysis.mitre_techniques.map((t: string, i: number) => (
                        <a
                          key={i}
                          href={`https://attack.mitre.org/techniques/${t.replace(".", "/")}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-[10px] px-2 py-1 rounded bg-red-500/10 text-red-300 border border-red-500/20 hover:bg-red-500/20 transition-colors"
                        >
                          {t}
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {analysis.recommendations && analysis.recommendations.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold text-cyber-muted uppercase tracking-wider mb-2">Recommendations</h3>
                    <ul className="space-y-1.5">
                      {analysis.recommendations.map((r: string, i: number) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-cyber-text">
                          <span className="text-sentinel-400 shrink-0 mt-0.5">›</span>
                          <span className="leading-relaxed">{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Confidence */}
                {analysis.confidence !== undefined && (
                  <div className="flex items-center justify-between text-[10px] text-cyber-muted pt-2 border-t border-cyber-border">
                    <span>Confidence: {Math.round(analysis.confidence * 100)}%</span>
                    <span className="opacity-50">{analysis.status === "completed_with_fallback" ? "Pattern matching" : "AI analysis"}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
