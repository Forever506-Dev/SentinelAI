/**
 * Zustand store for Remote Shell state.
 *
 * Persists terminal history, AI analysis results, command history
 * and selected agent across page navigations using sessionStorage
 * (cleared on tab close, survives in-app route changes).
 */
import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { ShellAnalysisResult } from "./api";

/* ───────── Types ───────── */

export interface ShellLine {
  type: "input" | "output" | "error" | "system";
  text: string;
  /** ISO-8601 string (Date is not serialisable to JSON) */
  ts: string;
  command?: string;
}

interface TerminalState {
  /* ── Data ── */
  history: ShellLine[];
  cmdHistory: string[];
  historyIdx: number;
  command: string;

  lastCommand: string;
  lastOutput: string;

  analysis: ShellAnalysisResult | null;
  analysisOpen: boolean;

  selectedAgent: string;

  /* ── Actions ── */
  addLine: (line: Omit<ShellLine, "ts"> & { ts?: string }) => void;
  clearHistory: () => void;
  setCommand: (cmd: string) => void;
  pushCmdHistory: (cmd: string) => void;
  setHistoryIdx: (idx: number) => void;
  setLastCommand: (cmd: string) => void;
  setLastOutput: (out: string) => void;
  setAnalysis: (a: ShellAnalysisResult | null) => void;
  setAnalysisOpen: (open: boolean) => void;
  setSelectedAgent: (id: string) => void;
}

/* ───────── Defaults ───────── */

const INITIAL_LINES: ShellLine[] = [
  { type: "system", text: "SentinelAI Remote Shell v0.3.0 — AI-powered analysis ready", ts: new Date().toISOString() },
  { type: "system", text: "Select an endpoint to begin. Type commands or use Quick Scan buttons.", ts: new Date().toISOString() },
];

/* ───────── Store ───────── */

export const useTerminalStore = create<TerminalState>()(
  persist(
    (set) => ({
      /* ── Initial data ── */
      history: INITIAL_LINES,
      cmdHistory: [],
      historyIdx: -1,
      command: "",
      lastCommand: "",
      lastOutput: "",
      analysis: null,
      analysisOpen: true,
      selectedAgent: "",

      /* ── Actions ── */
      addLine: (line) =>
        set((s) => ({
          history: [
            ...s.history,
            { ...line, ts: line.ts ?? new Date().toISOString() },
          ],
        })),

      clearHistory: () =>
        set({
          history: [{ type: "system", text: "Terminal cleared.", ts: new Date().toISOString() }],
          analysis: null,
          lastOutput: "",
          lastCommand: "",
        }),

      setCommand: (cmd) => set({ command: cmd }),

      pushCmdHistory: (cmd) =>
        set((s) => ({
          cmdHistory: [cmd, ...s.cmdHistory].slice(0, 50),
          historyIdx: -1,
          command: "",
        })),

      setHistoryIdx: (idx) => set({ historyIdx: idx }),

      setLastCommand: (cmd) => set({ lastCommand: cmd }),
      setLastOutput: (out) => set({ lastOutput: out }),

      setAnalysis: (a) => set({ analysis: a }),
      setAnalysisOpen: (open) => set({ analysisOpen: open }),

      setSelectedAgent: (id) => set({ selectedAgent: id }),
    }),
    {
      name: "sentinel-terminal",
      storage: createJSONStorage(() =>
        typeof window !== "undefined" ? sessionStorage : {
          getItem: () => null,
          setItem: () => {},
          removeItem: () => {},
        }
      ),
      // Only persist the fields that matter across navigation.
      // Transient UI flags (sending, analyzing) stay in component state.
      partialize: (state) => ({
        history: state.history,
        cmdHistory: state.cmdHistory,
        lastCommand: state.lastCommand,
        lastOutput: state.lastOutput,
        analysis: state.analysis,
        analysisOpen: state.analysisOpen,
        selectedAgent: state.selectedAgent,
      }),
    },
  ),
);
