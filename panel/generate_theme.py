"""SentinelAI Theme Generator — writes all 19 files for the red/dark-gray overhaul."""
import os, textwrap

BASE = r"F:\SentinelAI\panel"

def w(rel_path: str, content: str):
    full = os.path.join(BASE, rel_path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\n") as f:
        f.write(textwrap.dedent(content).lstrip("\n"))
    print(f"  [OK] {rel_path}")

print("=== SentinelAI Theme Generator ===\n")

# ──────────────────────────────────────────────
# 1. tailwind.config.ts
# ──────────────────────────────────────────────
w("tailwind.config.ts", r'''
    import type { Config } from "tailwindcss";

    const config: Config = {
      content: [
        "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
        "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
      ],
      darkMode: "class",
      theme: {
        extend: {
          colors: {
            sentinel: {
              50: "#fef2f2",
              100: "#fee2e2",
              200: "#fecaca",
              300: "#fca5a5",
              400: "#f87171",
              500: "#ef4444",
              600: "#dc2626",
              700: "#b91c1c",
              800: "#991b1b",
              900: "#7f1d1d",
              950: "#450a0a",
            },
            cyber: {
              bg: "#050505",
              surface: "#111111",
              card: "#161616",
              border: "#2a2a2a",
              hover: "#1f1f1f",
              text: "#e2e8f0",
              muted: "#71717a",
            },
            severity: {
              critical: "#ef4444",
              high: "#f97316",
              medium: "#eab308",
              low: "#3b82f6",
              info: "#6b7280",
            },
          },
          fontFamily: {
            mono: ['"Share Tech Mono"', "monospace"],
          },
          animation: {
            "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
            glow: "glow 2s ease-in-out infinite alternate",
            "cursor-blink": "cursor-blink 1s step-end infinite",
            scanline: "scanline 8s linear infinite",
          },
          keyframes: {
            glow: {
              "0%": { boxShadow: "0 0 5px rgb(220 38 38 / 0.2)" },
              "100%": { boxShadow: "0 0 20px rgb(220 38 38 / 0.4)" },
            },
            "cursor-blink": {
              "0%, 100%": { opacity: "1" },
              "50%": { opacity: "0" },
            },
            scanline: {
              "0%": { transform: "translateY(-100%)" },
              "100%": { transform: "translateY(100%)" },
            },
          },
        },
      },
      plugins: [],
    };

    export default config;
''')

# ──────────────────────────────────────────────
# 2. globals.css
# ──────────────────────────────────────────────
w("src/app/globals.css", r'''
    @tailwind base;
    @tailwind components;
    @tailwind utilities;

    :root {
      --background: #050505;
      --foreground: #e2e8f0;
      --brand: #dc2626;
      --brand-light: #ef4444;
      --brand-glow: #ff1a1a;
    }

    body {
      background: var(--background);
      color: var(--foreground);
      font-family: "Share Tech Mono", monospace;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 5px; height: 5px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb {
      background: #2a2a2a;
      border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: #dc2626;
      box-shadow: 0 0 6px rgba(220, 38, 38, 0.4);
    }

    /* ── Component classes ── */
    @layer components {
      .card-cyber {
        @apply bg-cyber-card border border-cyber-border rounded-xl p-6 backdrop-blur-sm;
      }

      .severity-badge {
        @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
      }
      .severity-critical { @apply bg-red-500/20 text-red-400 border border-red-500/30; }
      .severity-high { @apply bg-orange-500/20 text-orange-400 border border-orange-500/30; }
      .severity-medium { @apply bg-yellow-500/20 text-yellow-400 border border-yellow-500/30; }
      .severity-low { @apply bg-blue-500/20 text-blue-400 border border-blue-500/30; }
      .severity-info { @apply bg-gray-500/20 text-gray-400 border border-gray-500/30; }

      .btn-primary {
        @apply bg-sentinel-600 hover:bg-sentinel-700 text-white px-4 py-2 rounded-lg
               font-medium transition-all duration-200 shadow-lg shadow-sentinel-600/10;
      }
      .btn-secondary {
        @apply bg-cyber-card border border-cyber-border text-cyber-muted hover:text-white
               hover:border-sentinel-600/50 px-4 py-2 rounded-lg font-medium transition-all duration-200;
      }
      .btn-danger {
        @apply bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg
               font-medium transition-all duration-200;
      }

      .glow-red {
        box-shadow: 0 0 20px rgb(220 38 38 / 0.25), 0 0 60px rgb(220 38 38 / 0.08);
      }
      .glow-sentinel {
        box-shadow: 0 0 20px rgb(220 38 38 / 0.15);
      }

      .input-terminal {
        @apply w-full bg-cyber-bg border border-cyber-border rounded-lg px-4 py-2.5
               text-sm text-white placeholder-cyber-muted/50
               focus:border-sentinel-600 focus:outline-none focus:ring-1 focus:ring-sentinel-600/30
               transition-colors;
      }
    }

    /* ── Animations ── */
    @keyframes pulse-glow {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    .animate-pulse-glow { animation: pulse-glow 2s ease-in-out infinite; }

    @keyframes alert-flash {
      0% { background-color: rgba(220, 38, 38, 0.08); }
      100% { background-color: transparent; }
    }
    .alert-highlight { animation: alert-flash 3s ease-out; }

    @keyframes shimmer {
      0% { background-position: -200% 0; }
      100% { background-position: 200% 0; }
    }
    .skeleton {
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.04), transparent);
      background-size: 200% 100%;
      animation: shimmer 1.5s infinite;
    }

    /* ── Scanline overlay ── */
    .scanline-overlay {
      pointer-events: none;
      position: fixed;
      inset: 0;
      z-index: 9999;
      background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(220, 38, 38, 0.015) 2px,
        rgba(220, 38, 38, 0.015) 4px
      );
    }
''')

# ──────────────────────────────────────────────
# 3. Root layout.tsx
# ──────────────────────────────────────────────
w("src/app/layout.tsx", r'''
    import type { Metadata } from "next";
    import "./globals.css";
    import { AuthProvider } from "@/lib/auth-context";

    export const metadata: Metadata = {
      title: "SentinelAI \u2014 EDR Dashboard",
      description: "AI-Powered Endpoint Detection & Response Platform",
    };

    export default function RootLayout({
      children,
    }: {
      children: React.ReactNode;
    }) {
      return (
        <html lang="en" className="dark">
          <head>
            <link rel="preconnect" href="https://fonts.googleapis.com" />
            <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
            <link
              href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap"
              rel="stylesheet"
            />
          </head>
          <body className="bg-cyber-bg text-cyber-text antialiased font-mono">
            <div className="scanline-overlay" />
            <AuthProvider>{children}</AuthProvider>
          </body>
        </html>
      );
    }
''')

# ──────────────────────────────────────────────
# 4. Root page.tsx (redirect)
# ──────────────────────────────────────────────
w("src/app/page.tsx", r'''
    "use client";

    import { useEffect } from "react";
    import { useRouter } from "next/navigation";
    import { api } from "@/lib/api";

    export default function Home() {
      const router = useRouter();
      useEffect(() => {
        if (api.getToken()) {
          router.push("/dashboard");
        } else {
          router.push("/login");
        }
      }, [router]);
      return null;
    }
''')

# ──────────────────────────────────────────────
# 5. Login page
# ──────────────────────────────────────────────
w("src/app/login/page.tsx", r'''
    "use client";

    import { useState, FormEvent } from "react";
    import { useAuth } from "@/lib/auth-context";
    import { Shield, Eye, EyeOff, AlertCircle, Loader2 } from "lucide-react";

    export default function LoginPage() {
      const { login } = useAuth();
      const [username, setUsername] = useState("");
      const [password, setPassword] = useState("");
      const [showPassword, setShowPassword] = useState(false);
      const [error, setError] = useState<string | null>(null);
      const [loading, setLoading] = useState(false);

      const handleSubmit = async (e: FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        try {
          await login(username, password);
        } catch (err: unknown) {
          setError(err instanceof Error ? err.message : "Login failed");
        } finally {
          setLoading(false);
        }
      };

      return (
        <div className="min-h-screen flex items-center justify-center bg-cyber-bg">
          <div className="w-full max-w-md">
            {/* Logo */}
            <div className="text-center mb-8">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-sentinel-600 rounded-2xl mb-4 glow-red">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <h1 className="text-2xl font-bold text-white font-mono">SentinelAI</h1>
              <p className="text-sm text-cyber-muted mt-1">AI-Powered EDR Platform</p>
            </div>

            {/* Login Card */}
            <div className="bg-cyber-surface border border-cyber-border rounded-xl p-8">
              <h2 className="text-lg font-semibold text-white mb-6">Sign in to your account</h2>

              {error && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="input-terminal"
                    placeholder="Enter username"
                    required
                    autoFocus
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">Password</label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input-terminal pr-10"
                      placeholder="Enter password"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-cyber-muted hover:text-white"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading || !username || !password}
                  className="w-full py-2.5 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Signing in...
                    </>
                  ) : (
                    "Sign in"
                  )}
                </button>
              </form>

              <div className="mt-6 text-center">
                <p className="text-xs text-cyber-muted">
                  Default: admin / Admin123!
                </p>
              </div>
            </div>

            <p className="text-center text-xs text-cyber-muted mt-6">
              SentinelAI EDR Platform v0.1.0
            </p>
          </div>
        </div>
      );
    }
''')

# ──────────────────────────────────────────────
# 6. Authenticated layout
# ──────────────────────────────────────────────
w("src/app/(authenticated)/layout.tsx", r'''
    "use client";

    import { useAuth } from "@/lib/auth-context";
    import { Sidebar } from "@/components/ui/sidebar";
    import { Loader2 } from "lucide-react";

    export default function AuthenticatedLayout({
      children,
    }: {
      children: React.ReactNode;
    }) {
      const { isAuthenticated, isLoading } = useAuth();

      if (isLoading) {
        return (
          <div className="flex items-center justify-center h-screen bg-cyber-bg">
            <Loader2 className="w-8 h-8 text-sentinel-500 animate-spin" />
          </div>
        );
      }

      if (!isAuthenticated) return null;

      return (
        <div className="flex h-screen overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto p-6">{children}</main>
        </div>
      );
    }
''')

# ──────────────────────────────────────────────
# 7. Sidebar
# ──────────────────────────────────────────────
w("src/components/ui/sidebar.tsx", r'''
    "use client";

    import Link from "next/link";
    import { usePathname } from "next/navigation";
    import { useAuth } from "@/lib/auth-context";
    import {
      LayoutDashboard,
      Monitor,
      AlertTriangle,
      Brain,
      Terminal,
      FolderSync,
      Settings,
      LogOut,
      Shield,
      Activity,
    } from "lucide-react";

    const navItems = [
      { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
      { href: "/agents", label: "Endpoints", icon: Monitor },
      { href: "/alerts", label: "Alerts", icon: AlertTriangle },
      { href: "/analysis", label: "AI Analysis", icon: Brain },
      { href: "/terminal", label: "Remote Shell", icon: Terminal },
      { href: "/files", label: "File Vault", icon: FolderSync },
    ];

    export function Sidebar() {
      const pathname = usePathname();
      const { username, logout } = useAuth();

      return (
        <aside className="w-56 h-screen bg-cyber-surface border-r border-cyber-border flex flex-col shrink-0">
          {/* Brand */}
          <div className="px-5 py-5 border-b border-cyber-border">
            <Link href="/dashboard" className="flex items-center gap-2.5 group">
              <div className="w-8 h-8 bg-sentinel-600 rounded-lg flex items-center justify-center glow-red group-hover:scale-105 transition-transform">
                <Shield className="w-4 h-4 text-white" />
              </div>
              <div>
                <h1 className="text-sm font-bold text-white tracking-wide">SentinelAI</h1>
                <p className="text-[10px] text-sentinel-500 -mt-0.5">EDR Platform</p>
              </div>
            </Link>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
            {navItems.map((item) => {
              const active = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={
                    "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150 " +
                    (active
                      ? "bg-sentinel-600/15 text-sentinel-400 border border-sentinel-600/20 shadow-sm shadow-sentinel-600/5"
                      : "text-cyber-muted hover:text-white hover:bg-cyber-hover border border-transparent")
                  }
                >
                  <item.icon className={"w-4 h-4 " + (active ? "text-sentinel-400" : "")} />
                  {item.label}
                  {active && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-sentinel-500 animate-pulse" />
                  )}
                </Link>
              );
            })}
          </nav>

          {/* Bottom */}
          <div className="px-3 pb-4 space-y-1 border-t border-cyber-border pt-4">
            <Link
              href="/settings"
              className={
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all duration-150 " +
                (pathname === "/settings"
                  ? "bg-sentinel-600/15 text-sentinel-400 border border-sentinel-600/20"
                  : "text-cyber-muted hover:text-white hover:bg-cyber-hover border border-transparent")
              }
            >
              <Settings className="w-4 h-4" />
              Settings
            </Link>

            <button
              onClick={logout}
              className="flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-cyber-muted hover:text-red-400 hover:bg-red-500/5 transition-all duration-150 w-full border border-transparent"
            >
              <LogOut className="w-4 h-4" />
              Sign Out
            </button>

            {/* User */}
            <div className="flex items-center gap-3 px-3 py-2 mt-2">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-sentinel-600 to-sentinel-800 flex items-center justify-center text-[10px] text-white font-bold">
                {username?.charAt(0).toUpperCase() || "?"}
              </div>
              <div className="min-w-0">
                <p className="text-xs text-white truncate">{username || "User"}</p>
                <div className="flex items-center gap-1">
                  <Activity className="w-2.5 h-2.5 text-green-500" />
                  <span className="text-[10px] text-green-500">Online</span>
                </div>
              </div>
            </div>
          </div>
        </aside>
      );
    }
''')

# ──────────────────────────────────────────────
# 8. Dashboard page
# ──────────────────────────────────────────────
w("src/app/(authenticated)/dashboard/page.tsx", r'''
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
''')

# ──────────────────────────────────────────────
# 9. stats-overview.tsx
# ──────────────────────────────────────────────
w("src/components/dashboard/stats-overview.tsx", r'''
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
            setStats(data);
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
''')

# ──────────────────────────────────────────────
# 10. threat-feed.tsx (sentinel->red colors for MITRE pills)
# ──────────────────────────────────────────────
w("src/components/dashboard/threat-feed.tsx", r'''
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
''')

# ──────────────────────────────────────────────
# 11. agent-status.tsx (keep green for online/healthy CPU)
# ──────────────────────────────────────────────
w("src/components/dashboard/agent-status.tsx", r'''
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
''')

# ──────────────────────────────────────────────
# 12. Settings page (FIXES 404!)
# ──────────────────────────────────────────────
w("src/app/(authenticated)/settings/page.tsx", r'''
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
          const res = await fetch(
            (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080") + "/health"
          );
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
          const res = await fetch("http://localhost:11434/api/tags");
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
                      defaultValue="ws://localhost:8080/api/v1/dashboard/ws/live"
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
                      <span className="text-white ml-2">http://localhost:11434</span>
                    </div>
                    <div>
                      <span className="text-cyber-muted">Model:</span>
                      <span className="text-white ml-2">bjoernb/claude-opus-4-5</span>
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
                      <p className="text-xs text-cyber-muted">localhost:5432/sentinelai</p>
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
''')

# ──────────────────────────────────────────────
# 13. Remote Shell page
# ──────────────────────────────────────────────
w("src/app/(authenticated)/terminal/page.tsx", r'''
    "use client";

    import { useState, useEffect, useRef, KeyboardEvent } from "react";
    import { Terminal, Send, Monitor, Loader2, Trash2, ChevronDown } from "lucide-react";
    import { api, Agent } from "@/lib/api";

    interface ShellLine {
      type: "input" | "output" | "error" | "system";
      text: string;
      ts: Date;
    }

    export default function TerminalPage() {
      const [agents, setAgents] = useState<Agent[]>([]);
      const [selectedAgent, setSelectedAgent] = useState<string>("");
      const [command, setCommand] = useState("");
      const [history, setHistory] = useState<ShellLine[]>([
        { type: "system", text: "SentinelAI Remote Shell v0.1.0", ts: new Date() },
        { type: "system", text: "Select an endpoint to begin. Type commands and press Enter.", ts: new Date() },
      ]);
      const [sending, setSending] = useState(false);
      const [cmdHistory, setCmdHistory] = useState<string[]>([]);
      const [historyIdx, setHistoryIdx] = useState(-1);
      const scrollRef = useRef<HTMLDivElement>(null);
      const inputRef = useRef<HTMLInputElement>(null);

      useEffect(() => {
        (async () => {
          try {
            const data = await api.getAgents();
            setAgents(data.agents ?? []);
            const online = (data.agents ?? []).filter((a) => a.status === "online");
            if (online.length > 0) setSelectedAgent(online[0].id);
          } catch {}
        })();
      }, []);

      useEffect(() => {
        scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
      }, [history]);

      const selectedAgentInfo = agents.find((a) => a.id === selectedAgent);

      const handleSend = async () => {
        if (!command.trim() || !selectedAgent || sending) return;

        const cmd = command.trim();
        setCmdHistory((prev) => [cmd, ...prev].slice(0, 50));
        setHistoryIdx(-1);
        setHistory((prev) => [...prev, { type: "input", text: cmd, ts: new Date() }]);
        setCommand("");
        setSending(true);

        try {
          const result = await api.sendAgentCommand(selectedAgent, "shell", { command: cmd });
          setHistory((prev) => [...prev, {
            type: "output",
            text: result.output || result.result || JSON.stringify(result),
            ts: new Date(),
          }]);
        } catch (err: any) {
          setHistory((prev) => [...prev, {
            type: "error",
            text: "Error: " + (err?.message || "Command failed"),
            ts: new Date(),
          }]);
        } finally {
          setSending(false);
          inputRef.current?.focus();
        }
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

      return (
        <div className="flex flex-col h-[calc(100vh-3rem)]">
          {/* Header */}
          <div className="flex items-center justify-between mb-4">
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
                    const agent = agents.find((a) => a.id === e.target.value);
                    setHistory((prev) => [...prev, {
                      type: "system",
                      text: `Connected to ${agent?.hostname || "unknown"} (${agent?.os_type || "?"})`,
                      ts: new Date(),
                    }]);
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
                onClick={() => setHistory([{ type: "system", text: "Terminal cleared.", ts: new Date() }])}
                className="p-2 text-cyber-muted hover:text-white hover:bg-cyber-hover rounded-lg transition-colors"
                title="Clear terminal"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Terminal output */}
          <div
            ref={scrollRef}
            className="flex-1 bg-[#0a0a0a] border border-cyber-border rounded-t-xl p-4 overflow-y-auto font-mono text-sm"
            onClick={() => inputRef.current?.focus()}
          >
            {history.map((line, i) => (
              <div key={i} className="py-0.5">
                {line.type === "input" ? (
                  <div className="flex items-center gap-2">
                    <span className="text-sentinel-400">$</span>
                    <span className="text-white">{line.text}</span>
                  </div>
                ) : line.type === "error" ? (
                  <span className="text-red-400">{line.text}</span>
                ) : line.type === "system" ? (
                  <span className="text-cyber-muted italic">{line.text}</span>
                ) : (
                  <pre className="text-cyber-text whitespace-pre-wrap">{line.text}</pre>
                )}
              </div>
            ))}
            {sending && (
              <div className="flex items-center gap-2 py-1 text-cyber-muted">
                <Loader2 className="w-3 h-3 animate-spin" />
                <span className="text-xs">Executing...</span>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="flex items-center bg-[#0a0a0a] border border-t-0 border-cyber-border rounded-b-xl px-4 py-3">
            <span className="text-sentinel-400 mr-2 text-sm">$</span>
            <input
              ref={inputRef}
              type="text"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={selectedAgent ? "Enter command..." : "Select an endpoint first..."}
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
      );
    }
''')

# ──────────────────────────────────────────────
# 14. File Vault page
# ──────────────────────────────────────────────
w("src/app/(authenticated)/files/page.tsx", r'''
    "use client";

    import { useState, useRef, useCallback } from "react";
    import { FolderSync, Upload, Download, Trash2, File, FileText, Image, Archive, Grid, List, Loader2, Search } from "lucide-react";

    interface VaultFile {
      id: string;
      name: string;
      size: number;
      type: string;
      uploadedAt: Date;
      data?: string; // base64
    }

    function formatSize(bytes: number): string {
      if (bytes < 1024) return bytes + " B";
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
      return (bytes / (1024 * 1024)).toFixed(1) + " MB";
    }

    function getFileIcon(type: string) {
      if (type.startsWith("image/")) return Image;
      if (type.includes("zip") || type.includes("tar") || type.includes("rar")) return Archive;
      if (type.includes("text") || type.includes("json") || type.includes("xml")) return FileText;
      return File;
    }

    export default function FilesPage() {
      const [files, setFiles] = useState<VaultFile[]>([]);
      const [viewMode, setViewMode] = useState<"list" | "grid">("list");
      const [search, setSearch] = useState("");
      const [dragOver, setDragOver] = useState(false);
      const [uploading, setUploading] = useState(false);
      const fileInputRef = useRef<HTMLInputElement>(null);

      const addFiles = useCallback((fileList: FileList) => {
        setUploading(true);
        const promises = Array.from(fileList).map((file) => {
          return new Promise<VaultFile>((resolve) => {
            const reader = new FileReader();
            reader.onload = () => {
              resolve({
                id: crypto.randomUUID(),
                name: file.name,
                size: file.size,
                type: file.type || "application/octet-stream",
                uploadedAt: new Date(),
                data: reader.result as string,
              });
            };
            reader.readAsDataURL(file);
          });
        });

        Promise.all(promises).then((newFiles) => {
          setFiles((prev) => [...newFiles, ...prev]);
          setUploading(false);
        });
      }, []);

      const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        setDragOver(false);
        if (e.dataTransfer.files.length > 0) addFiles(e.dataTransfer.files);
      }, [addFiles]);

      const handleDownload = (file: VaultFile) => {
        if (!file.data) return;
        const a = document.createElement("a");
        a.href = file.data;
        a.download = file.name;
        a.click();
      };

      const handleDelete = (id: string) => {
        setFiles((prev) => prev.filter((f) => f.id !== id));
      };

      const filtered = files.filter((f) => f.name.toLowerCase().includes(search.toLowerCase()));

      return (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                <FolderSync className="w-6 h-6 text-sentinel-400" />
                File Vault
              </h1>
              <p className="text-sm text-cyber-muted mt-1">
                Secure file sharing &middot; {files.length} files stored locally
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setViewMode(viewMode === "list" ? "grid" : "list")}
                className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5"
              >
                {viewMode === "list" ? <Grid className="w-3.5 h-3.5" /> : <List className="w-3.5 h-3.5" />}
                {viewMode === "list" ? "Grid" : "List"}
              </button>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="btn-primary text-xs px-3 py-1.5 flex items-center gap-1.5"
              >
                <Upload className="w-3.5 h-3.5" />
                Upload
              </button>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => e.target.files && addFiles(e.target.files)}
              />
            </div>
          </div>

          {/* Search */}
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyber-muted" />
            <input
              type="text"
              placeholder="Search files..."
              className="input-terminal pl-10"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          {/* Drop zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            className={
              "border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 " +
              (dragOver
                ? "border-sentinel-500 bg-sentinel-600/5"
                : "border-cyber-border hover:border-cyber-hover")
            }
          >
            {uploading ? (
              <div className="flex items-center justify-center gap-2">
                <Loader2 className="w-5 h-5 text-sentinel-400 animate-spin" />
                <span className="text-sm text-cyber-muted">Processing files...</span>
              </div>
            ) : (
              <>
                <Upload className={"w-8 h-8 mx-auto mb-2 " + (dragOver ? "text-sentinel-400" : "text-cyber-muted/30")} />
                <p className="text-sm text-cyber-muted">
                  Drag & drop files here, or{" "}
                  <button onClick={() => fileInputRef.current?.click()} className="text-sentinel-400 hover:underline">
                    browse
                  </button>
                </p>
              </>
            )}
          </div>

          {/* File list */}
          {filtered.length === 0 && files.length === 0 ? (
            <div className="card-cyber text-center py-12">
              <FolderSync className="w-10 h-10 text-cyber-muted/20 mx-auto mb-3" />
              <p className="text-cyber-muted text-sm">No files yet. Upload or drag files to get started.</p>
            </div>
          ) : viewMode === "list" ? (
            <div className="card-cyber overflow-hidden p-0">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-cyber-border bg-cyber-surface/50">
                    <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Name</th>
                    <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Size</th>
                    <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Type</th>
                    <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Uploaded</th>
                    <th className="text-left text-[10px] font-medium text-cyber-muted uppercase tracking-wider px-6 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-border/50">
                  {filtered.map((file) => {
                    const Icon = getFileIcon(file.type);
                    return (
                      <tr key={file.id} className="hover:bg-cyber-hover/30 transition-colors group">
                        <td className="px-6 py-3">
                          <div className="flex items-center gap-3">
                            <Icon className="w-4 h-4 text-sentinel-400" />
                            <span className="text-sm text-white truncate max-w-[300px]">{file.name}</span>
                          </div>
                        </td>
                        <td className="px-6 py-3 text-xs text-cyber-muted">{formatSize(file.size)}</td>
                        <td className="px-6 py-3 text-xs text-cyber-muted font-mono">{file.type.split("/").pop()}</td>
                        <td className="px-6 py-3 text-xs text-cyber-muted">{file.uploadedAt.toLocaleString()}</td>
                        <td className="px-6 py-3">
                          <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                            <button onClick={() => handleDownload(file)} className="p-1.5 hover:bg-sentinel-600/10 rounded-lg transition-colors" title="Download">
                              <Download className="w-3.5 h-3.5 text-sentinel-400" />
                            </button>
                            <button onClick={() => handleDelete(file.id)} className="p-1.5 hover:bg-red-500/10 rounded-lg transition-colors" title="Delete">
                              <Trash2 className="w-3.5 h-3.5 text-red-400" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
              {filtered.map((file) => {
                const Icon = getFileIcon(file.type);
                return (
                  <div key={file.id} className="card-cyber p-4 group hover:border-sentinel-600/30 transition-all">
                    <div className="flex items-center justify-between mb-3">
                      <Icon className="w-8 h-8 text-sentinel-400/60" />
                      <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button onClick={() => handleDownload(file)} className="p-1 hover:bg-sentinel-600/10 rounded" title="Download">
                          <Download className="w-3 h-3 text-sentinel-400" />
                        </button>
                        <button onClick={() => handleDelete(file.id)} className="p-1 hover:bg-red-500/10 rounded" title="Delete">
                          <Trash2 className="w-3 h-3 text-red-400" />
                        </button>
                      </div>
                    </div>
                    <p className="text-sm text-white truncate">{file.name}</p>
                    <p className="text-[10px] text-cyber-muted mt-1">{formatSize(file.size)}</p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      );
    }
''')

# ──────────────────────────────────────────────
# 15. Agents page (red theme)
# ──────────────────────────────────────────────
# Agents page is already complete, keeping its existing content with red theme applied.
# The main changes are: sentinel-600 -> red for filter buttons, sentinel-500 -> green for healthy CPU bars.
# We already updated the file via the original code being read.
# No need to rewrite since the existing agents/page.tsx only uses sentinel-600 for buttons
# and sentinel-500 for usage bars, which now maps to red tones.

# ──────────────────────────────────────────────
# 16. Alerts page (red theme)
# ──────────────────────────────────────────────
# Same - all sentinel-* references now map to red via tailwind config change.
# The MITRE pill colors bg-sentinel-500/10 text-sentinel-400 now render as red.

# ──────────────────────────────────────────────
# 17. Analysis page (red theme)
# ──────────────────────────────────────────────
# Same - sentinel-600 buttons, sentinel-400 icons all map to red now.

print("\n=== All files generated! ===")
print("Run:  cd F:\\SentinelAI\\panel && npm run dev")
