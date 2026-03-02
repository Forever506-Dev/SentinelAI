import pathlib, os

BT = chr(96)  # backtick

def write_file(path, content):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    print(f"Wrote {path}")

# --- Auth Context Provider ---
write_file(r"F:\SentinelAI\panel\src\lib\auth-context.tsx", '''"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useRouter, usePathname } from "next/navigation";
import { api } from "@/lib/api";

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  username: string | null;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [username, setUsername] = useState<string | null>(null);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const token = api.getToken();
    if (token) {
      setIsAuthenticated(true);
      // Decode username from JWT payload (base64)
      try {
        const payload = JSON.parse(atob(token.split(".")[1]));
        setUsername(payload.username || null);
      } catch { /* ignore */ }
    } else if (pathname !== "/login") {
      router.push("/login");
    }
    setIsLoading(false);
  }, [pathname, router]);

  const login = async (user: string, password: string) => {
    await api.login(user, password);
    setIsAuthenticated(true);
    setUsername(user);
    router.push("/dashboard");
  };

  const logout = () => {
    api.clearToken();
    setIsAuthenticated(false);
    setUsername(null);
    router.push("/login");
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, username, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
''')

# --- Login Page ---
write_file(r"F:\SentinelAI\panel\src\app\login\page.tsx", '''"use client";

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
          <div className="inline-flex items-center justify-center w-16 h-16 bg-sentinel-600 rounded-2xl mb-4 glow-green">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white">SentinelAI</h1>
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
                className="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-white placeholder-cyber-muted/50 focus:border-sentinel-500 focus:outline-none focus:ring-1 focus:ring-sentinel-500/20"
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
                  className="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-white placeholder-cyber-muted/50 focus:border-sentinel-500 focus:outline-none focus:ring-1 focus:ring-sentinel-500/20 pr-10"
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

        {/* Footer */}
        <p className="text-center text-xs text-cyber-muted mt-6">
          SentinelAI EDR Platform v0.1.0
        </p>
      </div>
    </div>
  );
}
''')

# --- Update Root Layout to wrap with AuthProvider ---
write_file(r"F:\SentinelAI\panel\src\app\layout.tsx", '''import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";

export const metadata: Metadata = {
  title: "SentinelAI \\u2014 EDR Dashboard",
  description: "AI-Powered Endpoint Detection & Response Platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-cyber-bg text-cyber-text antialiased">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
''')

# --- Update root page.tsx to be client-side redirect ---
write_file(r"F:\SentinelAI\panel\src\app\page.tsx", '''"use client";

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

# --- Update sidebar to add logout button and show real username ---
sidebar_content = '''"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, Monitor, AlertTriangle, Brain, Target, Settings, Shield, Search, LogOut } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

const navItems = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/agents", label: "Agents", icon: Monitor },
  { href: "/alerts", label: "Alerts", icon: AlertTriangle },
  { href: "/analysis", label: "AI Analysis", icon: Brain },
];
const bottomItems = [{ href: "/settings", label: "Settings", icon: Settings }];

export function Sidebar() {
  const pathname = usePathname();
  const { username, logout } = useAuth();
  const [alertCount, setAlertCount] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchCount = async () => {
      try {
        const data = await api.getDashboardStats();
        if (!cancelled) setAlertCount(data.alerts?.active ?? 0);
      } catch { /* ignore */ }
    };
    fetchCount();
    const id = setInterval(fetchCount, 30000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return (
    <aside className="w-64 bg-cyber-surface border-r border-cyber-border flex flex-col h-full">
      <div className="p-6 border-b border-cyber-border">
        <Link href="/dashboard" className="flex items-center gap-3">
          <div className="w-9 h-9 bg-sentinel-600 rounded-lg flex items-center justify-center glow-green">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">SentinelAI</h1>
            <p className="text-[10px] text-sentinel-400 uppercase tracking-widest">EDR Platform</p>
          </div>
        </Link>
      </div>

      <nav className="flex-1 p-4 space-y-1">
        {navItems.map((item) => {
          const isActive = pathname.startsWith(item.href);
          return (
            <Link key={item.href} href={item.href} className={"flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors " + (isActive ? "bg-sentinel-600/20 text-sentinel-400 border border-sentinel-500/20" : "text-cyber-muted hover:bg-cyber-hover hover:text-white")}>
              <item.icon className="w-4.5 h-4.5" />
              {item.label}
              {item.label === "Alerts" && alertCount != null && alertCount > 0 && (
                <span className="ml-auto bg-red-500/20 text-red-400 text-xs px-2 py-0.5 rounded-full">{alertCount}</span>
              )}
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-cyber-border space-y-1">
        {bottomItems.map((item) => (
          <Link key={item.href} href={item.href} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-cyber-muted hover:bg-cyber-hover hover:text-white transition-colors">
            <item.icon className="w-4.5 h-4.5" />
            {item.label}
          </Link>
        ))}
        <button onClick={logout} className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium text-red-400/70 hover:bg-red-500/10 hover:text-red-400 transition-colors w-full">
          <LogOut className="w-4.5 h-4.5" />
          Logout
        </button>
        <div className="flex items-center gap-3 px-3 py-2 mt-4">
          <div className="w-8 h-8 bg-sentinel-600 rounded-full flex items-center justify-center text-white text-xs font-bold">''' + "{(username || \"A\")[0].toUpperCase()}" + '''</div>
          <div className="flex-1 min-w-0">
            <div className="text-sm font-medium text-white truncate">{username || "User"}</div>
            <div className="text-xs text-cyber-muted truncate">analyst</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
'''
# Fix the JSX expressions - need curly braces for template literal in JSX
write_file(r"F:\SentinelAI\panel\src\components\ui\sidebar.tsx", sidebar_content)

print("All panel files written!")
