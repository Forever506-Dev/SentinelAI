"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import {
  LayoutDashboard,
  Monitor,
  AlertTriangle,
  Brain,
  Terminal,
  Flame,
  FolderSync,
  Settings,
  LogOut,
  Shield,
  Activity,
  ClipboardCheck,
} from "lucide-react";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  minRole?: "viewer" | "analyst" | "admin" | "superadmin";
  badge?: number;
}

const ROLE_LABELS: Record<string, { label: string; color: string }> = {
  superadmin: { label: "Super Admin", color: "text-red-400" },
  admin: { label: "Admin", color: "text-orange-400" },
  analyst: { label: "Analyst", color: "text-blue-400" },
  viewer: { label: "Viewer", color: "text-gray-400" },
};

export function Sidebar() {
  const pathname = usePathname();
  const { username, role, logout, hasRole } = useAuth();
  const [pendingApprovals, setPendingApprovals] = useState(0);

  // Poll for pending approvals (admins only)
  useEffect(() => {
    if (!hasRole("admin")) return;

    const fetchCount = async () => {
      try {
        const data = await api.getPendingApprovalCount();
        setPendingApprovals(data.pending_count);
      } catch { /* ignore */ }
    };

    fetchCount();
    const interval = setInterval(fetchCount, 30_000); // every 30s
    return () => clearInterval(interval);
  }, [role]); // eslint-disable-line react-hooks/exhaustive-deps

  const navItems: NavItem[] = [
    { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { href: "/agents", label: "Endpoints", icon: Monitor },
    { href: "/alerts", label: "Alerts", icon: AlertTriangle },
    { href: "/analysis", label: "AI Analysis", icon: Brain, minRole: "analyst" },
    { href: "/terminal", label: "Remote Shell", icon: Terminal, minRole: "analyst" },
    { href: "/firewall", label: "Firewall", icon: Flame },
    { href: "/approvals", label: "Approvals", icon: ClipboardCheck, minRole: "admin", badge: pendingApprovals },
    { href: "/files", label: "File Vault", icon: FolderSync },
  ];

  const roleInfo = ROLE_LABELS[role || "viewer"] || ROLE_LABELS.viewer;

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
        {navItems
          .filter((item) => !item.minRole || hasRole(item.minRole))
          .map((item) => {
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
              {item.badge && item.badge > 0 ? (
                <span className="ml-auto px-1.5 py-0.5 text-[10px] font-bold bg-red-600 text-white rounded-full min-w-[18px] text-center">
                  {item.badge > 99 ? "99+" : item.badge}
                </span>
              ) : active ? (
                <div className="ml-auto w-1.5 h-1.5 rounded-full bg-sentinel-500 animate-pulse" />
              ) : null}
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
            <div className="flex items-center gap-1.5">
              <Activity className="w-2.5 h-2.5 text-green-500" />
              <span className={`text-[10px] font-medium ${roleInfo.color}`}>{roleInfo.label}</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
}
