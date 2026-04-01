"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useRouter, usePathname } from "next/navigation";
import { api } from "@/lib/api";

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  username: string | null;
  role: string | null;
  login: (username: string, password: string, totpCode?: string) => Promise<{ requires_2fa?: boolean; two_fa_token?: string }>;
  login2FA: (twoFaToken: string, totpCode: string) => Promise<void>;
  logout: () => void;
  /** Check if user has at least the given role level */
  hasRole: (minRole: "viewer" | "analyst" | "admin" | "superadmin") => boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

const PUBLIC_PATHS = ["/login", "/forgot-password"];

const ROLE_HIERARCHY: Record<string, number> = {
  viewer: 0,
  analyst: 1,
  admin: 2,
  superadmin: 3,
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [username, setUsername] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const router = useRouter();
  const pathname = usePathname();

  const decodeTokenClaims = (token: string) => {
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      setUsername(payload.username || null);
      setRole(payload.role || "viewer");
    } catch { /* ignore */ }
  };

  useEffect(() => {
    const token = api.getToken();
    if (token) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setIsAuthenticated(true);
      decodeTokenClaims(token);
    } else if (!PUBLIC_PATHS.includes(pathname)) {
      router.push("/login");
    }
    setIsLoading(false);
  }, [pathname, router]);

  const login = async (user: string, password: string, totpCode?: string) => {
    const data = await api.login(user, password, totpCode);

    if (data.requires_2fa) {
      return { requires_2fa: true, two_fa_token: data.two_fa_token };
    }

    setIsAuthenticated(true);
    setUsername(user);
    // Decode role from freshly set token
    const token = api.getToken();
    if (token) decodeTokenClaims(token);
    router.push("/dashboard");
    return {};
  };

  const login2FA = async (twoFaToken: string, totpCode: string) => {
    await api.login2FA(twoFaToken, totpCode);
    setIsAuthenticated(true);
    // Decode username/role from token
    const token = api.getToken();
    if (token) {
      decodeTokenClaims(token);
    }
    router.push("/dashboard");
  };

  const logout = () => {
    api.clearToken();
    setIsAuthenticated(false);
    setUsername(null);
    setRole(null);
    router.push("/login");
  };

  const hasRole = (minRole: "viewer" | "analyst" | "admin" | "superadmin"): boolean => {
    const userLevel = ROLE_HIERARCHY[role || "viewer"] ?? 0;
    const requiredLevel = ROLE_HIERARCHY[minRole] ?? 0;
    return userLevel >= requiredLevel;
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, username, role, login, login2FA, logout, hasRole }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
