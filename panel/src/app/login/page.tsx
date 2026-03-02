"use client";

import { useEffect, useState, FormEvent } from "react";
import { useAuth } from "@/lib/auth-context";
import { Shield, Eye, EyeOff, AlertCircle, Loader2, KeyRound } from "lucide-react";
import Link from "next/link";

export default function LoginPage() {
  const { login, login2FA } = useAuth();
  const [mounted, setMounted] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // 2FA state
  const [requires2FA, setRequires2FA] = useState(false);
  const [twoFaToken, setTwoFaToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="min-h-screen bg-cyber-bg" />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const result = await login(username, password);
      if (result.requires_2fa && result.two_fa_token) {
        setRequires2FA(true);
        setTwoFaToken(result.two_fa_token);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  const handle2FASubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (twoFaToken) {
        await login2FA(twoFaToken, totpCode);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Invalid TOTP code");
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
          {!requires2FA ? (
            <>
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
                    suppressHydrationWarning
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="input-terminal"
                    placeholder="Enter username"
                    required
                    autoFocus
                    autoComplete="username"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">Password</label>
                  <div className="relative">
                    <input
                      suppressHydrationWarning
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input-terminal pr-10"
                      placeholder="Enter password"
                      required
                      autoComplete="current-password"
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

              <div className="mt-4 text-center">
                <Link
                  href="/forgot-password"
                  className="text-sm text-sentinel-400 hover:text-sentinel-300 transition-colors"
                >
                  Forgot your password?
                </Link>
              </div>
            </>
          ) : (
            <>
              <div className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-12 h-12 bg-sentinel-600/20 rounded-xl mb-3">
                  <KeyRound className="w-6 h-6 text-sentinel-400" />
                </div>
                <h2 className="text-lg font-semibold text-white">Two-Factor Authentication</h2>
                <p className="text-sm text-cyber-muted mt-1">Enter the 6-digit code from your authenticator app</p>
              </div>

              {error && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              <form onSubmit={handle2FASubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">TOTP Code</label>
                  <input
                    suppressHydrationWarning
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                    className="input-terminal text-center text-2xl tracking-[0.5em] font-mono"
                    placeholder="000000"
                    required
                    autoFocus
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || totpCode.length !== 6}
                  className="w-full py-2.5 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Verifying...
                    </>
                  ) : (
                    "Verify & Sign in"
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setRequires2FA(false);
                    setTwoFaToken(null);
                    setTotpCode("");
                    setError(null);
                  }}
                  className="w-full py-2 text-sm text-cyber-muted hover:text-white transition-colors"
                >
                  ← Back to login
                </button>
              </form>
            </>
          )}
        </div>

        <p className="text-center text-xs text-cyber-muted mt-6">
          SentinelAI EDR Platform v0.1.0
        </p>
      </div>
    </div>
  );
}
