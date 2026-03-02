"use client";

import { useState, FormEvent } from "react";
import { api } from "@/lib/api";
import { Shield, Mail, KeyRound, AlertCircle, CheckCircle, Loader2, ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";

type Step = "email" | "code" | "done";

export default function ForgotPasswordPage() {
  const router = useRouter();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleEmailSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await api.forgotPassword(email);
      setStep("code");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to send reset code");
    } finally {
      setLoading(false);
    }
  };

  const handleCodeSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }

    setLoading(true);
    try {
      await api.resetPassword(email, code, newPassword);
      setStep("done");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to reset password");
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
          <p className="text-sm text-cyber-muted mt-1">Password Recovery</p>
        </div>

        <div className="bg-cyber-surface border border-cyber-border rounded-xl p-8">
          {/* Step 1: Enter email */}
          {step === "email" && (
            <>
              <div className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-12 h-12 bg-sentinel-600/20 rounded-xl mb-3">
                  <Mail className="w-6 h-6 text-sentinel-400" />
                </div>
                <h2 className="text-lg font-semibold text-white">Reset your password</h2>
                <p className="text-sm text-cyber-muted mt-1">
                  Enter your email address and we&apos;ll send you a verification code
                </p>
              </div>

              {error && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              <form onSubmit={handleEmailSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">Email Address</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="input-terminal"
                    placeholder="you@example.com"
                    required
                    autoFocus
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || !email}
                  className="w-full py-2.5 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Sending code...
                    </>
                  ) : (
                    "Send Reset Code"
                  )}
                </button>
              </form>

              <div className="mt-4 text-center">
                <Link
                  href="/login"
                  className="text-sm text-cyber-muted hover:text-white transition-colors inline-flex items-center gap-1"
                >
                  <ArrowLeft className="w-3 h-3" />
                  Back to login
                </Link>
              </div>
            </>
          )}

          {/* Step 2: Enter code + new password */}
          {step === "code" && (
            <>
              <div className="text-center mb-6">
                <div className="inline-flex items-center justify-center w-12 h-12 bg-sentinel-600/20 rounded-xl mb-3">
                  <KeyRound className="w-6 h-6 text-sentinel-400" />
                </div>
                <h2 className="text-lg font-semibold text-white">Enter verification code</h2>
                <p className="text-sm text-cyber-muted mt-1">
                  Check your email <span className="text-sentinel-400">{email}</span> for the 6-digit code
                </p>
              </div>

              {error && (
                <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              <form onSubmit={handleCodeSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">Verification Code</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={code}
                    onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                    className="input-terminal text-center text-2xl tracking-[0.5em] font-mono"
                    placeholder="000000"
                    required
                    autoFocus
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">New Password</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="input-terminal"
                    placeholder="Minimum 8 characters"
                    required
                    minLength={8}
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-cyber-muted mb-1.5">Confirm Password</label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="input-terminal"
                    placeholder="Repeat new password"
                    required
                    minLength={8}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading || code.length < 6 || !newPassword || !confirmPassword}
                  className="w-full py-2.5 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
                >
                  {loading ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Resetting...
                    </>
                  ) : (
                    "Reset Password"
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => { setStep("email"); setError(null); }}
                  className="w-full py-2 text-sm text-cyber-muted hover:text-white transition-colors"
                >
                  ← Use a different email
                </button>
              </form>
            </>
          )}

          {/* Step 3: Success */}
          {step === "done" && (
            <div className="text-center py-4">
              <div className="inline-flex items-center justify-center w-12 h-12 bg-green-500/20 rounded-xl mb-3">
                <CheckCircle className="w-6 h-6 text-green-400" />
              </div>
              <h2 className="text-lg font-semibold text-white mb-2">Password Reset Successful</h2>
              <p className="text-sm text-cyber-muted mb-6">
                Your password has been updated. You can now sign in with your new password.
              </p>
              <button
                onClick={() => router.push("/login")}
                className="w-full py-2.5 bg-sentinel-600 hover:bg-sentinel-500 text-white rounded-lg font-medium transition-colors"
              >
                Go to Login
              </button>
            </div>
          )}
        </div>

        <p className="text-center text-xs text-cyber-muted mt-6">
          SentinelAI EDR Platform v0.1.0
        </p>
      </div>
    </div>
  );
}
