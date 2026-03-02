"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import {
  Shield,
  ShieldCheck,
  ShieldOff,
  QrCode,
  AlertCircle,
  CheckCircle,
  Loader2,
  Copy,
  KeyRound,
  Lock,
} from "lucide-react";

type TwoFAStatus = "loading" | "disabled" | "setup" | "verify" | "enabled";

export default function SecuritySettingsPage() {
  const [status, setStatus] = useState<TwoFAStatus>("loading");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // 2FA setup data
  const [secret, setSecret] = useState("");
  const [qrCode, setQrCode] = useState("");
  const [verifyCode, setVerifyCode] = useState("");

  // Disable 2FA
  const [disableCode, setDisableCode] = useState("");

  // Change password
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordMsg, setPasswordMsg] = useState<{ type: "error" | "success"; text: string } | null>(null);

  useEffect(() => {
    loadProfile();
  }, []);

  const loadProfile = async () => {
    try {
      const profile = await api.getProfile();
      setStatus(profile.totp_enabled ? "enabled" : "disabled");
    } catch {
      setStatus("disabled");
    }
  };

  const handleSetup = async () => {
    setError(null);
    setLoading(true);
    try {
      const data = await api.setup2FA();
      setSecret(data.secret);
      setQrCode(data.qr_code_base64);
      setStatus("setup");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start 2FA setup");
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    setError(null);
    setLoading(true);
    try {
      await api.verify2FA(verifyCode);
      setStatus("enabled");
      setSuccess("Two-factor authentication has been enabled!");
      setVerifyCode("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Invalid code");
    } finally {
      setLoading(false);
    }
  };

  const handleDisable = async () => {
    setError(null);
    setLoading(true);
    try {
      await api.disable2FA(disableCode);
      setStatus("disabled");
      setSuccess("Two-factor authentication has been disabled.");
      setDisableCode("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Invalid code");
    } finally {
      setLoading(false);
    }
  };

  const handleChangePassword = async () => {
    setPasswordMsg(null);
    if (newPassword !== confirmPassword) {
      setPasswordMsg({ type: "error", text: "Passwords do not match" });
      return;
    }
    if (newPassword.length < 8) {
      setPasswordMsg({ type: "error", text: "Password must be at least 8 characters" });
      return;
    }
    setPasswordLoading(true);
    try {
      await api.changePassword(currentPassword, newPassword);
      setPasswordMsg({ type: "success", text: "Password changed successfully!" });
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: unknown) {
      setPasswordMsg({ type: "error", text: err instanceof Error ? err.message : "Failed to change password" });
    } finally {
      setPasswordLoading(false);
    }
  };

  const copySecret = () => {
    navigator.clipboard.writeText(secret);
  };

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Shield className="w-6 h-6 text-sentinel-400" />
          Security Settings
        </h1>
        <p className="text-cyber-muted mt-1">Manage your account security preferences</p>
      </div>

      {/* ─── Change Password ─── */}
      <div className="bg-cyber-surface border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <Lock className="w-5 h-5 text-cyber-muted" />
          Change Password
        </h2>

        {passwordMsg && (
          <div className={`flex items-center gap-2 rounded-lg p-3 mb-4 ${
            passwordMsg.type === "error"
              ? "bg-red-500/10 border border-red-500/20"
              : "bg-green-500/10 border border-green-500/20"
          }`}>
            {passwordMsg.type === "error" ? (
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
            )}
            <p className={`text-sm ${passwordMsg.type === "error" ? "text-red-400" : "text-green-400"}`}>
              {passwordMsg.text}
            </p>
          </div>
        )}

        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-cyber-muted mb-1">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="input-terminal max-w-sm"
              placeholder="Enter current password"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-cyber-muted mb-1">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="input-terminal max-w-sm"
              placeholder="Minimum 8 characters"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-cyber-muted mb-1">Confirm New Password</label>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="input-terminal max-w-sm"
              placeholder="Repeat new password"
            />
          </div>
          <button
            onClick={handleChangePassword}
            disabled={passwordLoading || !currentPassword || !newPassword || !confirmPassword}
            className="px-4 py-2 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
          >
            {passwordLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            Update Password
          </button>
        </div>
      </div>

      {/* ─── Two-Factor Authentication ─── */}
      <div className="bg-cyber-surface border border-cyber-border rounded-xl p-6">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-4">
          <KeyRound className="w-5 h-5 text-cyber-muted" />
          Two-Factor Authentication (TOTP)
        </h2>

        {error && (
          <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/20 rounded-lg p-3 mb-4">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {success && (
          <div className="flex items-center gap-2 bg-green-500/10 border border-green-500/20 rounded-lg p-3 mb-4">
            <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
            <p className="text-sm text-green-400">{success}</p>
          </div>
        )}

        {status === "loading" && (
          <div className="flex items-center gap-2 text-cyber-muted">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading...
          </div>
        )}

        {/* Disabled — offer to enable */}
        {status === "disabled" && (
          <div>
            <div className="flex items-center gap-3 mb-4">
              <ShieldOff className="w-8 h-8 text-yellow-500" />
              <div>
                <p className="text-white font-medium">2FA is not enabled</p>
                <p className="text-sm text-cyber-muted">
                  Add an extra layer of security to your account using an authenticator app
                  like Google Authenticator, Authy, or 1Password.
                </p>
              </div>
            </div>
            <button
              onClick={handleSetup}
              disabled={loading}
              className="px-4 py-2 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <QrCode className="w-4 h-4" />}
              Enable 2FA
            </button>
          </div>
        )}

        {/* Setup — show QR + secret */}
        {status === "setup" && (
          <div className="space-y-4">
            <p className="text-sm text-cyber-muted">
              Scan the QR code below with your authenticator app, then enter the 6-digit code to verify.
            </p>

            <div className="flex justify-center">
              <div className="bg-white p-3 rounded-lg">
                <img
                  src={`data:image/png;base64,${qrCode}`}
                  alt="TOTP QR Code"
                  width={200}
                  height={200}
                />
              </div>
            </div>

            <div className="bg-cyber-bg border border-cyber-border rounded-lg p-3">
              <p className="text-xs text-cyber-muted mb-1">Manual entry key:</p>
              <div className="flex items-center gap-2">
                <code className="text-sm text-sentinel-400 font-mono break-all">{secret}</code>
                <button onClick={copySecret} className="text-cyber-muted hover:text-white shrink-0">
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-cyber-muted mb-1.5">Verification Code</label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                value={verifyCode}
                onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, ""))}
                className="input-terminal max-w-xs text-center text-xl tracking-[0.5em] font-mono"
                placeholder="000000"
              />
            </div>

            <div className="flex gap-3">
              <button
                onClick={handleVerify}
                disabled={loading || verifyCode.length !== 6}
                className="px-4 py-2 bg-sentinel-600 hover:bg-sentinel-500 disabled:bg-sentinel-600/50 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
              >
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                Verify & Enable
              </button>
              <button
                onClick={() => { setStatus("disabled"); setError(null); }}
                className="px-4 py-2 text-cyber-muted hover:text-white text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Enabled — offer to disable */}
        {status === "enabled" && (
          <div>
            <div className="flex items-center gap-3 mb-4">
              <ShieldCheck className="w-8 h-8 text-green-400" />
              <div>
                <p className="text-white font-medium">2FA is enabled</p>
                <p className="text-sm text-cyber-muted">
                  Your account is protected with TOTP two-factor authentication.
                </p>
              </div>
            </div>

            <div className="border-t border-cyber-border pt-4 mt-4">
              <p className="text-sm text-cyber-muted mb-3">
                To disable 2FA, enter a code from your authenticator app:
              </p>
              <div className="flex items-end gap-3">
                <div>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    maxLength={6}
                    value={disableCode}
                    onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, ""))}
                    className="input-terminal w-40 text-center text-xl tracking-[0.5em] font-mono"
                    placeholder="000000"
                  />
                </div>
                <button
                  onClick={handleDisable}
                  disabled={loading || disableCode.length !== 6}
                  className="px-4 py-2 bg-red-600 hover:bg-red-500 disabled:bg-red-600/50 text-white rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldOff className="w-4 h-4" />}
                  Disable 2FA
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}