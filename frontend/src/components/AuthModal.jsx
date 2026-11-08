import React, { useState } from "react";
import { Shield, Lock, Mail, User, KeyRound, AlertCircle, Sparkles, X, Zap } from "lucide-react";
import { login, register } from "../api";

export default function AuthModal({ isOpen, onClose, onAuthSuccess }) {
  const [mode, setMode] = useState("signin"); // "signin" | "register"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [loading, setLoading] = useState(false);
  const [demoLoading, setDemoLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setNotice("");

    if (!email || !password) {
      setError("Please provide both email and password.");
      return;
    }

    if (mode === "register" && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      if (mode === "register") {
        await register(email, password, fullName || "Security Analyst");
        setNotice("Account registered successfully! Please sign in.");
        setMode("signin");
      } else {
        const data = await login(email, password);
        onAuthSuccess(data.user);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setDemoLoading(true);
    setError("");
    setNotice("");
    const demoEmail = "operator@vigilix.local";
    const demoPass = "VigilixSec2026!";
    try {
      try {
        const data = await login(demoEmail, demoPass);
        onAuthSuccess(data.user);
        return;
      } catch {
        // If account does not exist yet, auto-register it
        await register(demoEmail, demoPass, "Lead SOC Analyst");
        const data = await login(demoEmail, demoPass);
        onAuthSuccess(data.user);
      }
    } catch (err) {
      setError(err.message || "Failed to initialize demo operator session");
    } finally {
      setDemoLoading(false);
    }
  };

  return (
    <div 
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(4, 7, 14, 0.88)",
        backdropFilter: "blur(18px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 9999,
        padding: "20px",
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget && onClose) onClose();
      }}
    >
      <div style={{
        width: "100%",
        maxWidth: "460px",
        background: "linear-gradient(145deg, rgba(16, 27, 48, 0.95), rgba(9, 15, 27, 0.98))",
        border: "1px solid rgba(0, 245, 212, 0.35)",
        borderRadius: "20px",
        padding: "36px 32px",
        boxShadow: "0 20px 60px rgba(0, 0, 0, 0.7), 0 0 30px rgba(0, 245, 212, 0.15)",
        position: "relative",
        overflow: "hidden",
      }}>
        {/* Subtle Cyber Accent Top Bar */}
        <div style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: "4px",
          background: "linear-gradient(90deg, #00f5d4, #38bdf8, #818cf8)",
        }} />

        {/* Close Button */}
        {onClose && (
          <button
            onClick={onClose}
            style={{
              position: "absolute",
              top: "16px",
              right: "16px",
              background: "transparent",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              padding: "6px",
              borderRadius: "6px",
            }}
          >
            <X size={18} />
          </button>
        )}

        <div style={{ textAlign: "center", marginBottom: "26px" }}>
          <div style={{
            width: "56px",
            height: "56px",
            borderRadius: "14px",
            background: "rgba(0, 245, 212, 0.12)",
            border: "1px solid rgba(0, 245, 212, 0.4)",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            color: "#00f5d4",
            marginBottom: "14px",
            boxShadow: "0 0 20px rgba(0, 245, 212, 0.25)",
          }}>
            <Shield size={30} />
          </div>
          <h2 style={{ fontSize: "1.65rem", fontWeight: 700, color: "#fff", marginBottom: "6px" }}>
            Vigilix AI
          </h2>
          <p style={{ color: "var(--text-muted)", fontSize: "0.88rem" }}>
            AWS Cloud Security Operations & Triage
          </p>
        </div>

        {/* 1-Click Demo Operator Button */}
        <div style={{ marginBottom: "20px" }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleDemoLogin}
            disabled={demoLoading}
            style={{
              width: "100%",
              padding: "12px",
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              gap: "8px",
              background: "linear-gradient(135deg, rgba(0, 245, 212, 0.15), rgba(56, 189, 248, 0.15))",
              borderColor: "rgba(0, 245, 212, 0.4)",
              color: "#00f5d4",
              fontWeight: 600,
            }}
          >
            <Zap size={16} />
            {demoLoading ? "Initializing Demo Operator..." : "Instant Demo Operator Login"}
          </button>
        </div>

        <div style={{
          display: "flex",
          alignItems: "center",
          margin: "16px 0",
          color: "var(--text-dim)",
          fontSize: "0.75rem",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
        }}>
          <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
          <span style={{ padding: "0 10px" }}>Or Use Credentials</span>
          <div style={{ flex: 1, height: "1px", background: "var(--border)" }} />
        </div>

        {/* Mode Tabs */}
        <div style={{
          display: "flex",
          background: "rgba(10, 18, 32, 0.8)",
          padding: "4px",
          borderRadius: "12px",
          marginBottom: "24px",
          border: "1px solid var(--border)",
        }}>
          <button
            type="button"
            onClick={() => { setMode("signin"); setError(""); setNotice(""); }}
            style={{
              flex: 1,
              padding: "10px",
              background: mode === "signin" ? "var(--primary)" : "transparent",
              color: mode === "signin" ? "#04070e" : "var(--text-muted)",
              border: "none",
              borderRadius: "8px",
              fontWeight: 600,
              cursor: "pointer",
              transition: "all 0.2s ease",
            }}
          >
            Operator Sign In
          </button>
          <button
            type="button"
            onClick={() => { setMode("register"); setError(""); setNotice(""); }}
            style={{
              flex: 1,
              padding: "10px",
              background: mode === "register" ? "var(--primary)" : "transparent",
              color: mode === "register" ? "#04070e" : "var(--text-muted)",
              border: "none",
              borderRadius: "8px",
              fontWeight: 600,
              cursor: "pointer",
              transition: "all 0.2s ease",
            }}
          >
            Register Account
          </button>
        </div>

        {error && (
          <div style={{
            background: "rgba(239, 68, 68, 0.12)",
            border: "1px solid rgba(239, 68, 68, 0.35)",
            padding: "12px 14px",
            borderRadius: "10px",
            color: "#f87171",
            fontSize: "0.85rem",
            marginBottom: "18px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}>
            <AlertCircle size={16} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {notice && (
          <div style={{
            background: "rgba(0, 245, 212, 0.12)",
            border: "1px solid rgba(0, 245, 212, 0.35)",
            padding: "12px 14px",
            borderRadius: "10px",
            color: "#00f5d4",
            fontSize: "0.85rem",
            marginBottom: "18px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
          }}>
            <Sparkles size={16} style={{ flexShrink: 0 }} />
            <span>{notice}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {mode === "register" && (
            <div>
              <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "6px" }}>
                FULL NAME
              </label>
              <div style={{ position: "relative" }}>
                <User size={18} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-dim)" }} />
                <input
                  type="text"
                  className="input-control"
                  style={{ paddingLeft: "38px" }}
                  placeholder="e.g. Alex Vance"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                />
              </div>
            </div>
          )}

          <div>
            <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "6px" }}>
              SECURITY EMAIL
            </label>
            <div style={{ position: "relative" }}>
              <Mail size={18} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-dim)" }} />
              <input
                type="email"
                className="input-control"
                style={{ paddingLeft: "38px" }}
                placeholder="analyst@organization.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "6px" }}>
              PASSWORD
            </label>
            <div style={{ position: "relative" }}>
              <Lock size={18} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-dim)" }} />
              <input
                type="password"
                className="input-control"
                style={{ paddingLeft: "38px" }}
                placeholder={mode === "register" ? "At least 8 characters" : "Your password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          </div>

          {mode === "register" && (
            <div>
              <label style={{ display: "block", fontSize: "0.78rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "6px" }}>
                CONFIRM PASSWORD
              </label>
              <div style={{ position: "relative" }}>
                <KeyRound size={18} style={{ position: "absolute", left: "12px", top: "12px", color: "var(--text-dim)" }} />
                <input
                  type="password"
                  className="input-control"
                  style={{ paddingLeft: "38px" }}
                  placeholder="Repeat password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                />
              </div>
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ width: "100%", marginTop: "8px", padding: "12px" }}
          >
            {loading ? "Authenticating..." : mode === "signin" ? "Initialize Operator Session" : "Create Security Account"}
          </button>
        </form>

        <div style={{ textAlign: "center", marginTop: "20px" }}>
          <span style={{ fontSize: "0.76rem", color: "var(--text-dim)" }}>
            ⚡ First registered account automatically becomes the workspace administrator.
          </span>
        </div>
      </div>
    </div>
  );
}
