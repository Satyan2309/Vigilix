import React, { useState } from "react";
import {
  Shield,
  Zap,
  Brain,
  Layers,
  Cloud,
  Search,
  Bot,
  Activity,
  ChevronRight,
  Lock,
  Radar,
  Database,
  FileSearch,
  ShieldCheck
} from "lucide-react";

export default function LandingPage({ onGetStarted }) {
  const [hoveredFeature, setHoveredFeature] = useState(null);

  const features = [
    {
      icon: Radar,
      title: "Real-Time Threat Detection",
      description: "15+ precision-engineered detection rules scan for root account abuse, public S3 exposures, open security groups, KMS tampering, and MFA manipulation in real-time.",
      color: "#f87171",
      gradient: "rgba(248, 113, 113, 0.12)",
      borderColor: "rgba(248, 113, 113, 0.3)",
    },
    {
      icon: Brain,
      title: "AI-Powered Investigation Engine",
      description: "LangGraph-orchestrated multi-step reasoning generates actionable incident reports with MITRE ATT&CK mapping, threat hypotheses, and defensive runbooks.",
      color: "#818cf8",
      gradient: "rgba(129, 140, 248, 0.12)",
      borderColor: "rgba(129, 140, 248, 0.3)",
    },
    {
      icon: Bot,
      title: "Streaming AI Copilot",
      description: "Real-time SSE copilot that answers security questions with SQL-grounded telemetry counts, contextual RAG retrieval, and guided remediation steps.",
      color: "#00f5d4",
      gradient: "rgba(0, 245, 212, 0.12)",
      borderColor: "rgba(0, 245, 212, 0.3)",
    },
    {
      icon: Cloud,
      title: "Native AWS Connectors",
      description: "Direct integration with CloudTrail events, S3 log archives, GuardDuty threat intel, and Security Hub compliance findings via the AWS Boto3 SDK.",
      color: "#38bdf8",
      gradient: "rgba(56, 189, 248, 0.12)",
      borderColor: "rgba(56, 189, 248, 0.3)",
    },
    {
      icon: FileSearch,
      title: "RAG Knowledge Base",
      description: "Index security runbooks, CIS benchmarks, and incident playbooks into a vector store for AI-powered contextual retrieval during live investigations.",
      color: "#fbbf24",
      gradient: "rgba(251, 191, 36, 0.12)",
      borderColor: "rgba(251, 191, 36, 0.3)",
    },
    {
      icon: Database,
      title: "PostgreSQL-Backed SOC Store",
      description: "Production-grade Neon PostgreSQL persistence for events, incidents, users, and chat history with full multi-tenant isolation.",
      color: "#34d399",
      gradient: "rgba(52, 211, 153, 0.12)",
      borderColor: "rgba(52, 211, 153, 0.3)",
    },
  ];

  const stats = [
    { value: "15+", label: "Detection Rules", icon: ShieldCheck },
    { value: "<2s", label: "AI Response Time", icon: Zap },
    { value: "5", label: "AWS Connectors", icon: Cloud },
    { value: "100%", label: "Open Source", icon: Lock },
  ];

  return (
    <div className="landing-hero">
      {/* HUD Grid Background */}
      <div className="hud-grid" />

      {/* ── Navigation Bar ─────────────────────────────────────────── */}
      <nav className="landing-nav">
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            width: "40px",
            height: "40px",
            borderRadius: "12px",
            background: "linear-gradient(135deg, rgba(0, 245, 212, 0.2), rgba(56, 189, 248, 0.2))",
            border: "1px solid var(--accent-cyan)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--accent-cyan)",
            boxShadow: "0 0 20px rgba(0, 245, 212, 0.3)",
          }}>
            <Shield size={24} />
          </div>
          <div>
            <div style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: "1.2rem", color: "#fff", letterSpacing: "-0.01em" }}>
              Vigilix <span style={{ color: "var(--accent-cyan)" }}>AI</span>
            </div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.12em" }}>
              Cloud Security Operations
            </div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            padding: "6px 14px",
            borderRadius: "20px",
            background: "rgba(0, 245, 212, 0.08)",
            border: "1px solid rgba(0, 245, 212, 0.25)",
          }}>
            <div className="pulse-indicator" style={{ width: "6px", height: "6px" }} />
            <span style={{ fontSize: "0.75rem", color: "var(--accent-cyan)", fontWeight: 600 }}>
              SYSTEM ONLINE
            </span>
          </div>
          <button
            onClick={onGetStarted}
            className="btn btn-primary"
            style={{ fontSize: "0.88rem" }}
          >
            Launch SOC
            <ChevronRight size={16} />
          </button>
        </div>
      </nav>

      {/* ── Hero Section ───────────────────────────────────────────── */}
      <div className="landing-content">
        <div className="landing-grid">
          {/* Left: Headline Copy */}
          <div>
            <div style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              padding: "8px 16px",
              borderRadius: "24px",
              background: "rgba(0, 245, 212, 0.08)",
              border: "1px solid rgba(0, 245, 212, 0.2)",
              marginBottom: "28px",
              fontSize: "0.82rem",
              color: "var(--accent-cyan)",
              fontWeight: 600,
            }}>
              <Zap size={14} />
              AI-Powered AWS Security Intelligence Platform
            </div>

            <h1 style={{
              fontSize: "clamp(2.2rem, 5vw, 3.6rem)",
              lineHeight: 1.12,
              fontWeight: 800,
              marginBottom: "24px",
              background: "linear-gradient(135deg, #ffffff 0%, #c4d5ea 40%, #00f5d4 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
            }}>
              Detect. Investigate.
              <br />
              Respond. In Real-Time.
            </h1>

            <p style={{
              fontSize: "1.1rem",
              color: "var(--text-muted)",
              lineHeight: 1.7,
              maxWidth: "540px",
              marginBottom: "36px",
            }}>
              Vigilix AI transforms your AWS CloudTrail events into actionable
              threat intelligence with LangGraph-driven investigations, streaming AI
              copilot, and automated detection rules — all in a single SOC dashboard.
            </p>

            <div style={{ display: "flex", gap: "12px", flexWrap: "wrap" }}>
              <button
                onClick={onGetStarted}
                className="btn btn-primary"
                style={{ padding: "14px 28px", fontSize: "1rem" }}
              >
                <Shield size={18} />
                Enter SOC Command Center
              </button>
              <a
                href="http://127.0.0.1:8000/docs"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-secondary"
                style={{ padding: "14px 28px", fontSize: "1rem" }}
              >
                <Layers size={18} />
                View API Docs
              </a>
            </div>
          </div>

          {/* Right: HUD Visualization */}
          <div style={{ position: "relative" }}>
            {/* Decorative SOC Card */}
            <div style={{
              background: "linear-gradient(145deg, rgba(16, 27, 48, 0.95), rgba(9, 15, 27, 0.98))",
              border: "1px solid rgba(0, 245, 212, 0.25)",
              borderRadius: "20px",
              padding: "32px",
              boxShadow: "0 20px 60px rgba(0, 0, 0, 0.5), 0 0 40px rgba(0, 245, 212, 0.08)",
              animation: "borderGlow 4s ease-in-out infinite",
            }}>
              {/* Top status bar */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <div className="pulse-indicator" />
                  <span style={{ fontSize: "0.8rem", color: "var(--accent-cyan)", fontWeight: 600 }}>LIVE MONITORING</span>
                </div>
                <span style={{ fontSize: "0.72rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                  SYS::OPERATIONAL
                </span>
              </div>

              {/* Fake Threat Meter */}
              <div style={{ marginBottom: "24px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                  <span style={{ fontSize: "0.78rem", color: "var(--text-muted)", fontWeight: 600 }}>THREAT POSTURE</span>
                  <span style={{ fontSize: "0.85rem", color: "var(--accent-warn)", fontWeight: 700, fontFamily: "var(--font-mono)" }}>ELEVATED</span>
                </div>
                <div style={{ height: "8px", background: "rgba(0,0,0,0.4)", borderRadius: "4px", overflow: "hidden" }}>
                  <div style={{
                    height: "100%",
                    width: "62%",
                    background: "linear-gradient(90deg, var(--accent-success), var(--accent-warn), var(--accent-danger))",
                    borderRadius: "4px",
                    transition: "width 1s ease",
                  }} />
                </div>
              </div>

              {/* Fake detection feed */}
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {[
                  { severity: "CRITICAL", event: "ROOT_ACCOUNT_LOGIN", time: "2s ago", color: "#f87171", bg: "rgba(248,113,113,0.12)" },
                  { severity: "HIGH", event: "S3_PUBLIC_EXPOSURE", time: "14s ago", color: "#fb923c", bg: "rgba(251,146,60,0.12)" },
                  { severity: "MEDIUM", event: "SG_OPEN_PORT_22", time: "31s ago", color: "#fbbf24", bg: "rgba(251,191,36,0.12)" },
                  { severity: "LOW", event: "ConsoleLogin:MFA", time: "1m ago", color: "#34d399", bg: "rgba(52,211,153,0.12)" },
                ].map((item, i) => (
                  <div key={i} style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    padding: "10px 14px",
                    background: item.bg,
                    borderRadius: "8px",
                    border: `1px solid ${item.color}22`,
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <div style={{
                        width: "6px", height: "6px", borderRadius: "50%",
                        background: item.color, boxShadow: `0 0 6px ${item.color}`,
                      }} />
                      <span style={{ fontSize: "0.72rem", fontWeight: 700, color: item.color, fontFamily: "var(--font-display)", width: "65px" }}>
                        {item.severity}
                      </span>
                      <span style={{ fontSize: "0.78rem", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                        {item.event}
                      </span>
                    </div>
                    <span style={{ fontSize: "0.7rem", color: "var(--text-dim)" }}>{item.time}</span>
                  </div>
                ))}
              </div>

              {/* Bottom stats */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px", marginTop: "20px" }}>
                {[
                  { label: "Events Ingested", value: "3,847", color: "var(--accent-cyan)" },
                  { label: "Detections Fired", value: "23", color: "var(--accent-warn)" },
                  { label: "Active Incidents", value: "4", color: "var(--accent-danger)" },
                ].map((s, i) => (
                  <div key={i} style={{
                    padding: "12px",
                    background: "rgba(0,0,0,0.3)",
                    borderRadius: "10px",
                    textAlign: "center",
                    border: "1px solid var(--border-subtle)",
                  }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "1.3rem", fontWeight: 700, color: s.color }}>
                      {s.value}
                    </div>
                    <div style={{ fontSize: "0.68rem", color: "var(--text-dim)", marginTop: "2px", textTransform: "uppercase" }}>
                      {s.label}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── Stats Bar ──────────────────────────────────────────────── */}
      <div style={{
        display: "flex",
        justifyContent: "center",
        gap: "48px",
        padding: "32px 40px",
        flexWrap: "wrap",
        position: "relative",
        zIndex: 10,
      }}>
        {stats.map((stat, i) => {
          const Icon = stat.icon;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: "14px" }}>
              <div style={{
                width: "44px",
                height: "44px",
                borderRadius: "12px",
                background: "rgba(0, 245, 212, 0.08)",
                border: "1px solid rgba(0, 245, 212, 0.2)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "var(--accent-cyan)",
              }}>
                <Icon size={20} />
              </div>
              <div>
                <div style={{ fontFamily: "var(--font-display)", fontSize: "1.5rem", fontWeight: 800, color: "#fff" }}>
                  {stat.value}
                </div>
                <div style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
                  {stat.label}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Features Grid ──────────────────────────────────────────── */}
      <div style={{
        textAlign: "center",
        padding: "60px 40px 40px",
        position: "relative",
        zIndex: 10,
      }}>
        <h2 style={{ fontSize: "clamp(1.6rem, 3vw, 2.2rem)", marginBottom: "12px" }}>
          Enterprise-Grade Cloud Security
        </h2>
        <p style={{ color: "var(--text-muted)", fontSize: "1.05rem", maxWidth: "600px", margin: "0 auto 48px" }}>
          Every capability a modern SOC team needs to detect, investigate, and respond to AWS cloud threats.
        </p>
      </div>

      <div className="landing-features">
        {features.map((feature, i) => {
          const Icon = feature.icon;
          return (
            <div
              key={i}
              className="feature-card"
              onMouseEnter={() => setHoveredFeature(i)}
              onMouseLeave={() => setHoveredFeature(null)}
              style={{
                borderColor: hoveredFeature === i ? feature.borderColor : undefined,
              }}
            >
              <div style={{
                width: "48px",
                height: "48px",
                borderRadius: "12px",
                background: feature.gradient,
                border: `1px solid ${feature.borderColor}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                marginBottom: "18px",
              }}>
                <Icon size={24} color={feature.color} />
              </div>
              <h3 style={{ fontSize: "1.1rem", marginBottom: "10px", fontWeight: 700 }}>
                {feature.title}
              </h3>
              <p style={{ fontSize: "0.9rem", color: "var(--text-muted)", lineHeight: 1.65 }}>
                {feature.description}
              </p>
            </div>
          );
        })}
      </div>

      {/* ── CTA Footer ─────────────────────────────────────────────── */}
      <div style={{
        textAlign: "center",
        padding: "40px",
        position: "relative",
        zIndex: 10,
        borderTop: "1px solid var(--border-subtle)",
        background: "rgba(9, 15, 27, 0.5)",
      }}>
        <h3 style={{ fontSize: "1.4rem", marginBottom: "16px" }}>
          Ready to Secure Your Cloud?
        </h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.95rem", marginBottom: "24px", maxWidth: "500px", margin: "0 auto 24px" }}>
          Sign in to the SOC Command Center and start analyzing your AWS telemetry in seconds.
        </p>
        <button
          onClick={onGetStarted}
          className="btn btn-primary"
          style={{ padding: "14px 36px", fontSize: "1rem" }}
        >
          <Shield size={18} />
          Launch Vigilix AI
          <ChevronRight size={16} />
        </button>

        <div style={{ marginTop: "32px", fontSize: "0.75rem", color: "var(--text-dim)" }}>
          Vigilix AI v0.2.0 — Continuous Intelligent Cloud Security Monitoring
        </div>
      </div>
    </div>
  );
}

