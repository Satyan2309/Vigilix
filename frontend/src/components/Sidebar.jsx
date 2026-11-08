import React, { useState } from "react";
import {
  Shield,
  LayoutDashboard,
  Flame,
  Bot,
  Search,
  BookOpen,
  Cloud,
  LogOut,
  Upload,
  Play,
  CheckCircle2,
  AlertTriangle,
  Database
} from "lucide-react";
import { loadDemo, uploadLogs, importPublicDataset } from "../api";

export default function Sidebar({
  activeTab,
  setActiveTab,
  user,
  onSignOut,
  onTelemetryUpdated,
  health
}) {
  const [loadingScenario, setLoadingScenario] = useState(false);
  const [feedback, setFeedback] = useState("");

  const handleLoadRealDataset = async () => {
    setLoadingScenario(true);
    setFeedback("");
    try {
      const res = await importPublicDataset(3000);
      setFeedback(`Imported ${res.new_events || res.parsed_events} real CloudTrail events!`);
      onTelemetryUpdated?.();
      setTimeout(() => setFeedback(""), 4500);
    } catch (err) {
      setFeedback(`Failed: ${err.message}`);
    } finally {
      setLoadingScenario(false);
    }
  };

  const handleLoadDemo = async (scenario) => {
    setLoadingScenario(true);
    setFeedback("");
    try {
      const res = await loadDemo(scenario);
      setFeedback(`Loaded ${res.new_events} events (${scenario})`);
      onTelemetryUpdated?.();
      setTimeout(() => setFeedback(""), 3500);
    } catch (err) {
      setFeedback(`Failed: ${err.message}`);
    } finally {
      setLoadingScenario(false);
    }
  };

  const navItems = [
    { id: "overview", label: "Command Center", icon: LayoutDashboard },
    { id: "investigations", label: "Incident War Room", icon: Flame },
    { id: "copilot", label: "Real-Time Copilot", icon: Bot },
    { id: "explorer", label: "Event Explorer", icon: Search },
    { id: "knowledge", label: "Threat Runbooks", icon: BookOpen },
    { id: "connectors", label: "AWS Telemetry", icon: Cloud },
  ];

  return (
    <>
      {/* Brand Header */}
      <div style={{ padding: "24px 20px 18px", borderBottom: "1px solid var(--border-subtle)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "10px" }}>
          <div style={{
            width: "38px",
            height: "38px",
            borderRadius: "10px",
            background: "linear-gradient(135deg, rgba(0, 245, 212, 0.2), rgba(56, 189, 248, 0.2))",
            border: "1px solid var(--accent-cyan)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "var(--accent-cyan)",
            boxShadow: "0 0 16px rgba(0, 245, 212, 0.3)",
          }}>
            <Shield size={22} />
          </div>
          <div>
            <div style={{ fontFamily: "var(--font-display)", fontWeight: 700, fontSize: "1.15rem", letterSpacing: "-0.01em", color: "#fff" }}>
              Vigilix <span style={{ color: "var(--accent-cyan)" }}>AI</span>
            </div>
            <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
              INTELLIGENT SOC v0.2
            </div>
          </div>
        </div>

        {/* Operator Badge */}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "8px 12px",
          background: "rgba(15, 26, 44, 0.6)",
          borderRadius: "8px",
          border: "1px solid var(--border-subtle)",
        }}>
          <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            <div style={{ fontSize: "0.82rem", fontWeight: 600, color: "#fff", textOverflow: "ellipsis", overflow: "hidden" }}>
              {user?.full_name || user?.email || "Operator"}
            </div>
            <div style={{ fontSize: "0.7rem", color: "var(--text-dim)" }}>
              {user?.email}
            </div>
          </div>
          <span className={`badge ${user?.role === "admin" ? "badge-cyan" : "badge-medium"}`} style={{ fontSize: "0.68rem" }}>
            {user?.role || "analyst"}
          </span>
        </div>
      </div>

      {/* Navigation */}
      <div style={{ flex: 1, padding: "16px 12px", overflowY: "auto" }}>
        <div style={{ fontSize: "0.7rem", fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.12em", padding: "0 10px 8px" }}>
          SURVEILLANCE MODULES
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  padding: "10px 14px",
                  borderRadius: "10px",
                  border: "1px solid",
                  borderColor: isActive ? "rgba(0, 245, 212, 0.35)" : "transparent",
                  background: isActive ? "linear-gradient(90deg, rgba(0, 245, 212, 0.14), rgba(56, 189, 248, 0.05))" : "transparent",
                  color: isActive ? "#00f5d4" : "var(--text-muted)",
                  fontWeight: isActive ? 600 : 500,
                  fontSize: "0.88rem",
                  cursor: "pointer",
                  textAlign: "left",
                  transition: "all 0.16s ease",
                }}
              >
                <Icon size={18} style={{ color: isActive ? "#00f5d4" : "var(--text-dim)" }} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>

        {/* Quick Ingestion Section */}
        <div style={{ marginTop: "24px", paddingTop: "18px", borderTop: "1px solid var(--border-subtle)" }}>
          <div style={{ fontSize: "0.7rem", fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.12em", padding: "0 10px 8px" }}>
            TELEMETRY DATASETS
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            <button
              onClick={handleLoadRealDataset}
              disabled={loadingScenario}
              className="btn btn-secondary"
              style={{
                justifyContent: "flex-start",
                fontSize: "0.78rem",
                padding: "8px 12px",
                background: "linear-gradient(90deg, rgba(0, 245, 212, 0.12), rgba(56, 189, 248, 0.08))",
                borderColor: "rgba(0, 245, 212, 0.4)",
                color: "#00f5d4",
                fontWeight: 600,
              }}
            >
              <Database size={14} style={{ color: "var(--accent-cyan)" }} />
              <span>Load Real CloudTrail (3k)</span>
            </button>
            <button
              onClick={() => handleLoadDemo("suspicious")}
              disabled={loadingScenario}
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "0.78rem", padding: "8px 12px" }}
            >
              <Play size={14} style={{ color: "var(--accent-danger)" }} />
              <span>Load Suspicious Attack</span>
            </button>
            <button
              onClick={() => handleLoadDemo("mixed")}
              disabled={loadingScenario}
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "0.78rem", padding: "8px 12px" }}
            >
              <Play size={14} style={{ color: "var(--accent-warn)" }} />
              <span>Load Mixed Telemetry</span>
            </button>
            <button
              onClick={() => handleLoadDemo("benign")}
              disabled={loadingScenario}
              className="btn btn-secondary"
              style={{ justifyContent: "flex-start", fontSize: "0.78rem", padding: "8px 12px" }}
            >
              <Play size={14} style={{ color: "var(--accent-success)" }} />
              <span>Load Benign Activity</span>
            </button>
          </div>

          {feedback && (
            <div style={{
              marginTop: "10px",
              padding: "6px 10px",
              borderRadius: "6px",
              background: "rgba(0, 245, 212, 0.1)",
              border: "1px solid rgba(0, 245, 212, 0.3)",
              fontSize: "0.74rem",
              color: "#00f5d4",
            }}>
              {feedback}
            </div>
          )}
        </div>
      </div>

      {/* Footer / System Status */}
      <div style={{ padding: "16px 18px", borderTop: "1px solid var(--border-subtle)", background: "rgba(6, 10, 18, 0.6)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span className="pulse-indicator" />
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 500 }}>
              AI: {health?.llm_mode?.toUpperCase() || "READY"}
            </span>
          </div>
          <span style={{ fontSize: "0.7rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
            PORT 8000
          </span>
        </div>

        <button
          onClick={onSignOut}
          className="btn btn-secondary"
          style={{ width: "100%", padding: "7px", fontSize: "0.8rem", color: "var(--accent-danger)", borderColor: "rgba(248, 113, 113, 0.25)" }}
        >
          <LogOut size={14} />
          <span>Sign Out</span>
        </button>
      </div>
    </>
  );
}
