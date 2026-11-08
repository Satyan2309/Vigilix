import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  Flame,
  Activity,
  Zap,
  Terminal,
  Database,
  Search,
  ArrowRight,
  AlertTriangle,
  CheckCircle,
  Eye,
  Server,
  Trash2,
  TrendingUp,
  Users,
  Globe,
  Radio,
  Lock,
  AlertCircle
} from "lucide-react";
import { runInvestigation, getTelemetryStats, clearEvents } from "../api";

export default function OverviewView({
  events,
  incidents,
  knowledge,
  health,
  onTelemetryUpdated,
  onNavigateToTab,
  onShowToast,
}) {
  const [investigating, setInvestigating] = useState(false);
  const [invError, setInvError] = useState("");
  const [stats, setStats] = useState(null);
  const [clearing, setClearing] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);
  const confirmClearTimerRef = React.useRef(null);

  const latestIncident = incidents?.[0] || null;
  const currentRiskScore = latestIncident ? latestIncident.risk_score : (events?.length ? 25 : 5);
  const currentSeverity = latestIncident ? latestIncident.severity : (events?.length ? "Low" : "Minimal");

  useEffect(() => {
    getTelemetryStats()
      .then((data) => setStats(data))
      .catch(() => {});
  }, [events, incidents]);

  const handleQuickInvestigate = async () => {
    setInvestigating(true);
    setInvError("");
    try {
      await runInvestigation(200, "Automated Threat Sweep");
      onTelemetryUpdated?.();
      onNavigateToTab?.("investigations");
      onShowToast?.("Investigation complete — navigating to War Room.", "success");
    } catch (err) {
      setInvError(err.message);
      onShowToast?.(`Investigation failed: ${err.message}`, "error");
    } finally {
      setInvestigating(false);
    }
  };

  const handleClearTelemetry = async () => {
    if (!confirmClear) {
      setConfirmClear(true);
      if (confirmClearTimerRef.current) clearTimeout(confirmClearTimerRef.current);
      confirmClearTimerRef.current = setTimeout(() => setConfirmClear(false), 4000);
      return;
    }
    setConfirmClear(false);
    setClearing(true);
    try {
      await clearEvents();
      onTelemetryUpdated?.();
      onShowToast?.("Workspace telemetry cleared.", "info");
    } catch (err) {
      onShowToast?.(`Clear failed: ${err.message}`, "error");
    } finally {
      setClearing(false);
    }
  };

  const getThreatColor = (score) => {
    if (score >= 85) return "#f87171";
    if (score >= 55) return "#fb923c";
    if (score >= 30) return "#fbbf24";
    return "#00f5d4";
  };

  const threatColor = getThreatColor(currentRiskScore);

  // Real time-based 16-bucket histogram
  const timelineBuckets = React.useMemo(() => {
    if (!events || events.length === 0) return Array(16).fill({ count: 0, height: 12 });
    const times = events
      .map(e => e.event_time ? new Date(e.event_time).getTime() : null)
      .filter(Boolean);
    if (times.length === 0) return Array(16).fill({ count: 0, height: 12 });
    const minT = Math.min(...times);
    const maxT = Math.max(...times);
    const range = maxT - minT || 1;
    const buckets = Array(16).fill(0);
    times.forEach(t => {
      const idx = Math.min(15, Math.floor(((t - minT) / range) * 16));
      buckets[idx]++;
    });
    const max = Math.max(...buckets, 1);
    return buckets.map(count => ({ count, height: Math.max(12, Math.round((count / max) * 44)) }));
  }, [events]);

  // Format time range labels
  const timeRange = React.useMemo(() => {
    if (!events || events.length === 0) return { earliest: "—", latest: "—" };
    const times = events.map(e => e.event_time).filter(Boolean).sort();
    const fmt = (t) => t ? t.replace("T", " ").slice(0, 16) : "—";
    return { earliest: fmt(times[0]), latest: fmt(times[times.length - 1]) };
  }, [events]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* HUD Hero Banner */}
      <div style={{
        background: "linear-gradient(135deg, rgba(16, 29, 53, 0.85) 0%, rgba(9, 16, 28, 0.95) 100%)",
        border: `1px solid ${threatColor}44`,
        borderRadius: "20px",
        padding: "28px 32px",
        boxShadow: `0 12px 40px rgba(0, 0, 0, 0.5), 0 0 35px ${threatColor}18`,
        position: "relative",
        overflow: "hidden",
      }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "20px" }}>
          <div style={{ maxWidth: "700px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px", flexWrap: "wrap" }}>
              <span className="badge badge-cyan" style={{ fontSize: "0.72rem" }}>
                SURVEILLANCE HUD
              </span>
              <span style={{ fontSize: "0.75rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                DB: {health?.database?.toUpperCase() || "POSTGRESQL"}
              </span>
              <span style={{ fontSize: "0.75rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                AI ENGINE: {health?.llm_mode?.toUpperCase() || "READY"}
              </span>
            </div>
            <h1 style={{ fontSize: "2rem", fontWeight: 700, color: "#fff", marginBottom: "8px" }}>
              Cloud Infrastructure Sentinel
            </h1>
            <p style={{ color: "var(--text-muted)", fontSize: "0.95rem", lineHeight: 1.6 }}>
              Continuous correlation of AWS CloudTrail management &amp; data events, GuardDuty behavioral findings, and Security Hub compliance posture.
            </p>
          </div>

          {/* Threat Priority Meter & Launch Triage */}
          <div style={{
            background: "rgba(6, 11, 20, 0.85)",
            border: `1px solid ${threatColor}66`,
            borderRadius: "16px",
            padding: "18px 24px",
            display: "flex",
            alignItems: "center",
            gap: "20px",
            boxShadow: `0 0 25px ${threatColor}20`,
          }}>
            <div>
              <div style={{ fontSize: "0.7rem", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.1em" }}>
                HEURISTIC THREAT INDEX
              </div>
              <div style={{ display: "flex", alignItems: "baseline", gap: "6px" }}>
                <span style={{ fontFamily: "var(--font-display)", fontSize: "2.8rem", fontWeight: 700, color: threatColor, lineHeight: 1 }}>
                  {currentRiskScore}
                </span>
                <span style={{ fontSize: "1rem", color: "var(--text-dim)", fontFamily: "var(--font-display)" }}>
                  /100
                </span>
              </div>
              <div style={{ fontSize: "0.75rem", fontWeight: 700, color: threatColor, textTransform: "uppercase", letterSpacing: "0.08em", marginTop: "2px" }}>
                {currentSeverity} PRIORITY
              </div>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <button
                onClick={handleQuickInvestigate}
                disabled={investigating || !events?.length}
                className="btn btn-primary"
                style={{ padding: "10px 18px" }}
              >
                <Zap size={15} />
                <span>{investigating ? "Correlating State..." : "Run Investigation"}</span>
              </button>
              {events && events.length > 0 && (
                <button
                  onClick={handleClearTelemetry}
                  disabled={clearing}
                  className={`btn btn-secondary ${confirmClear ? "btn-confirm-danger" : ""}`}
                  style={{ padding: "6px 12px", fontSize: "0.76rem", color: confirmClear ? "var(--accent-danger)" : "var(--accent-danger)" }}
                  title={confirmClear ? "Click again to confirm clearing all telemetry" : "Clear all workspace telemetry"}
                >
                  <Trash2 size={12} />
                  <span>{clearing ? "Clearing..." : confirmClear ? "⚠️ Confirm Clear?" : "Clear Workspace"}</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {invError && (
          <div style={{ marginTop: "16px", display: "flex", alignItems: "center", gap: "8px", color: "var(--accent-danger)", fontSize: "0.84rem" }}>
            <AlertCircle size={14} />
            <span>Investigation error: {invError}</span>
          </div>
        )}
      </div>

      {/* Cyber Metric Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "16px" }}>
        {[
          {
            label: "Total Telemetry",
            value: (events?.length || 0).toLocaleString(),
            sub: "Events Stored in Database",
            icon: Database,
            color: "var(--accent-cyan)",
          },
          {
            label: "Active Incidents",
            value: incidents?.filter(i => ["OPEN", "INVESTIGATING"].includes(String(i.status || "OPEN").toUpperCase())).length || 0,
            sub: `${incidents?.length || 0} Total Triage Reports`,
            icon: Flame,
            color: "var(--accent-danger)",
          },
          {
            label: "Distinct Principals",
            value: (stats?.unique_principals ?? (events ? new Set(events.map(e => e.principal).filter(p => p !== "unknown")).size : 0)).toLocaleString(),
            sub: "Active IAM Users & Roles",
            icon: Users,
            color: "var(--accent-blue)",
          },
          {
            label: "Observed Source IPs",
            value: (stats?.unique_ips ?? (events ? new Set(events.map(e => e.source_ip).filter(ip => ip !== "unknown")).size : 0)).toLocaleString(),
            sub: "Network Origins Tracked",
            icon: Globe,
            color: "var(--accent-purple)",
          },
        ].map((metric, i) => {
          const Icon = metric.icon;
          return (
            <div key={i} className="glass-panel" style={{ padding: "20px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "10px" }}>
                <span style={{ fontSize: "0.78rem", fontWeight: 600, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  {metric.label}
                </span>
                <Icon size={18} style={{ color: metric.color }} />
              </div>
              <div style={{ fontFamily: "var(--font-display)", fontSize: "2rem", fontWeight: 700, color: "#fff" }}>
                {metric.value}
              </div>
              <div style={{ fontSize: "0.76rem", color: "var(--text-dim)", marginTop: "4px" }}>
                {metric.sub}
              </div>
            </div>
          );
        })}
      </div>

      {/* Visual Telemetry Velocity & MITRE ATT&CK Posture */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: "20px" }}>
        {/* Real Time-Based Velocity Histogram */}
        <div className="glass-panel" style={{ padding: "20px 24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
            <div>
              <h3 style={{ fontSize: "0.98rem", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                <TrendingUp size={16} color="var(--accent-cyan)" />
                Telemetry Timeline Distribution
              </h3>
              <p style={{ fontSize: "0.76rem", color: "var(--text-dim)", margin: "2px 0 0" }}>
                Event volume bucketed across time range
              </p>
            </div>
            <span className="badge badge-cyan" style={{ fontSize: "0.68rem" }}>Time-Based</span>
          </div>

          {/* SVG Bar Histogram */}
          <div style={{ height: "64px", display: "flex", alignItems: "flex-end", gap: "4px", paddingTop: "8px" }}>
            {timelineBuckets.map((b, i) => (
              <div
                key={i}
                title={`Events: ${b.count}`}
                style={{
                  flex: 1,
                  height: `${b.height}px`,
                  background: b.count > 0
                    ? (i >= 12
                      ? "linear-gradient(180deg, var(--accent-danger), rgba(248, 113, 113, 0.3))"
                      : "linear-gradient(180deg, var(--accent-cyan), rgba(0, 245, 212, 0.15))")
                    : "rgba(56, 96, 150, 0.1)",
                  borderRadius: "3px 3px 1px 1px",
                  transition: "height 0.4s ease",
                  cursor: b.count > 0 ? "pointer" : "default",
                }}
              />
            ))}
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.68rem", color: "var(--text-dim)", marginTop: "6px" }}>
            <span title={timeRange.earliest}>{timeRange.earliest}</span>
            <span title={timeRange.latest}>{timeRange.latest}</span>
          </div>
        </div>

        {/* MITRE ATT&CK Tactics Breakdown */}
        <div className="glass-panel" style={{ padding: "20px 24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
            <div>
              <h3 style={{ fontSize: "0.98rem", fontWeight: 700, margin: 0, display: "flex", alignItems: "center", gap: "8px" }}>
                <ShieldAlert size={16} color="var(--accent-warn)" />
                Observed MITRE ATT&CK Tactics
              </h3>
              <p style={{ fontSize: "0.76rem", color: "var(--text-dim)", margin: "2px 0 0" }}>
                Heuristic tactic mapping across active events
              </p>
            </div>
            <span className="badge badge-medium" style={{ fontSize: "0.68rem" }}>Matrix v14</span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {[
              { tactic: "Credential Access", keywords: ["Login", "GetCredentials", "AssumeRole", "Key"], color: "var(--accent-danger)" },
              { tactic: "Defense Evasion", keywords: ["StopLogging", "DeleteTrail", "PutBucketLogging", "KMS", "DisableKey"], color: "var(--accent-warn)" },
              { tactic: "Privilege Escalation", keywords: ["PutUserPolicy", "AttachUserPolicy", "CreateRole", "PutRolePolicy"], color: "var(--accent-purple)" },
              { tactic: "Exfiltration / S3 Exposure", keywords: ["PutBucketAcl", "PutBucketPolicy", "GetObject", "ListBucket"], color: "var(--accent-blue)" },
            ].map((t, idx) => {
              const count = events
                ? events.filter(e => t.keywords.some(kw => e.event_name.includes(kw))).length
                : 0;
              const pct = events?.length ? Math.min(100, Math.round((count / events.length) * 100)) : 0;
              return (
                <div key={idx}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.76rem", marginBottom: "3px" }}>
                    <span style={{ color: "#fff", fontWeight: 600 }}>{t.tactic}</span>
                    <span style={{ color: t.color, fontFamily: "var(--font-mono)" }}>
                      {count} events {count > 0 && `(${pct}%)`}
                    </span>
                  </div>
                  <div style={{ height: "5px", background: "rgba(255,255,255,0.06)", borderRadius: "3px", overflow: "hidden" }}>
                    <div style={{
                      width: `${Math.max(count > 0 ? 4 : 0, pct)}%`,
                      height: "100%",
                      background: t.color,
                      borderRadius: "3px",
                      transition: "width 0.6s ease",
                    }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Grid: Signals Stream & Telemetry Feed */}
      <div className="responsive-grid-overview">
        {/* Left: Recent Telemetry Stream */}
        <div className="glass-panel">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "18px" }}>
            <div>
              <h3 style={{ fontSize: "1.1rem" }}>Surveillance Telemetry Stream</h3>
              <p style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
                Latest 10 AWS management &amp; security events
              </p>
            </div>
            <button
              onClick={() => onNavigateToTab?.("explorer")}
              className="btn btn-secondary"
              style={{ padding: "6px 12px", fontSize: "0.76rem" }}
            >
              <span>Explore All</span>
              <ArrowRight size={13} />
            </button>
          </div>

          {events && events.length > 0 ? (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.82rem" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", textAlign: "left" }}>
                    <th style={{ padding: "8px 10px" }}>TIME</th>
                    <th style={{ padding: "8px 10px" }}>EVENT NAME</th>
                    <th style={{ padding: "8px 10px" }}>ACTOR / PRINCIPAL</th>
                    <th style={{ padding: "8px 10px" }}>SOURCE IP</th>
                  </tr>
                </thead>
                <tbody>
                  {events.slice(0, 10).map((ev, i) => (
                    <tr
                      key={ev.event_id || i}
                      style={{ borderBottom: "1px solid rgba(56, 96, 150, 0.1)", transition: "background 0.15s" }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(255,255,255,0.03)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <td style={{ padding: "9px 10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.76rem", whiteSpace: "nowrap" }}>
                        {ev.event_time ? ev.event_time.replace("T", " ").slice(0, 19) : "unknown"}
                      </td>
                      <td style={{ padding: "9px 10px", fontWeight: 600, color: "#fff" }}>
                        {ev.event_name}
                      </td>
                      <td style={{ padding: "9px 10px", color: ev.principal?.toLowerCase() === "root" ? "var(--accent-danger)" : "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.78rem" }}>
                        {ev.principal?.toLowerCase() === "root" ? "🚨 root" : (ev.principal || "unknown")}
                      </td>
                      <td style={{ padding: "9px 10px", fontFamily: "var(--font-mono)", fontSize: "0.76rem" }}>
                        <span style={{ color: "var(--accent-blue)" }}>{ev.source_ip || "unknown"}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "40px 20px", color: "var(--text-dim)" }}>
              No telemetry loaded. Use the sidebar to load synthetic scenario logs.
            </div>
          )}
        </div>

        {/* Right: Latest Investigation & Threat Hypotheses */}
        <div className="glass-panel">
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "18px" }}>
            <div>
              <h3 style={{ fontSize: "1.1rem" }}>Active Triage Incident</h3>
              <p style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
                Latest correlated LangGraph triage report
              </p>
            </div>
            {latestIncident && (
              <span className={`badge ${latestIncident.risk_score >= 85 ? "badge-critical" : latestIncident.risk_score >= 55 ? "badge-high" : "badge-medium"}`}>
                {latestIncident.severity}
              </span>
            )}
          </div>

          {latestIncident ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{
                background: "rgba(10, 18, 32, 0.7)",
                borderRadius: "12px",
                padding: "16px",
                border: "1px solid var(--border-subtle)",
              }}>
                <div style={{ fontWeight: 700, fontSize: "1rem", color: "#fff", marginBottom: "6px" }}>
                  {latestIncident.title}
                </div>
                <p style={{ fontSize: "0.85rem", color: "var(--text-muted)", lineHeight: 1.5 }}>
                  {latestIncident.summary}
                </p>
              </div>

              {latestIncident.hypotheses && latestIncident.hypotheses.length > 0 && (
                <div>
                  <div style={{ fontSize: "0.72rem", fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "8px" }}>
                    ROOT-CAUSE HYPOTHESES TO VALIDATE
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {latestIncident.hypotheses.slice(0, 3).map((hyp, i) => (
                      <div
                        key={i}
                        style={{
                          display: "flex", alignItems: "flex-start", gap: "8px",
                          fontSize: "0.82rem", color: "var(--text-muted)",
                          background: "rgba(255, 255, 255, 0.02)",
                          padding: "8px 10px", borderRadius: "8px",
                        }}
                      >
                        <AlertTriangle size={15} style={{ color: "var(--accent-warn)", flexShrink: 0, marginTop: "2px" }} />
                        <span>{hyp}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <button
                onClick={() => onNavigateToTab?.("investigations")}
                className="btn btn-secondary"
                style={{ width: "100%", marginTop: "8px", justifyContent: "center" }}
              >
                <span>View Full War Room Report</span>
                <ArrowRight size={14} />
              </button>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "40px 20px", color: "var(--text-dim)" }}>
              No incidents analyzed yet. Click &ldquo;Run Investigation&rdquo; above.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
