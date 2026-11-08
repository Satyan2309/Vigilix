import React, { useState } from "react";
import {
  Flame,
  Zap,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  BookOpen,
  Code2,
  Copy,
  ChevronDown,
  ChevronRight,
  Clock,
  Trash2,
  Bot,
  Filter,
  CheckSquare,
  Square
} from "lucide-react";
import { runInvestigation, updateIncidentStatus, toggleIncidentAction, deleteIncident } from "../api";

export default function InvestigationsView({ incidents, onTelemetryUpdated, onAskCopilot, onShowToast }) {
  const [title, setTitle] = useState("Cloud Security Incident Triage");
  const [limit, setLimit] = useState(200);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeIncident, setActiveIncident] = useState(incidents?.[0] || null);
  const [showJson, setShowJson] = useState(false);
  const [copied, setCopied] = useState(false);
  const [statusFilter, setStatusFilter] = useState("ALL"); // "ALL" | "OPEN" | "RESOLVED"
  const [actionLoading, setActionLoading] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const deleteTimerRef = React.useRef(null);

  // Sync active incident if null and list updates
  React.useEffect(() => {
    if (!activeIncident && incidents && incidents.length > 0) {
      setActiveIncident(incidents[0]);
    } else if (activeIncident && incidents) {
      const match = incidents.find((i) => i.incident_id === activeIncident.incident_id);
      if (match) setActiveIncident(match);
    }
  }, [incidents]);

  const handleRunInvestigation = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const rep = await runInvestigation(limit, title);
      setActiveIncident(rep);
      onTelemetryUpdated?.();
      onShowToast?.("Threat investigation concluded successfully.", "success");
    } catch (err) {
      setError(err.message);
      onShowToast?.(`Investigation failed: ${err.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = async (newStatus) => {
    if (!activeIncident) return;
    try {
      const updated = await updateIncidentStatus(activeIncident.incident_id, newStatus);
      setActiveIncident(updated);
      onTelemetryUpdated?.();
      onShowToast?.(`Incident status updated to ${newStatus}.`, "success");
    } catch (err) {
      onShowToast?.(`Failed to update status: ${err.message}`, "error");
    }
  };

  const handleToggleAction = async (idx, currentCompleted) => {
    if (!activeIncident || actionLoading) return;
    setActionLoading(true);
    try {
      const updated = await toggleIncidentAction(activeIncident.incident_id, idx, !currentCompleted);
      setActiveIncident(updated);
      onTelemetryUpdated?.();
      onShowToast?.(
        !currentCompleted ? "Action item marked complete." : "Action item reopened.",
        "info"
      );
    } catch (err) {
      console.error("Failed to toggle action:", err);
      onShowToast?.(`Action toggle failed: ${err.message}`, "error");
    } finally {
      setActionLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!activeIncident) return;
    if (!confirmDelete) {
      setConfirmDelete(true);
      if (deleteTimerRef.current) clearTimeout(deleteTimerRef.current);
      deleteTimerRef.current = setTimeout(() => setConfirmDelete(false), 4000);
      return;
    }
    setConfirmDelete(false);
    try {
      await deleteIncident(activeIncident.incident_id);
      setActiveIncident(null);
      onTelemetryUpdated?.();
      onShowToast?.("Incident report deleted from database.", "info");
    } catch (err) {
      onShowToast?.(`Delete failed: ${err.message}`, "error");
    }
  };

  const handleCopyJson = () => {
    if (!activeIncident) return;
    navigator.clipboard.writeText(JSON.stringify(activeIncident, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusBadge = (status) => {
    const s = String(status || "OPEN").toUpperCase();
    if (s === "OPEN") return <span className="badge badge-critical">OPEN</span>;
    if (s === "INVESTIGATING") return <span className="badge badge-medium">INVESTIGATING</span>;
    if (s === "CONTAINED") return <span className="badge badge-info">CONTAINED</span>;
    if (s === "RESOLVED") return <span className="badge badge-low">RESOLVED</span>;
    return <span className="badge badge-cyan">{s}</span>;
  };

  const filteredIncidents = (incidents || []).filter((inc) => {
    if (statusFilter === "ALL") return true;
    const s = String(inc.status || "OPEN").toUpperCase();
    if (statusFilter === "OPEN") return s === "OPEN" || s === "INVESTIGATING";
    if (statusFilter === "RESOLVED") return s === "RESOLVED" || s === "CONTAINED";
    return true;
  });

  // Extract actions robustly
  const actionsList = activeIncident?.defensive_actions || activeIncident?.recommended_actions || [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Investigation Trigger Card */}
      <div className="glass-panel" style={{ padding: "24px 28px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <div>
            <h3 style={{ fontSize: "1.2rem", display: "flex", alignItems: "center", gap: "10px" }}>
              <Flame size={20} style={{ color: "var(--accent-danger)" }} />
              <span>Launch LangGraph Investigation State Machine</span>
            </h3>
            <p style={{ fontSize: "0.84rem", color: "var(--text-dim)" }}>
              Executes deterministic correlation, vector retrieval against threat runbooks, and evidence-grounded AI synthesis.
            </p>
          </div>
        </div>

        <form onSubmit={handleRunInvestigation} style={{ display: "flex", gap: "16px", flexWrap: "wrap", alignItems: "flex-end" }}>
          <div style={{ flex: 1, minWidth: "260px" }}>
            <label style={{ display: "block", fontSize: "0.76rem", fontWeight: 700, color: "var(--text-dim)", marginBottom: "6px" }}>
              INVESTIGATION TITLE
            </label>
            <input
              type="text"
              className="input"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Unauthorized IAM Credential & Trail Tampering"
            />
          </div>

          <div style={{ width: "160px" }}>
            <label style={{ display: "block", fontSize: "0.76rem", fontWeight: 700, color: "var(--text-dim)", marginBottom: "6px" }}>
              EVENTS TO ANALYZE
            </label>
            <select
              className="input-control"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
            >
              <option value={50}>Recent 50</option>
              <option value={100}>Recent 100</option>
              <option value={200}>Recent 200</option>
              <option value={500}>Recent 500</option>
            </select>
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ height: "42px", padding: "0 24px" }}
          >
            <Zap size={16} />
            <span>{loading ? "Running State Machine..." : "Execute Investigation"}</span>
          </button>
        </form>

        {error && (
          <div style={{ marginTop: "14px", color: "var(--accent-danger)", fontSize: "0.84rem" }}>
            {error}
          </div>
        )}
      </div>

      {/* Main Investigation Split View */}
      <div className="responsive-grid-split">
        {/* Left: Investigation Archive List */}
        <div className="glass-panel" style={{ padding: "18px", height: "fit-content", maxHeight: "820px", overflowY: "auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
            <h4 style={{ fontSize: "0.85rem", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--text-dim)", margin: 0 }}>
              ARCHIVE ({filteredIncidents.length})
            </h4>
            {/* Filter Chips */}
            <div style={{ display: "flex", gap: "4px" }}>
              {["ALL", "OPEN", "RESOLVED"].map((f) => (
                <button
                  key={f}
                  onClick={() => setStatusFilter(f)}
                  style={{
                    background: statusFilter === f ? "rgba(0, 245, 212, 0.15)" : "transparent",
                    color: statusFilter === f ? "var(--accent-cyan)" : "var(--text-dim)",
                    border: "1px solid",
                    borderColor: statusFilter === f ? "rgba(0, 245, 212, 0.4)" : "transparent",
                    borderRadius: "6px",
                    padding: "3px 8px",
                    fontSize: "0.7rem",
                    cursor: "pointer",
                    fontWeight: 600,
                  }}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          {filteredIncidents && filteredIncidents.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {filteredIncidents.map((inc) => {
                const isSelected = activeIncident?.incident_id === inc.incident_id;
                return (
                  <div
                    key={inc.incident_id}
                    onClick={() => setActiveIncident(inc)}
                    style={{
                      padding: "12px",
                      borderRadius: "10px",
                      border: "1px solid",
                      borderColor: isSelected ? "var(--accent-cyan)" : "var(--border-subtle)",
                      background: isSelected ? "rgba(0, 245, 212, 0.08)" : "rgba(10, 18, 32, 0.6)",
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "4px" }}>
                      <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                        <span className={`badge ${inc.risk_score >= 85 ? "badge-critical" : inc.risk_score >= 55 ? "badge-high" : "badge-medium"}`} style={{ fontSize: "0.65rem" }}>
                          {inc.severity}
                        </span>
                        {getStatusBadge(inc.status)}
                      </div>
                      <span style={{ fontSize: "0.78rem", fontWeight: 700, fontFamily: "var(--font-mono)", color: "#fff" }}>
                        {inc.risk_score}/100
                      </span>
                    </div>
                    <div style={{ fontWeight: 600, fontSize: "0.85rem", color: isSelected ? "#00f5d4" : "#fff", marginBottom: "4px" }}>
                      {inc.title}
                    </div>
                    <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", display: "flex", alignItems: "center", gap: "4px" }}>
                      <Clock size={12} />
                      <span>{inc.created_at ? String(inc.created_at).slice(0, 19).replace("T", " ") : "Recent"}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div style={{ padding: "20px 0", textAlign: "center", color: "var(--text-dim)", fontSize: "0.85rem" }}>
              No incidents match this filter.
            </div>
          )}
        </div>

        {/* Right: Selected Incident Deep Dive */}
        {activeIncident ? (
          <div className="glass-panel" style={{ padding: "28px" }}>
            {/* Header info */}
            <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: "16px", marginBottom: "20px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "18px" }}>
              <div style={{ flex: 1, minWidth: "260px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px", flexWrap: "wrap" }}>
                  <span className={`badge ${activeIncident.risk_score >= 85 ? "badge-critical" : activeIncident.risk_score >= 55 ? "badge-high" : "badge-medium"}`} style={{ fontSize: "0.78rem", padding: "6px 14px" }}>
                    {activeIncident.severity} SEVERITY
                  </span>
                  
                  {/* Status Dropdown */}
                  <select
                    value={activeIncident.status || "OPEN"}
                    onChange={(e) => handleStatusChange(e.target.value)}
                    className="input-control"
                    style={{ width: "auto", padding: "4px 28px 4px 10px", fontSize: "0.76rem", fontWeight: 700 }}
                  >
                    <option value="OPEN">🔴 OPEN</option>
                    <option value="INVESTIGATING">🟡 INVESTIGATING</option>
                    <option value="CONTAINED">🔵 CONTAINED</option>
                    <option value="RESOLVED">🟢 RESOLVED</option>
                    <option value="FALSE_POSITIVE">⚪ FALSE POSITIVE</option>
                  </select>

                  <span style={{ fontSize: "0.82rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                    ID: {activeIncident.incident_id?.slice(0, 16)}
                  </span>
                </div>
                <h3 style={{ fontSize: "1.35rem", fontWeight: 700, color: "#fff", margin: "0 0 6px 0" }}>
                  {activeIncident.title}
                </h3>
              </div>

              {/* Actions */}
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
                <button
                  onClick={() => onAskCopilot?.(`Analyze incident '${activeIncident.title}' (Severity: ${activeIncident.severity}, Risk: ${activeIncident.risk_score}/100). Summary: ${activeIncident.summary}`)}
                  className="btn btn-secondary"
                  style={{ padding: "8px 12px", fontSize: "0.8rem", color: "var(--accent-cyan)" }}
                  title="Ask AI Copilot to analyze this incident"
                >
                  <Bot size={15} />
                  <span>Ask Copilot</span>
                </button>
                <button
                  onClick={() => setShowJson(!showJson)}
                  className="btn btn-secondary"
                  style={{ padding: "8px 12px", fontSize: "0.8rem" }}
                  title="Toggle raw report JSON"
                >
                  <Code2 size={15} />
                  <span>{showJson ? "View Report" : "Inspect JSON"}</span>
                </button>
                <button
                  onClick={handleDelete}
                  className={`btn btn-secondary ${confirmDelete ? "btn-confirm-danger" : ""}`}
                  style={{
                    padding: "8px 12px",
                    fontSize: "0.8rem",
                    color: "var(--accent-danger)",
                    borderColor: confirmDelete ? "var(--accent-danger)" : undefined,
                  }}
                  title={confirmDelete ? "Click again to permanently delete" : "Delete incident report"}
                >
                  <Trash2 size={15} />
                  {confirmDelete && <span style={{ fontSize: "0.74rem" }}>Confirm Delete?</span>}
                </button>
              </div>
            </div>

            {showJson ? (
              <div>
                <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "10px" }}>
                  <button onClick={handleCopyJson} className="btn btn-secondary" style={{ padding: "6px 12px", fontSize: "0.78rem" }}>
                    <Copy size={13} />
                    <span>{copied ? "Copied!" : "Copy JSON"}</span>
                  </button>
                </div>
                <pre style={{
                  background: "#080e18",
                  padding: "18px",
                  borderRadius: "10px",
                  fontSize: "0.78rem",
                  color: "#a5b4fc",
                  overflowX: "auto",
                  border: "1px solid var(--border-subtle)",
                }}>
                  {JSON.stringify(activeIncident, null, 2)}
                </pre>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
                {/* Executive Summary */}
                <div>
                  <h4 style={{ fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--accent-cyan)", marginBottom: "8px" }}>
                    EXECUTIVE SUMMARY
                  </h4>
                  <p style={{ fontSize: "0.95rem", color: "var(--text-main)", lineHeight: 1.6, background: "rgba(10, 18, 32, 0.6)", padding: "16px", borderRadius: "12px", border: "1px solid var(--border-subtle)" }}>
                    {activeIncident.summary}
                  </p>
                </div>

                {/* Signals Grid */}
                {activeIncident.signals && activeIncident.signals.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--accent-cyan)", marginBottom: "10px" }}>
                      OBSERVED CORRELATION SIGNALS ({activeIncident.signals.length})
                    </h4>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: "10px" }}>
                      {activeIncident.signals.map((sig, i) => (
                        <div
                          key={i}
                          style={{
                            padding: "12px 16px",
                            borderRadius: "10px",
                            background: "rgba(12, 21, 38, 0.7)",
                            border: "1px solid var(--border-subtle)",
                            display: "flex",
                            alignItems: "flex-start",
                            gap: "12px",
                          }}
                        >
                          <ShieldAlert size={18} style={{ color: sig.severity === "critical" ? "var(--accent-danger)" : "var(--accent-warn)", marginTop: "2px", flexShrink: 0 }} />
                          <div style={{ flex: 1 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "3px" }}>
                              <span style={{ fontWeight: 600, fontSize: "0.9rem", color: "#fff" }}>
                                {sig.title}
                              </span>
                              <span className={`badge ${sig.severity === "critical" ? "badge-critical" : "badge-medium"}`} style={{ fontSize: "0.65rem" }}>
                                {sig.severity}
                              </span>
                            </div>
                            <p style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>
                              {sig.description}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Hypotheses & Interactive Defensive Actions */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "20px" }}>
                  {/* Hypotheses */}
                  <div>
                    <h4 style={{ fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--accent-cyan)", marginBottom: "10px" }}>
                      ROOT-CAUSE HYPOTHESES
                    </h4>
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {activeIncident.hypotheses?.map((hyp, i) => (
                        <div
                          key={i}
                          style={{
                            padding: "12px 14px",
                            borderRadius: "8px",
                            background: "rgba(10, 18, 32, 0.5)",
                            border: "1px solid var(--border-subtle)",
                            fontSize: "0.84rem",
                            color: "var(--text-muted)",
                            lineHeight: 1.5,
                          }}
                        >
                          {hyp}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Interactive Defensive Action Checklist */}
                  <div>
                    <h4 style={{ fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--accent-cyan)", marginBottom: "10px" }}>
                      DEFENSIVE ACTION CHECKLIST ({actionsList.filter(a => typeof a === 'object' && a.completed).length}/{actionsList.length})
                    </h4>
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {actionsList.map((act, i) => {
                        const isCompleted = typeof act === "object" ? !!act.completed : false;
                        const actionText = typeof act === "object" ? act.text || act.action || JSON.stringify(act) : String(act);
                        return (
                          <div
                            key={i}
                            onClick={() => handleToggleAction(i, isCompleted)}
                            style={{
                              padding: "10px 14px",
                              borderRadius: "8px",
                              background: isCompleted ? "rgba(52, 211, 153, 0.1)" : "rgba(10, 18, 32, 0.5)",
                              border: "1px solid",
                              borderColor: isCompleted ? "rgba(52, 211, 153, 0.35)" : "var(--border-subtle)",
                              fontSize: "0.84rem",
                              color: isCompleted ? "var(--accent-success)" : "var(--text-muted)",
                              display: "flex",
                              alignItems: "flex-start",
                              gap: "10px",
                              cursor: "pointer",
                              textDecoration: isCompleted ? "line-through" : "none",
                              transition: "all 0.15s ease",
                            }}
                          >
                            {isCompleted ? (
                              <CheckSquare size={16} style={{ color: "var(--accent-success)", marginTop: "2px", flexShrink: 0 }} />
                            ) : (
                              <Square size={16} style={{ color: "var(--text-dim)", marginTop: "2px", flexShrink: 0 }} />
                            )}
                            <span style={{ flex: 1 }}>{actionText}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* Synthesis Narrative */}
                {activeIncident.analysis_markdown && (
                  <div>
                    <h4 style={{ fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.08em", color: "var(--accent-cyan)", marginBottom: "10px" }}>
                      EVIDENCE ANALYSIS NARRATIVE
                    </h4>
                    <div style={{
                      background: "rgba(10, 18, 32, 0.6)",
                      padding: "20px",
                      borderRadius: "12px",
                      border: "1px solid var(--border-subtle)",
                      fontSize: "0.9rem",
                      color: "var(--text-main)",
                      lineHeight: 1.7,
                      whiteSpace: "pre-line",
                    }}>
                      {activeIncident.analysis_markdown}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ) : (
          <div className="glass-panel" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "400px", color: "var(--text-dim)" }}>
            Select an incident from the archive or execute a new investigation.
          </div>
        )}
      </div>
    </div>
  );
}
