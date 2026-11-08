import React, { useState } from "react";
import { Search, Filter, Download, Eye, X, ShieldAlert, Globe, Server, Lock, Bot, ChevronLeft, ChevronRight, AlertCircle } from "lucide-react";
import { getEvents } from "../api";

const PAGE_SIZE = 100;

export default function EventExplorerView({ initialEvents, onRefresh, onAskCopilot, onShowToast }) {
  const [events, setEvents] = useState(initialEvents || []);
  const [eventName, setEventName] = useState("");
  const [principal, setPrincipal] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [provider, setProvider] = useState("All");
  const [loading, setLoading] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [filterError, setFilterError] = useState("");
  const [page, setPage] = useState(0);

  React.useEffect(() => {
    setEvents(initialEvents || []);
    setPage(0);
  }, [initialEvents]);

  const totalPages = Math.ceil(events.length / PAGE_SIZE);
  const pagedEvents = events.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const handleFilter = async (preset = {}) => {
    setLoading(true);
    setFilterError("");
    setPage(0);
    const params = {
      limit: 1000,
      event_name: preset.eventName !== undefined ? preset.eventName : eventName,
      principal: preset.principal !== undefined ? preset.principal : principal,
      source_ip: preset.sourceIp !== undefined ? preset.sourceIp : sourceIp,
      provider: preset.provider !== undefined ? preset.provider : provider,
    };
    try {
      const data = await getEvents(params);
      setEvents(data.events || []);
    } catch (err) {
      setFilterError(err.message);
      onShowToast?.(`Filter failed: ${err.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const handleExportCsv = () => {
    if (!events.length) return;
    const headers = ["event_id", "event_time", "event_name", "principal", "source_ip", "region", "provider", "error_code"];
    const rows = events.map((e) => headers.map((h) => JSON.stringify(e[h] || "")).join(","));
    const csvContent = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `vigilix_telemetry_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    onShowToast?.(`Exported ${events.length} events to CSV.`, "success");
  };

  const getIpBadge = (ip) => {
    if (!ip || ip === "unknown") return null;
    if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.1") || ip.startsWith("172.2") || ip.startsWith("172.3")) {
      return <span className="badge badge-low" style={{ fontSize: "0.65rem" }}>PRIVATE</span>;
    }
    if (ip.startsWith("203.0.113.") || ip.startsWith("198.51.100.") || ip.startsWith("192.0.2.")) {
      return <span className="badge badge-cyan" style={{ fontSize: "0.65rem" }}>DOC-NET</span>;
    }
    if (ip.includes("amazonaws.com")) {
      return <span className="badge badge-medium" style={{ fontSize: "0.65rem" }}>AWS</span>;
    }
    return <span className="badge badge-high" style={{ fontSize: "0.65rem" }}>PUBLIC</span>;
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Filter Header Panel */}
      <div className="glass-panel" style={{ padding: "20px 24px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
          <div>
            <h3 style={{ fontSize: "1.15rem" }}>Telemetry Event Explorer</h3>
            <p style={{ fontSize: "0.8rem", color: "var(--text-dim)" }}>
              Filter, search, and inspect normalized audit records across your cloud estate.
            </p>
          </div>
          <button
            onClick={handleExportCsv}
            disabled={!events.length}
            className="btn btn-secondary"
            style={{ padding: "8px 14px", fontSize: "0.82rem" }}
          >
            <Download size={14} />
            <span>Export CSV ({events.length.toLocaleString()})</span>
          </button>
        </div>

        {/* Quick Filter Presets */}
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "16px" }}>
          <span style={{ fontSize: "0.74rem", fontWeight: 700, color: "var(--text-dim)", alignSelf: "center", marginRight: "4px" }}>
            PRESETS:
          </span>
          {[
            { label: "Failed Logins", eventName: "ConsoleLogin" },
            { label: "Root Principal", principal: "root" },
            { label: "IAM & Policy", eventName: "Policy" },
            { label: "StopLogging", eventName: "StopLogging" },
            { label: "S3 Buckets", eventName: "Bucket" },
            { label: "Security Groups", eventName: "SecurityGroup" },
            { label: "GuardDuty Findings", provider: "guardduty" },
          ].map((preset) => (
            <button
              key={preset.label}
              onClick={() => {
                if (preset.eventName !== undefined) setEventName(preset.eventName);
                if (preset.principal !== undefined) setPrincipal(preset.principal);
                if (preset.provider !== undefined) setProvider(preset.provider);
                handleFilter({
                  eventName: preset.eventName,
                  principal: preset.principal,
                  provider: preset.provider,
                });
              }}
              className="btn btn-secondary"
              style={{ fontSize: "0.75rem", padding: "5px 10px" }}
            >
              {preset.label}
            </button>
          ))}
          <button
            onClick={() => {
              setEventName(""); setPrincipal(""); setSourceIp(""); setProvider("All");
              handleFilter({ eventName: "", principal: "", sourceIp: "", provider: "All" });
            }}
            className="btn btn-secondary"
            style={{ fontSize: "0.75rem", padding: "5px 10px", color: "var(--accent-cyan)" }}
          >
            Reset Filters
          </button>
        </div>

        {/* Inputs Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr)) 110px", gap: "12px", alignItems: "flex-end" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.74rem", fontWeight: 600, color: "var(--text-dim)", marginBottom: "4px" }}>
              EVENT NAME
            </label>
            <input
              type="text"
              className="input"
              placeholder="e.g. StopLogging"
              value={eventName}
              onChange={(e) => setEventName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleFilter()}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.74rem", fontWeight: 600, color: "var(--text-dim)", marginBottom: "4px" }}>
              PRINCIPAL / USER
            </label>
            <input
              type="text"
              className="input"
              placeholder="e.g. root, admin"
              value={principal}
              onChange={(e) => setPrincipal(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleFilter()}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.74rem", fontWeight: 600, color: "var(--text-dim)", marginBottom: "4px" }}>
              SOURCE IP
            </label>
            <input
              type="text"
              className="input"
              placeholder="e.g. 203.0.113"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleFilter()}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.74rem", fontWeight: 600, color: "var(--text-dim)", marginBottom: "4px" }}>
              PROVIDER
            </label>
            <select
              className="input"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
            >
              <option value="All">All Providers</option>
              <option value="aws">AWS CloudTrail</option>
              <option value="guardduty">GuardDuty</option>
              <option value="securityhub">Security Hub</option>
              <option value="uploaded">Uploaded Logs</option>
            </select>
          </div>

          <button
            onClick={() => handleFilter()}
            disabled={loading}
            className="btn btn-primary"
            style={{ height: "42px" }}
          >
            <Search size={15} />
            <span>{loading ? "Filtering..." : "Filter"}</span>
          </button>
        </div>

        {filterError && (
          <div style={{ marginTop: "12px", display: "flex", alignItems: "center", gap: "8px", color: "var(--accent-danger)", fontSize: "0.82rem" }}>
            <AlertCircle size={14} />
            <span>{filterError}</span>
          </div>
        )}
      </div>

      {/* Events Table Panel */}
      <div className="glass-panel" style={{ padding: "0", overflow: "hidden" }}>
        <div style={{ padding: "14px 20px", borderBottom: "1px solid var(--border-subtle)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: "0.82rem", fontWeight: 600, color: "var(--text-dim)" }}>
            SHOWING {pagedEvents.length.toLocaleString()} OF {events.length.toLocaleString()} TELEMETRY EVENTS
            {totalPages > 1 && ` (PAGE ${page + 1} / ${totalPages})`}
          </span>
          {loading && <span className="pulse-indicator" />}
        </div>

        {events && events.length > 0 ? (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.84rem" }}>
                <thead>
                  <tr style={{ background: "rgba(10, 18, 32, 0.75)", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-dim)", textAlign: "left" }}>
                    <th style={{ padding: "10px 16px" }}>TIMESTAMP</th>
                    <th style={{ padding: "10px 16px" }}>EVENT NAME</th>
                    <th style={{ padding: "10px 16px" }}>ACTOR / PRINCIPAL</th>
                    <th style={{ padding: "10px 16px" }}>SOURCE IP & THREAT CLASS</th>
                    <th style={{ padding: "10px 16px" }}>REGION</th>
                    <th style={{ padding: "10px 16px" }}>PROVIDER</th>
                    <th style={{ padding: "10px 16px", textAlign: "right" }}>INSPECT</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedEvents.map((ev, index) => {
                    const hasError = ev.error_code && ev.error_code !== "None";
                    const isRoot = ev.principal?.toLowerCase() === "root";
                    return (
                      <tr
                        key={ev.event_id || index}
                        style={{
                          borderBottom: "1px solid rgba(56, 96, 150, 0.12)",
                          transition: "background 0.15s ease",
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(0, 245, 212, 0.04)")}
                        onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                      >
                        <td style={{ padding: "11px 16px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: "0.78rem", whiteSpace: "nowrap" }}>
                          {ev.event_time ? ev.event_time.replace("T", " ").slice(0, 19) : "unknown"}
                        </td>
                        <td style={{ padding: "11px 16px", fontWeight: 600, color: "#fff" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span>{ev.event_name}</span>
                            {hasError && (
                              <span className="badge badge-critical" style={{ fontSize: "0.62rem", padding: "2px 6px" }}>
                                {ev.error_code}
                              </span>
                            )}
                          </div>
                        </td>
                        <td style={{ padding: "11px 16px", fontFamily: "var(--font-mono)", fontSize: "0.8rem", color: isRoot ? "var(--accent-danger)" : "var(--text-muted)" }}>
                          {isRoot ? "🚨 root" : ev.principal || "unknown"}
                        </td>
                        <td style={{ padding: "11px 16px", fontFamily: "var(--font-mono)", fontSize: "0.78rem" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <span style={{ color: "var(--accent-blue)" }}>{ev.source_ip || "unknown"}</span>
                            {getIpBadge(ev.source_ip)}
                          </div>
                        </td>
                        <td style={{ padding: "11px 16px", color: "var(--text-dim)", fontSize: "0.78rem" }}>
                          {ev.region || "unknown"}
                        </td>
                        <td style={{ padding: "11px 16px" }}>
                          <span className="badge badge-cyan" style={{ fontSize: "0.65rem" }}>
                            {ev.provider}
                          </span>
                        </td>
                        <td style={{ padding: "11px 16px", textAlign: "right" }}>
                          <button
                            onClick={() => setSelectedEvent(ev)}
                            className="btn btn-secondary"
                            style={{ padding: "5px 9px", fontSize: "0.74rem" }}
                            title="Inspect raw telemetry payload"
                          >
                            <Eye size={13} />
                            <span>Raw JSON</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="pagination">
                <button
                  className="pagination-btn"
                  onClick={() => setPage(0)}
                  disabled={page === 0}
                >
                  «
                </button>
                <button
                  className="pagination-btn"
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                >
                  <ChevronLeft size={14} />
                </button>
                <span style={{ flex: 1, textAlign: "center" }}>
                  Page <strong style={{ color: "#fff" }}>{page + 1}</strong> of <strong style={{ color: "#fff" }}>{totalPages}</strong>
                  {" · "}
                  <span style={{ color: "var(--text-dim)" }}>
                    rows {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, events.length)} of {events.length.toLocaleString()}
                  </span>
                </span>
                <button
                  className="pagination-btn"
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                >
                  <ChevronRight size={14} />
                </button>
                <button
                  className="pagination-btn"
                  onClick={() => setPage(totalPages - 1)}
                  disabled={page >= totalPages - 1}
                >
                  »
                </button>
              </div>
            )}
          </>
        ) : (
          <div style={{ textAlign: "center", padding: "50px 20px", color: "var(--text-dim)" }}>
            {loading ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "12px", alignItems: "center" }}>
                <span className="pulse-indicator" style={{ width: "12px", height: "12px" }} />
                <span>Filtering telemetry…</span>
              </div>
            ) : "No events match the selected criteria."}
          </div>
        )}
      </div>

      {/* Raw Event Modal */}
      {selectedEvent && (
        <div style={{
          position: "fixed", inset: 0,
          background: "rgba(4, 7, 14, 0.82)",
          backdropFilter: "blur(14px)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 9999, padding: "20px",
        }}
          onClick={() => setSelectedEvent(null)}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "100%", maxWidth: "720px",
              background: "#0a111e",
              border: "1px solid var(--accent-cyan)",
              borderRadius: "16px", padding: "24px",
              boxShadow: "0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(0, 245, 212, 0.15)",
              maxHeight: "85vh", display: "flex", flexDirection: "column",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "12px" }}>
              <div>
                <h3 style={{ fontSize: "1.1rem", color: "#fff" }}>
                  {selectedEvent.event_name}
                </h3>
                <span style={{ fontSize: "0.75rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                  ID: {selectedEvent.event_id}
                </span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", padding: "4px" }}
              >
                <X size={20} />
              </button>
            </div>

            <pre style={{
              flex: 1, background: "#04070d", padding: "16px", borderRadius: "10px",
              overflowY: "auto", fontSize: "0.78rem", color: "#a5b4fc",
              fontFamily: "var(--font-mono)",
            }}>
              {JSON.stringify(selectedEvent.raw || selectedEvent, null, 2)}
            </pre>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "14px" }}>
              <button
                onClick={() => {
                  onAskCopilot?.(`Analyze this AWS event:\nName: ${selectedEvent.event_name}\nPrincipal: ${selectedEvent.principal}\nSource IP: ${selectedEvent.source_ip}\nTime: ${selectedEvent.event_time}\nRaw details: ${JSON.stringify(selectedEvent.raw || selectedEvent, null, 2)}`);
                  setSelectedEvent(null);
                }}
                className="btn btn-primary"
                style={{ padding: "8px 16px", fontSize: "0.82rem" }}
              >
                <Bot size={15} />
                <span>Analyze with Copilot</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
