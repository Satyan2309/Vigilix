import React, { useRef } from "react";
import { RefreshCw, Upload, Menu } from "lucide-react";
import { uploadLogs } from "../api";

export default function Topbar({ activeTab, onRefresh, onTelemetryUpdated, totalEvents, onMobileMenuToggle, onShowToast }) {
  const fileInputRef = useRef(null);

  const titles = {
    overview: "SOC Command Center",
    investigations: "Incident War Room & LangGraph Triage",
    copilot: "Vigilix Real-Time AI Copilot",
    explorer: "Telemetry Event Explorer",
    knowledge: "Security Knowledge Base & MITRE ATT&CK",
    connectors: "AWS Live Connectors & Ingestion",
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const res = await uploadLogs(file);
      onTelemetryUpdated?.();
      onShowToast?.(`Uploaded "${file.name}": ${res.new_events || res.parsed_events} new events saved.`, "success");
    } catch (err) {
      onShowToast?.(`Upload failed: ${err.message}`, "error");
    }
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  return (
    <header className="topbar">
      {/* Left: Mobile menu + Title */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", minWidth: 0 }}>
        <button className="mobile-menu-btn" onClick={onMobileMenuToggle} aria-label="Toggle navigation">
          <Menu size={20} />
        </button>
        <h2 style={{
          fontSize: "1.1rem",
          fontWeight: 700,
          color: "#fff",
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
          margin: 0,
        }}>
          {titles[activeTab] || "Security Operations"}
        </h2>
      </div>

      {/* Right: Actions */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px", flexShrink: 0 }}>
        {/* Event Count Chip — hide on small screens */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          padding: "6px 12px",
          background: "rgba(10, 18, 32, 0.7)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "8px",
          fontSize: "0.78rem",
          color: "var(--text-muted)",
        }}>
          <span className="pulse-indicator" style={{ width: "6px", height: "6px" }} />
          <span className="topbar-hide-mobile">Telemetry:</span>
          <strong style={{ color: "#fff", fontFamily: "var(--font-mono)" }}>
            {(totalEvents || 0).toLocaleString()}
          </strong>
        </div>

        {/* Upload */}
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileUpload}
          style={{ display: "none" }}
          accept=".json,.jsonl,.csv,.txt,.gz,.log"
        />
        <button
          onClick={() => fileInputRef.current?.click()}
          className="btn btn-secondary"
          style={{ padding: "7px 12px", fontSize: "0.82rem" }}
          title="Upload raw CloudTrail JSON, CSV, or gzip files"
        >
          <Upload size={14} />
          <span className="topbar-hide-mobile">Upload</span>
        </button>

        {/* Refresh */}
        <button
          onClick={onRefresh}
          className="btn btn-secondary"
          style={{ padding: "7px 12px", fontSize: "0.82rem" }}
          title="Refresh workspace telemetry"
        >
          <RefreshCw size={14} />
          <span className="topbar-hide-mobile">Refresh</span>
        </button>
      </div>
    </header>
  );
}
