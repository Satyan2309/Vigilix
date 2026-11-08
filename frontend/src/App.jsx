import React, { useState, useEffect, useCallback } from "react";
import Sidebar from "./components/Sidebar";
import Topbar from "./components/Topbar";
import OverviewView from "./components/OverviewView";
import EventExplorerView from "./components/EventExplorerView";
import InvestigationsView from "./components/InvestigationsView";
import ChatCopilotView from "./components/ChatCopilotView";
import KnowledgeBaseView from "./components/KnowledgeBaseView";
import AwsConnectorsView from "./components/AwsConnectorsView";
import AuthModal from "./components/AuthModal";
import LandingPage from "./components/LandingPage";
import {
  LayoutDashboard,
  Flame,
  Bot,
  Search,
  BookOpen,
  Cloud,
  CheckCircle2,
  AlertTriangle,
  Info,
  X,
  Command,
  Play,
  Database
} from "lucide-react";
import {
  getMe,
  getEvents,
  getIncidents,
  getHealth,
  getKnowledgeStatus,
  setAuthToken,
  getAuthToken,
  loadDemo,
  importPublicDataset
} from "./api";

export default function App() {
  const [activeTab, setActiveTab] = useState("overview");
  const [user, setUser] = useState(null);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [copilotPrompt, setCopilotPrompt] = useState("");
  const [toast, setToast] = useState(null);
  const [isCommandOpen, setIsCommandOpen] = useState(false);

  // SOC Telemetry & Health States
  const [events, setEvents] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [health, setHealth] = useState(null);
  const [knowledge, setKnowledge] = useState(null);
  const [loadingData, setLoadingData] = useState(false);

  const toastTimerRef = React.useRef(null);
  const showToast = useCallback((message, type = "success") => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    setToast({ message, type });
    toastTimerRef.current = setTimeout(() => {
      setToast(null);
    }, 4500);
  }, []);

  // Check if user has a stored token / session
  const checkAuth = useCallback(async () => {
    const token = getAuthToken();
    if (!token) {
      setAuthChecked(true);
      return;
    }
    try {
      const me = await getMe();
      setUser(me);
    } catch {
      setUser(null);
      setAuthToken("");
    } finally {
      setAuthChecked(true);
    }
  }, []);

  // Fetch all SOC telemetry data
  const refreshSocData = useCallback(async () => {
    setLoadingData(true);
    try {
      const [eventsRes, incidentsRes, healthRes, knowledgeRes] =
        await Promise.allSettled([
          getEvents({ limit: 500 }),
          getIncidents(50),
          getHealth(),
          getKnowledgeStatus(),
        ]);

      if (eventsRes.status === "fulfilled")
        setEvents(eventsRes.value.events || []);
      if (incidentsRes.status === "fulfilled")
        setIncidents(incidentsRes.value.incidents || []);
      if (healthRes.status === "fulfilled")
        setHealth(healthRes.value);
      if (knowledgeRes.status === "fulfilled")
        setKnowledge(knowledgeRes.value);
    } catch (err) {
      console.error("Error refreshing SOC data:", err);
    } finally {
      setLoadingData(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  // Load SOC data when user is authenticated
  useEffect(() => {
    if (user) refreshSocData();
  }, [user, refreshSocData]);

  // Global Ctrl+K / Cmd+K Command Palette listener
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (user) setIsCommandOpen((prev) => !prev);
      }
      if (e.key === "Escape") {
        setIsCommandOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [user]);

  // Listen for auth expiration events
  useEffect(() => {
    const handleExpired = () => {
      setUser(null);
      setIsAuthOpen(true);
    };
    window.addEventListener("auth_expired", handleExpired);
    return () => window.removeEventListener("auth_expired", handleExpired);
  }, []);

  const handleLogout = () => {
    setAuthToken("");
    setUser(null);
    showToast("Signed out from SOC workspace.", "info");
  };

  const handleAuthSuccess = (authenticatedUser) => {
    setUser(authenticatedUser);
    setIsAuthOpen(false);
    showToast(`Welcome Operator, ${authenticatedUser.full_name || authenticatedUser.email}!`, "success");
  };

  const handleGetStarted = () => {
    setIsAuthOpen(true);
  };

  const handleSetActiveTab = (tab) => {
    setActiveTab(tab);
    setSidebarOpen(false);
  };

  const handleAskCopilot = (promptText) => {
    setCopilotPrompt(promptText);
    setActiveTab("copilot");
  };

  const handleQuickLoad = async (scenario) => {
    setIsCommandOpen(false);
    try {
      if (scenario === "real_dataset") {
        showToast("Ingesting real CloudTrail research dataset...", "info");
        const res = await importPublicDataset(3000);
        showToast(`Imported ${res.new_events || res.parsed_events} real CloudTrail events!`, "success");
      } else {
        const res = await loadDemo(scenario);
        showToast(`Loaded ${res.new_events} events (${scenario})`, "success");
      }
      refreshSocData();
    } catch (err) {
      showToast(`Failed to load scenario: ${err.message}`, "error");
    }
  };

  // ── Show loading state while checking stored token ──────────
  if (!authChecked) {
    return (
      <div style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        flexDirection: "column",
        gap: "16px",
      }}>
        <div className="pulse-indicator" style={{ width: "14px", height: "14px" }} />
        <span style={{ color: "var(--text-dim)", fontSize: "0.9rem" }}>
          Initializing Vigilix AI...
        </span>
      </div>
    );
  }

  // ── Show Landing Page when not authenticated ────────────────
  if (!user) {
    return (
      <>
        <LandingPage onGetStarted={handleGetStarted} />
        <AuthModal
          isOpen={isAuthOpen}
          onClose={() => setIsAuthOpen(false)}
          onAuthSuccess={handleAuthSuccess}
        />
      </>
    );
  }

  // ── Authenticated SOC Dashboard ─────────────────────────────
  return (
    <div className="soc-layout">
      {/* Mobile sidebar overlay */}
      <div
        className={`sidebar-overlay ${sidebarOpen ? "visible" : ""}`}
        onClick={() => setSidebarOpen(false)}
      />

      {/* Fixed Cyber Sidebar */}
      <div className={sidebarOpen ? "sidebar open" : "sidebar"}>
        <Sidebar
          activeTab={activeTab}
          setActiveTab={handleSetActiveTab}
          user={user}
          onSignOut={handleLogout}
          onTelemetryUpdated={refreshSocData}
          health={health}
        />
      </div>

      {/* Main Command Workspace */}
      <div className="main-content">
        <Topbar
          activeTab={activeTab}
          totalEvents={events.length}
          onRefresh={refreshSocData}
          onTelemetryUpdated={refreshSocData}
          onMobileMenuToggle={() => setSidebarOpen((v) => !v)}
          onShowToast={showToast}
        />

        <div className="content-container">
          {activeTab === "overview" && (
            <OverviewView
              events={events}
              incidents={incidents}
              knowledge={knowledge}
              health={health}
              onTelemetryUpdated={refreshSocData}
              onNavigateToTab={handleSetActiveTab}
              onShowToast={showToast}
            />
          )}

          {activeTab === "explorer" && (
            <EventExplorerView
              initialEvents={events}
              onRefresh={refreshSocData}
              onAskCopilot={handleAskCopilot}
              onShowToast={showToast}
            />
          )}

          {activeTab === "investigations" && (
            <InvestigationsView
              incidents={incidents}
              onTelemetryUpdated={refreshSocData}
              onAskCopilot={handleAskCopilot}
              onShowToast={showToast}
            />
          )}

          {activeTab === "copilot" && (
            <ChatCopilotView
              health={health}
              preloadedPrompt={copilotPrompt}
            />
          )}

          {activeTab === "knowledge" && (
            <KnowledgeBaseView
              knowledge={knowledge}
              onRefreshKnowledge={refreshSocData}
            />
          )}

          {activeTab === "connectors" && (
            <AwsConnectorsView
              onSyncComplete={refreshSocData}
            />
          )}
        </div>
      </div>

      {/* Global Cyber Toast Alert */}
      {toast && (
        <div style={{
          position: "fixed",
          bottom: "24px",
          right: "24px",
          zIndex: 10000,
          background: "rgba(10, 18, 32, 0.95)",
          border: `1px solid ${toast.type === "error" ? "var(--accent-danger)" : toast.type === "info" ? "var(--accent-blue)" : "var(--accent-cyan)"}`,
          borderRadius: "12px",
          padding: "12px 18px",
          boxShadow: "0 10px 30px rgba(0, 0, 0, 0.7)",
          display: "flex",
          alignItems: "center",
          gap: "10px",
          backdropFilter: "blur(12px)",
          maxWidth: "420px",
        }}>
          {toast.type === "error" ? (
            <AlertTriangle size={18} color="var(--accent-danger)" />
          ) : toast.type === "info" ? (
            <Info size={18} color="var(--accent-blue)" />
          ) : (
            <CheckCircle2 size={18} color="var(--accent-cyan)" />
          )}
          <span style={{ fontSize: "0.85rem", color: "#fff", flex: 1 }}>{toast.message}</span>
          <button onClick={() => setToast(null)} style={{ background: "transparent", border: "none", color: "var(--text-dim)", cursor: "pointer" }}>
            <X size={14} />
          </button>
        </div>
      )}

      {/* Cyber Command Palette (Ctrl+K) */}
      {isCommandOpen && (
        <div
          onClick={() => setIsCommandOpen(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(4, 7, 14, 0.75)",
            backdropFilter: "blur(10px)",
            zIndex: 10001,
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "center",
            paddingTop: "15vh",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              width: "100%",
              maxWidth: "520px",
              background: "linear-gradient(145deg, rgba(16, 27, 48, 0.98), rgba(9, 15, 27, 0.98))",
              border: "1px solid rgba(0, 245, 212, 0.4)",
              borderRadius: "16px",
              padding: "16px",
              boxShadow: "0 20px 60px rgba(0,0,0,0.8), 0 0 30px rgba(0, 245, 212, 0.15)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", paddingBottom: "12px", borderBottom: "1px solid var(--border-subtle)" }}>
              <Command size={18} color="var(--accent-cyan)" />
              <span style={{ fontWeight: 700, fontSize: "0.95rem", color: "#fff" }}>Command Palette</span>
              <span style={{ marginLeft: "auto", fontSize: "0.72rem", color: "var(--text-dim)", background: "rgba(255,255,255,0.06)", padding: "2px 8px", borderRadius: "4px" }}>
                ESC to close
              </span>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "12px" }}>
              <div style={{ fontSize: "0.68rem", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em", padding: "4px 8px" }}>
                NAVIGATION JUMP
              </div>
              {[
                { id: "overview", label: "Command Center (Dashboard)", icon: LayoutDashboard },
                { id: "investigations", label: "Incident War Room & Triage", icon: Flame },
                { id: "copilot", label: "Defensive AI Copilot", icon: Bot },
                { id: "explorer", label: "Telemetry Event Explorer", icon: Search },
                { id: "knowledge", label: "Threat Runbooks & MITRE", icon: BookOpen },
                { id: "connectors", label: "AWS Telemetry Ingestion", icon: Cloud },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => { setActiveTab(item.id); setIsCommandOpen(false); }}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      padding: "8px 12px",
                      borderRadius: "8px",
                      background: activeTab === item.id ? "rgba(0, 245, 212, 0.12)" : "transparent",
                      border: "none",
                      color: activeTab === item.id ? "var(--accent-cyan)" : "var(--text-muted)",
                      cursor: "pointer",
                      fontSize: "0.85rem",
                      textAlign: "left",
                    }}
                  >
                    <Icon size={16} />
                    <span>{item.label}</span>
                  </button>
                );
              })}

              <div style={{ fontSize: "0.68rem", color: "var(--text-dim)", textTransform: "uppercase", letterSpacing: "0.08em", padding: "8px 8px 4px", marginTop: "6px" }}>
                TELEMETRY DATASETS
              </div>
              {[
                { label: "Load Real CloudTrail Research Data (3,000 events)", scenario: "real_dataset", color: "var(--accent-cyan)", isReal: true },
                { label: "Load Suspicious Attack Sequence", scenario: "suspicious", color: "var(--accent-danger)" },
                { label: "Load Mixed Telemetry", scenario: "mixed", color: "var(--accent-warn)" },
                { label: "Load Benign Administrative Activity", scenario: "benign", color: "var(--accent-success)" },
              ].map((s, i) => (
                <button
                  key={i}
                  onClick={() => handleQuickLoad(s.scenario)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "8px 12px",
                    borderRadius: "8px",
                    background: s.isReal ? "rgba(0, 245, 212, 0.08)" : "transparent",
                    border: s.isReal ? "1px solid rgba(0, 245, 212, 0.25)" : "none",
                    color: s.isReal ? "#00f5d4" : "var(--text-main)",
                    cursor: "pointer",
                    fontSize: "0.82rem",
                    textAlign: "left",
                  }}
                >
                  {s.isReal ? <Database size={14} color={s.color} /> : <Play size={14} color={s.color} />}
                  <span>{s.label}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Re-authentication Modal (for expired sessions) */}
      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onAuthSuccess={handleAuthSuccess}
      />
    </div>
  );
}
