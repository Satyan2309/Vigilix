const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

export const getAuthToken = () => localStorage.getItem("cs_token") || "";
export const setAuthToken = (token) => {
  if (token) localStorage.setItem("cs_token", token);
  else localStorage.removeItem("cs_token");
};

const authHeaders = () => {
  const token = getAuthToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
};

export async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    ...authHeaders(),
    ...(options.headers || {}),
  };

  if (!(options.body instanceof FormData) && !headers["Content-Type"] && options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(url, { ...options, headers });
  
  if (response.status === 401) {
    setAuthToken("");
    window.dispatchEvent(new Event("auth_expired"));
    throw new Error("Session expired. Please sign in again.");
  }

  if (!response.ok) {
    let errorDetail = "Request failed";
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch {
      errorDetail = await response.text();
    }
    throw new Error(errorDetail || `HTTP error ${response.status}`);
  }

  return response.json();
}

// Authentication
export async function login(email, password) {
  const data = await apiRequest("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  if (data.access_token) {
    setAuthToken(data.access_token);
  }
  return data;
}

export async function register(email, password, fullName) {
  return apiRequest("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password, full_name: fullName }),
  });
}

export async function getMe() {
  return apiRequest("/api/v1/auth/me");
}

export async function getHealth() {
  return apiRequest("/api/v1/health");
}

// Telemetry & Ingestion
export async function getEvents(params = {}) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "" && v !== "All") q.append(k, v);
  });
  return apiRequest(`/api/v1/events?${q.toString()}`);
}

export async function loadDemo(scenario) {
  return apiRequest("/api/v1/demo/load", {
    method: "POST",
    body: JSON.stringify({ scenario }),
  });
}

export async function importPublicDataset(maxEvents = 26550) {
  return apiRequest(`/api/v1/datasets/public-cloudtrail/import?max_events=${maxEvents}`, {
    method: "POST",
  });
}

export async function uploadLogs(file) {
  const formData = new FormData();
  formData.append("file", file);
  return apiRequest("/api/v1/ingest/upload", {
    method: "POST",
    body: formData,
  });
}

export async function clearEvents() {
  return apiRequest("/api/v1/events/clear", { method: "DELETE" });
}

export async function getTelemetryStats() {
  return apiRequest("/api/v1/telemetry/stats");
}

// Investigations
export async function getIncidents(limit = 50) {
  return apiRequest(`/api/v1/incidents?limit=${limit}`);
}

export async function runInvestigation(limit = 200, title = "Cloud Security Incident Triage") {
  return apiRequest("/api/v1/incidents/investigate", {
    method: "POST",
    body: JSON.stringify({ limit, title }),
  });
}

export async function updateIncidentStatus(incidentId, status) {
  return apiRequest(`/api/v1/incidents/${encodeURIComponent(incidentId)}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

export async function toggleIncidentAction(incidentId, actionIdx, completed) {
  return apiRequest(`/api/v1/incidents/${encodeURIComponent(incidentId)}/actions/${actionIdx}`, {
    method: "PATCH",
    body: JSON.stringify({ completed }),
  });
}

export async function deleteIncident(incidentId) {
  return apiRequest(`/api/v1/incidents/${encodeURIComponent(incidentId)}`, {
    method: "DELETE",
  });
}

// Knowledge Base
export async function getKnowledgeStatus() {
  return apiRequest("/api/v1/knowledge");
}

export async function indexKnowledge(forceReindex = false) {
  return apiRequest("/api/v1/knowledge/index", {
    method: "POST",
    body: JSON.stringify({ force_reindex: forceReindex }),
  });
}

export async function searchKnowledge(query, k = 5) {
  return apiRequest(`/api/v1/knowledge/search?q=${encodeURIComponent(query)}&k=${k}`);
}

// AWS Connectors
export async function getAwsStatus(region = "ap-south-1", profile = "") {
  const q = new URLSearchParams({ region });
  if (profile) q.append("profile", profile);
  return apiRequest(`/api/v1/aws/status?${q.toString()}`);
}

export async function syncCloudTrail(region = "ap-south-1", hours = 24, limit = 200, profile = "") {
  const q = new URLSearchParams({ region, hours: hours.toString(), limit: limit.toString() });
  if (profile) q.append("profile", profile);
  return apiRequest(`/api/v1/aws/cloudtrail/sync?${q.toString()}`, { method: "POST" });
}

export async function syncCloudTrailS3(bucket, prefix = "", region = "ap-south-1", hours = 24, maxObjects = 20, profile = "") {
  const q = new URLSearchParams({ bucket, prefix, region, hours: hours.toString(), max_objects: maxObjects.toString() });
  if (profile) q.append("profile", profile);
  return apiRequest(`/api/v1/aws/cloudtrail/s3-sync?${q.toString()}`, { method: "POST" });
}

export async function syncGuardDuty(region = "ap-south-1", limit = 50, profile = "") {
  const q = new URLSearchParams({ region, limit: limit.toString() });
  if (profile) q.append("profile", profile);
  return apiRequest(`/api/v1/aws/guardduty/sync?${q.toString()}`, { method: "POST" });
}

export async function syncSecurityHub(region = "ap-south-1", limit = 100, profile = "") {
  const q = new URLSearchParams({ region, limit: limit.toString() });
  if (profile) q.append("profile", profile);
  return apiRequest(`/api/v1/aws/securityhub/sync?${q.toString()}`, { method: "POST" });
}

// Real-Time Chat Streaming Reader
export async function streamChat(question, sessionId, history = [], onToken, onDone, onError) {
  const token = getAuthToken();
  const response = await fetch(`${API_BASE}/api/v1/chat/stream`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      question,
      session_id: sessionId,
      history,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    onError?.(errorText || "Stream failed");
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  let doneHandled = false;

  const triggerDone = () => {
    if (!doneHandled) {
      doneHandled = true;
      onDone?.();
    }
  };

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (line.startsWith("data: ")) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.error) {
              onError?.(data.error);
              return;
            }
            if (data.token) {
              onToken?.(data.token);
            }
            if (data.done) {
              triggerDone();
            }
          } catch {
            // ignore parse glitch
          }
        }
      }
    }
    triggerDone();
  } catch (err) {
    if (!doneHandled) {
      onError?.(err.message);
    }
  }
}
