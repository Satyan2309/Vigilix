import React, { useState } from "react";
import { BookOpen, Search, RefreshCw, ExternalLink, Database, Sparkles, CheckCircle2 } from "lucide-react";
import { indexKnowledge, searchKnowledge } from "../api";

export default function KnowledgeBaseView({ knowledge, onRefreshKnowledge }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [indexing, setIndexing] = useState(false);
  const [statusMsg, setStatusMsg] = useState("");

  const handleSearch = async (e) => {
    e?.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    setStatusMsg("");
    try {
      const data = await searchKnowledge(query, 6);
      setResults(data.results || []);
    } catch (err) {
      setStatusMsg(`Search failed: ${err.message}`);
    } finally {
      setSearching(false);
    }
  };

  const handleIndex = async (force) => {
    setIndexing(true);
    setStatusMsg("");
    try {
      const res = await indexKnowledge(force);
      setStatusMsg(`Success: ${res.status} (${res.chunks_indexed} chunks)`);
      onRefreshKnowledge?.();
    } catch (err) {
      setStatusMsg(`Indexing failed: ${err.message}`);
    } finally {
      setIndexing(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {/* Knowledge Info Header */}
      <div className="glass-panel" style={{ padding: "24px 28px" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "16px", marginBottom: "18px" }}>
          <div>
            <h3 style={{ fontSize: "1.2rem", display: "flex", alignItems: "center", gap: "10px" }}>
              <BookOpen size={20} style={{ color: "var(--accent-blue)" }} />
              <span>Security Knowledge Base & MITRE ATT&CK RAG</span>
            </h3>
            <p style={{ fontSize: "0.82rem", color: "var(--text-dim)" }}>
              High-confidence incident response runbooks and AWS CIS Foundations benchmarks stored in ChromaDB.
            </p>
          </div>

          <div style={{ display: "flex", gap: "10px" }}>
            <button
              onClick={() => handleIndex(false)}
              disabled={indexing}
              className="btn btn-secondary"
              style={{ fontSize: "0.8rem", padding: "8px 14px" }}
            >
              <RefreshCw size={14} className={indexing ? "pulse-indicator" : ""} />
              <span>Index New Runbooks</span>
            </button>
            <button
              onClick={() => handleIndex(true)}
              disabled={indexing}
              className="btn btn-secondary"
              style={{ fontSize: "0.8rem", padding: "8px 14px", color: "var(--accent-warn)" }}
            >
              <Database size={14} />
              <span>Rebuild Vector Store</span>
            </button>
          </div>
        </div>

        {/* Status Metrics */}
        <div style={{ display: "flex", gap: "24px", flexWrap: "wrap", padding: "14px 18px", background: "rgba(8, 14, 25, 0.65)", borderRadius: "10px", border: "1px solid var(--border-subtle)" }}>
          <div>
            <div style={{ fontSize: "0.7rem", color: "var(--text-dim)", textTransform: "uppercase" }}>CHROMA CHUNKS</div>
            <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "#fff", fontFamily: "var(--font-mono)" }}>
              {knowledge?.indexed_chunks || 0}
            </div>
          </div>
          <div>
            <div style={{ fontSize: "0.7rem", color: "var(--text-dim)", textTransform: "uppercase" }}>EMBEDDINGS ENGINE</div>
            <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "var(--accent-cyan)", fontFamily: "var(--font-mono)" }}>
              {knowledge?.embedding_mode?.toUpperCase() || "HASH"}
            </div>
          </div>
          <div>
            <div style={{ fontSize: "0.7rem", color: "var(--text-dim)", textTransform: "uppercase" }}>COLLECTION NAME</div>
            <div style={{ fontSize: "1.2rem", fontWeight: 700, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              {knowledge?.collection_name || "vigilix_hash"}
            </div>
          </div>
        </div>

        {statusMsg && (
          <div style={{ marginTop: "12px", fontSize: "0.82rem", color: "var(--accent-cyan)" }}>
            {statusMsg}
          </div>
        )}
      </div>

      {/* Runbook Search Box */}
      <div className="glass-panel" style={{ padding: "20px 24px" }}>
        <h4 style={{ fontSize: "0.95rem", marginBottom: "12px" }}>Search Threat Guidance Runbooks</h4>
        <form onSubmit={handleSearch} style={{ display: "flex", gap: "10px" }}>
          <input
            type="text"
            className="input"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="e.g. StopLogging tampering, IAM privilege escalation, S3 bucket policy exposure..."
          />
          <button type="submit" disabled={searching || !query.trim()} className="btn btn-primary" style={{ padding: "0 22px" }}>
            <Search size={15} />
            <span>{searching ? "Searching..." : "Search"}</span>
          </button>
        </form>

        {/* Search Results */}
        {results && results.length > 0 && (
          <div style={{ marginTop: "20px", display: "flex", flexDirection: "column", gap: "14px" }}>
            <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--text-dim)", textTransform: "uppercase" }}>
              RETRIEVED RUNBOOK PASSAGES ({results.length})
            </div>
            {results.map((doc, idx) => (
              <div
                key={idx}
                style={{
                  background: "rgba(10, 18, 32, 0.75)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "12px",
                  padding: "18px 20px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "8px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <span className="badge badge-cyan" style={{ fontSize: "0.68rem" }}>
                      K{idx + 1}
                    </span>
                    <strong style={{ fontSize: "1rem", color: "#fff" }}>
                      {doc.title || doc.source}
                    </strong>
                    <span style={{ fontSize: "0.75rem", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>
                      `{doc.source}`
                    </span>
                  </div>

                  {doc.source_url && (
                    <a
                      href={doc.source_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        fontSize: "0.78rem",
                        color: "var(--accent-blue)",
                        textDecoration: "none",
                      }}
                    >
                      <span>AWS Documentation</span>
                      <ExternalLink size={12} />
                    </a>
                  )}
                </div>

                <p style={{ fontSize: "0.88rem", color: "var(--text-main)", lineHeight: 1.6, whiteSpace: "pre-line" }}>
                  {doc.content}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
