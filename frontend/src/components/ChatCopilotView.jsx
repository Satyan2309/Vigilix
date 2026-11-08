import React, { useState, useRef, useEffect, useCallback } from "react";
import { Bot, User, Send, Trash2, Sparkles, BookOpen, AlertCircle, Shield, Copy, Check } from "lucide-react";
import { streamChat } from "../api";

// Simple inline markdown renderer (no external deps)
function renderMarkdown(text) {
  if (!text) return "";
  let html = text
    // Escape HTML
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    // Code blocks
    .replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) =>
      `<pre><code class="lang-${lang}">${code.trim()}</code></pre>`)
    // Inline code
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    // Bold
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    // Italic
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    // Headers
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    // Horizontal rule
    .replace(/^---$/gm, "<hr>")
    // Blockquote
    .replace(/^> (.+)$/gm, "<blockquote>$1</blockquote>")
    // Unordered lists
    .replace(/^[\-\*] (.+)$/gm, "<li>$1</li>")
    .replace(/(<li>.*<\/li>)/gs, "<ul>$1</ul>")
    // Ordered lists
    .replace(/^\d+\. (.+)$/gm, "<li>$1</li>")
    // Paragraphs — convert double newlines
    .replace(/\n\n/g, "</p><p>")
    // Single newlines
    .replace(/\n/g, "<br>");

  // Wrap in paragraph if no block elements
  if (!html.match(/^<(h[123]|ul|ol|pre|blockquote|hr)/)) {
    html = `<p>${html}</p>`;
  }
  return html;
}

function ChatMessage({ msg, isStreaming }) {
  const isUser = msg.role === "user";
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(msg.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      style={{
        display: "flex",
        gap: "12px",
        alignItems: "flex-start",
        justifyContent: isUser ? "flex-end" : "flex-start",
        animation: "fadeInUp 0.25s ease-out",
      }}
    >
      {!isUser && (
        <div style={{
          width: "32px", height: "32px", borderRadius: "8px",
          background: isStreaming ? "rgba(0, 245, 212, 0.25)" : "rgba(0, 245, 212, 0.15)",
          border: `1px solid ${isStreaming ? "var(--accent-cyan)" : "rgba(0, 245, 212, 0.3)"}`,
          display: "flex", alignItems: "center", justifyContent: "center",
          color: "#00f5d4", flexShrink: 0,
          boxShadow: isStreaming ? "0 0 12px rgba(0, 245, 212, 0.3)" : "none",
          transition: "all 0.3s ease",
        }}>
          <Bot size={16} />
        </div>
      )}

      <div style={{ maxWidth: "78%", position: "relative" }}>
        <div style={{
          padding: "14px 18px",
          borderRadius: isUser ? "14px 14px 4px 14px" : "4px 14px 14px 14px",
          background: isUser
            ? "linear-gradient(135deg, rgba(0, 245, 212, 0.18), rgba(56, 189, 248, 0.12))"
            : "rgba(10, 18, 32, 0.78)",
          border: "1px solid",
          borderColor: isUser ? "rgba(0, 245, 212, 0.4)" : "var(--border-subtle)",
          color: isUser ? "#fff" : "var(--text-main)",
          fontSize: "0.9rem",
          lineHeight: 1.65,
          boxShadow: isUser ? "0 4px 18px rgba(0, 245, 212, 0.1)" : "none",
        }}>
          {isUser ? (
            <span style={{ whiteSpace: "pre-wrap" }}>{msg.content}</span>
          ) : (
            <div
              className="chat-markdown"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(msg.content) }}
            />
          )}
        </div>
        {!isUser && !isStreaming && msg.content && (
          <button
            onClick={handleCopy}
            title="Copy message"
            style={{
              position: "absolute", top: "6px", right: "-32px",
              background: "transparent", border: "none", cursor: "pointer",
              color: copied ? "var(--accent-cyan)" : "var(--text-dim)",
              padding: "4px", opacity: 0.7,
            }}
          >
            {copied ? <Check size={12} /> : <Copy size={12} />}
          </button>
        )}
      </div>

      {isUser && (
        <div style={{
          width: "32px", height: "32px", borderRadius: "8px",
          background: "rgba(56, 189, 248, 0.15)",
          border: "1px solid rgba(56, 189, 248, 0.3)",
          display: "flex", alignItems: "center", justifyContent: "center",
          color: "#38bdf8", flexShrink: 0,
        }}>
          <User size={16} />
        </div>
      )}
    </div>
  );
}

export default function ChatCopilotView({ health, preloadedPrompt }) {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      content: "👋 Greetings Operator. I am **Vigilix AI Copilot**, your continuous intelligent security monitoring & defensive triage assistant.\n\nAsk me about observed signals in your active workspace, exact event counts, AWS threat runbooks, or platform operations.",
    },
  ]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [streamingText, setStreamingText] = useState("");
  const [sessionId] = useState(() => "session_" + Math.random().toString(36).slice(2, 10));
  const messagesEndRef = useRef(null);
  const handledPromptRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (preloadedPrompt && preloadedPrompt !== handledPromptRef.current && !streaming) {
      handledPromptRef.current = preloadedPrompt;
      handleSend(preloadedPrompt);
    }
  }, [preloadedPrompt]);

  const suggestedPrompts = [
    "Explain the highest-risk signals in my workspace",
    "How many failed ConsoleLogin events occurred?",
    "What should I verify after suspicious IAM changes?",
    "Are there any root user or S3 public exposure events?",
    "How do I connect live AWS CloudTrail and S3?",
    "What are the top source IP addresses and principals?",
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamingText]);

  const handleSend = useCallback(async (textToSend) => {
    const q = textToSend || input;
    if (!q.trim() || streaming) return;

    setInput("");
    inputRef.current?.focus();
    const newHistory = [...messages, { role: "user", content: q }];
    setMessages(newHistory);
    setStreaming(true);
    setStreamingText("");

    let accumulated = "";

    await streamChat(
      q,
      sessionId,
      newHistory.slice(-8).map((m) => ({ role: m.role, content: m.content })),
      (token) => {
        accumulated += token;
        setStreamingText(accumulated);
      },
      () => {
        setMessages((prev) => [...prev, { role: "assistant", content: accumulated || "No response received." }]);
        setStreamingText("");
        setStreaming(false);
      },
      (error) => {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: `⚠️ **Error**: ${error}` },
        ]);
        setStreamingText("");
        setStreaming(false);
      }
    );
  }, [input, messages, streaming, sessionId]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "calc(100vh - 120px)", gap: "16px" }}>
      {/* Header & Mode Bar */}
      <div className="glass-panel" style={{ padding: "16px 22px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            width: "36px", height: "36px", borderRadius: "10px",
            background: "rgba(0, 245, 212, 0.15)", border: "1px solid var(--accent-cyan)",
            display: "flex", alignItems: "center", justifyContent: "center", color: "var(--accent-cyan)",
          }}>
            <Bot size={20} />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: "1rem", color: "#fff" }}>
              Vigilix AI Defensive Terminal
            </div>
            <div style={{ fontSize: "0.74rem", color: "var(--text-dim)" }}>
              Engine: <span style={{ color: "var(--accent-cyan)" }}>{health?.llm_mode?.toUpperCase() || "READY"}</span>
              {" · "}Evidence Grounded · RAG-Enabled
              {streaming && <span style={{ color: "var(--accent-warn)", marginLeft: "8px" }}>● Streaming...</span>}
            </div>
          </div>
        </div>

        <button
          onClick={() => setMessages([messages[0]])}
          className="btn btn-secondary"
          style={{ padding: "6px 12px", fontSize: "0.78rem" }}
          title="Clear visible conversation"
          disabled={messages.length <= 1}
        >
          <Trash2 size={13} />
          <span>Clear Chat</span>
        </button>
      </div>

      {/* Suggested Prompts Bar */}
      <div style={{ display: "flex", gap: "8px", overflowX: "auto", paddingBottom: "4px", flexShrink: 0 }}>
        {suggestedPrompts.map((p, idx) => (
          <button
            key={idx}
            onClick={() => handleSend(p)}
            disabled={streaming}
            className="btn btn-secondary"
            style={{
              padding: "7px 12px",
              fontSize: "0.76rem",
              fontWeight: 500,
              whiteSpace: "nowrap",
              flexShrink: 0,
            }}
          >
            {p}
          </button>
        ))}
      </div>

      {/* Message History Container */}
      <div className="glass-panel" style={{ flex: 1, padding: "20px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "16px" }}>
        {messages.map((msg, index) => (
          <ChatMessage key={index} msg={msg} isStreaming={false} />
        ))}

        {/* Streaming Message Box */}
        {streaming && (
          <ChatMessage
            msg={{ role: "assistant", content: streamingText || "" }}
            isStreaming={true}
          />
        )}
        {streaming && !streamingText && (
          <div style={{ display: "flex", gap: "12px", alignItems: "flex-start" }}>
            <div style={{
              width: "32px", height: "32px", borderRadius: "8px",
              background: "rgba(0, 245, 212, 0.25)", border: "1px solid var(--accent-cyan)",
              display: "flex", alignItems: "center", justifyContent: "center",
              color: "#00f5d4", flexShrink: 0, boxShadow: "0 0 12px rgba(0, 245, 212, 0.3)",
            }}>
              <Bot size={16} />
            </div>
            <div style={{
              padding: "14px 18px", borderRadius: "4px 14px 14px 14px",
              background: "rgba(10, 18, 32, 0.78)", border: "1px solid rgba(0, 245, 212, 0.3)",
              display: "flex", alignItems: "center", gap: "10px",
            }}>
              <span style={{ color: "var(--text-dim)", fontSize: "0.88rem" }}>Analyzing telemetry and synthesizing evidence</span>
              <span style={{ display: "flex", gap: "3px" }}>
                {[0, 1, 2].map(i => (
                  <span key={i} style={{
                    width: "6px", height: "6px", borderRadius: "50%",
                    background: "var(--accent-cyan)",
                    animation: `pulseLive ${0.6 + i * 0.2}s infinite ease-in-out`,
                    animationDelay: `${i * 0.15}s`,
                  }} />
                ))}
              </span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Bar */}
      <form
        onSubmit={(e) => { e.preventDefault(); handleSend(); }}
        style={{
          display: "flex",
          gap: "10px",
          background: "rgba(11, 19, 34, 0.9)",
          padding: "8px",
          borderRadius: "14px",
          border: `1px solid ${streaming ? "rgba(0, 245, 212, 0.3)" : "var(--border-subtle)"}`,
          backdropFilter: "blur(12px)",
          transition: "border-color 0.2s ease",
        }}
      >
        <input
          ref={inputRef}
          type="text"
          className="input"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask a cloud security or platform question… (e.g. 'Show timeline of failed logins')"
          disabled={streaming}
          style={{ border: "none", background: "transparent", fontSize: "0.92rem" }}
        />
        <button
          type="submit"
          className="btn btn-primary"
          disabled={streaming || !input.trim()}
          style={{ padding: "0 20px", height: "42px", flexShrink: 0 }}
        >
          <Send size={16} />
          <span>{streaming ? "Streaming..." : "Ask"}</span>
        </button>
      </form>
    </div>
  );
}
