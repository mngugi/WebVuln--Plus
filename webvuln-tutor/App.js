import { useState, useRef, useEffect } from "react";

const VULNERABILITIES = [
  { id: 1, category: "Injection", name: "SQL Injection", severity: "Critical", cwe: "CWE-89" },
  { id: 2, category: "Injection", name: "Command Injection", severity: "Critical", cwe: "CWE-78" },
  { id: 3, category: "Injection", name: "LDAP Injection", severity: "High", cwe: "CWE-90" },
  { id: 4, category: "Injection", name: "XPath Injection", severity: "High", cwe: "CWE-643" },
  { id: 5, category: "Injection", name: "NoSQL Injection", severity: "High", cwe: "CWE-943" },
  { id: 6, category: "XSS", name: "Reflected XSS", severity: "High", cwe: "CWE-79" },
  { id: 7, category: "XSS", name: "Stored XSS", severity: "Critical", cwe: "CWE-79" },
  { id: 8, category: "XSS", name: "DOM-based XSS", severity: "High", cwe: "CWE-79" },
  { id: 9, category: "Auth", name: "Broken Authentication", severity: "Critical", cwe: "CWE-287" },
  { id: 10, category: "Auth", name: "Session Fixation", severity: "High", cwe: "CWE-384" },
  { id: 11, category: "Auth", name: "JWT Vulnerabilities", severity: "High", cwe: "CWE-347" },
  { id: 12, category: "Access Control", name: "IDOR", severity: "High", cwe: "CWE-639" },
  { id: 13, category: "Access Control", name: "Privilege Escalation", severity: "Critical", cwe: "CWE-269" },
  { id: 14, category: "Access Control", name: "Path Traversal", severity: "High", cwe: "CWE-22" },
  { id: 15, category: "Crypto", name: "Weak Cryptography", severity: "High", cwe: "CWE-327" },
  { id: 16, category: "Crypto", name: "Cleartext Transmission", severity: "High", cwe: "CWE-319" },
  { id: 17, category: "CSRF", name: "Cross-Site Request Forgery", severity: "High", cwe: "CWE-352" },
  { id: 18, category: "SSRF", name: "Server-Side Request Forgery", severity: "Critical", cwe: "CWE-918" },
  { id: 19, category: "XXE", name: "XML External Entities", severity: "High", cwe: "CWE-611" },
  { id: 20, category: "Deserialization", name: "Insecure Deserialization", severity: "Critical", cwe: "CWE-502" },
  { id: 21, category: "Config", name: "Security Misconfiguration", severity: "Medium", cwe: "CWE-16" },
  { id: 22, category: "Config", name: "Default Credentials", severity: "Critical", cwe: "CWE-1188" },
  { id: 23, category: "File", name: "Unrestricted File Upload", severity: "Critical", cwe: "CWE-434" },
  { id: 24, category: "File", name: "Local File Inclusion", severity: "High", cwe: "CWE-98" },
  { id: 25, category: "Header", name: "Clickjacking", severity: "Medium", cwe: "CWE-1021" },
  { id: 26, category: "Header", name: "Missing Security Headers", severity: "Medium", cwe: "CWE-693" },
  { id: 27, category: "Logic", name: "Business Logic Flaws", severity: "High", cwe: "CWE-840" },
  { id: 28, category: "Logic", name: "Race Conditions", severity: "High", cwe: "CWE-362" },
  { id: 29, category: "API", name: "Broken Object Level Auth", severity: "Critical", cwe: "CWE-639" },
  { id: 30, category: "API", name: "GraphQL Injection", severity: "High", cwe: "CWE-89" },
];

const SEV = {
  Critical: { bg: "bg-red-900/40", text: "text-red-400", border: "border-red-700/50" },
  High: { bg: "bg-orange-900/40", text: "text-orange-400", border: "border-orange-700/50" },
  Medium: { bg: "bg-yellow-900/40", text: "text-yellow-400", border: "border-yellow-700/50" },
};

const MODES = [
  { key: "Explain", icon: "📖", label: "Explain" },
  { key: "Attack", icon: "⚔️", label: "Attack Demo" },
  { key: "Defence", icon: "🔒", label: "Defence" },
  { key: "Quiz", icon: "🧠", label: "Quiz Me" },
];

const CATS = ["All", ...new Set(VULNERABILITIES.map(v => v.category))];

function buildSystemPrompt(vuln, mode) {
  const ctx = `You are an expert cybersecurity educator for WebVuln-Plus (github.com/mngugi/WebVuln--Plus), an educational project covering 100+ web vulnerabilities. Topic: **${vuln.name}** (${vuln.cwe}, Severity: ${vuln.severity}).`;
  if (mode === "Explain") return `${ctx}\n\nExplain clearly:\n1. What it is & how it works\n2. Real-world example\n3. Vulnerable vs safe code snippets\n4. CVSS impact summary\nUse markdown with fenced code blocks.`;
  if (mode === "Attack") return `${ctx}\n\nProvide an ethical, educational attack walkthrough:\n1. How it's discovered\n2. Step-by-step exploitation with example payloads\n3. Tools used (Burp Suite, etc.)\n4. What an attacker gains\nClarify this is for defensive learning. Use code blocks.`;
  if (mode === "Defence") return `${ctx}\n\nFocus on defense:\n1. Secure coding patterns with code\n2. Framework mitigations\n3. WAF rules / security headers\n4. Detection & logging\n5. OWASP reference\nUse code blocks.`;
  if (mode === "Quiz") return `${ctx}\n\nCreate a 3-question quiz testing knowledge of ${vuln.name}. Use mixed formats (multiple choice, true/false, scenario). Show (A)(B)(C)(D) for MCQs. Don't reveal answers — ask the student to submit them.`;
  return ctx;
}

function parseContent(text) {
  const parts = text.split(/(```[\s\S]*?```)/g);
  return parts.map((part, i) => {
    if (part.startsWith("```")) {
      const lines = part.slice(3, -3).split("\n");
      const lang = lines[0] || "code";
      const code = lines.slice(1).join("\n");
      return (
        <div key={i} className="my-3 rounded-lg overflow-hidden border border-gray-700">
          <div className="bg-gray-800 px-3 py-1.5 text-xs text-gray-400 font-mono flex gap-2 items-center">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500 opacity-80"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-yellow-500 opacity-80"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-green-500 opacity-80"></span>
            <span className="ml-1 text-gray-500">{lang}</span>
          </div>
          <pre className="bg-gray-950 p-4 text-sm text-green-300 font-mono overflow-x-auto leading-relaxed whitespace-pre-wrap">{code}</pre>
        </div>
      );
    }
    const html = part
      .replace(/\*\*(.+?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
      .replace(/`([^`]+)`/g, '<code class="bg-gray-800 text-green-300 px-1.5 py-0.5 rounded text-xs font-mono">$1</code>')
      .replace(/^### (.+)$/gm, '<div class="text-base font-bold text-cyan-300 mt-5 mb-2">$1</div>')
      .replace(/^## (.+)$/gm, '<div class="text-lg font-bold text-cyan-400 mt-5 mb-2">$1</div>')
      .replace(/^# (.+)$/gm, '<div class="text-xl font-bold text-white mt-5 mb-2">$1</div>')
      .replace(/^\d+\. (.+)$/gm, '<div class="ml-4 my-1 text-gray-300">$1</div>');
    return <span key={i} className="whitespace-pre-wrap text-gray-300 leading-relaxed" dangerouslySetInnerHTML={{ __html: html }} />;
  });
}

export default function App() {
  const [selected, setSelected] = useState(null);
  const [mode, setMode] = useState("Explain");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [cat, setCat] = useState("All");
  const chatEnd = useRef(null);

  useEffect(() => { chatEnd.current?.scrollIntoView({ behavior: "smooth" }); }, [messages, loading]);

  const filtered = VULNERABILITIES.filter(v =>
    (cat === "All" || v.category === cat) &&
    (v.name.toLowerCase().includes(search.toLowerCase()) || v.cwe.toLowerCase().includes(search.toLowerCase()))
  );

  const callClaude = async (userContent, systemPrompt, resetHistory = false) => {
    setLoading(true);
    try {
      const history = resetHistory ? [] : messages.map(m => ({ role: m.role, content: m.content }));
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: systemPrompt,
          messages: [...history, { role: "user", content: userContent }],
        }),
      });
      const data = await res.json();
      const reply = data.content?.map(b => b.text || "").join("\n") || "No response received.";
      if (resetHistory) {
        setMessages([{ role: "assistant", content: reply }]);
      } else {
        setMessages(prev => [...prev, { role: "user", content: userContent }, { role: "assistant", content: reply }]);
      }
    } catch {
      const errMsg = { role: "assistant", content: "⚠️ Connection error. Please try again." };
      resetHistory ? setMessages([errMsg]) : setMessages(prev => [...prev, errMsg]);
    }
    setLoading(false);
  };

  const selectVuln = (v) => {
    setSelected(v);
    setMessages([]);
    callClaude(`Teach me about ${v.name}`, buildSystemPrompt(v, mode), true);
  };

  const switchMode = (m) => {
    setMode(m);
    if (selected) {
      setMessages([]);
      callClaude(`Teach me about ${selected.name}`, buildSystemPrompt(selected, m), true);
    }
  };

  const send = () => {
    if (!input.trim() || !selected || loading) return;
    const msg = input.trim();
    setInput("");
    callClaude(msg, buildSystemPrompt(selected, mode));
  };

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-200 overflow-hidden" style={{ fontFamily: "system-ui, sans-serif" }}>
      {/* Header */}
      <header className="flex items-center justify-between px-5 py-3 bg-gray-900 border-b border-gray-800 flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center font-black text-white text-sm">W+</div>
          <div>
            <div className="font-bold text-white text-base leading-tight">WebVuln<span className="text-cyan-400">+</span> AI Tutor</div>
            <div className="text-gray-500 text-xs">100+ Vulnerabilities · Powered by Claude AI</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-600">mngugi/WebVuln--Plus</span>
          <span className="px-2 py-1 text-xs rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">Project 1 of 4</span>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col flex-shrink-0">
          <div className="p-3 border-b border-gray-800 space-y-2">
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="🔍 Search..."
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm placeholder-gray-600 focus:outline-none focus:border-cyan-500 text-gray-200" />
            <div className="flex flex-wrap gap-1">
              {CATS.map(c => (
                <button key={c} onClick={() => setCat(c)}
                  className={`px-2 py-0.5 text-xs rounded-full border transition-colors ${cat === c ? "bg-cyan-500/25 border-cyan-500/50 text-cyan-300" : "border-gray-700 text-gray-500 hover:text-gray-300"}`}>
                  {c}
                </button>
              ))}
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-0.5">
            {filtered.map(v => {
              const s = SEV[v.severity] || SEV.Medium;
              const active = selected?.id === v.id;
              return (
                <button key={v.id} onClick={() => selectVuln(v)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg transition-all border ${active ? "bg-gray-800 border-gray-600" : "border-transparent hover:bg-gray-800/70"}`}>
                  <div className="flex items-center justify-between gap-1">
                    <span className="text-sm font-medium text-gray-200 truncate">{v.name}</span>
                    <span className={`text-xs px-1.5 py-0.5 rounded-full border flex-shrink-0 ${s.bg} ${s.text} ${s.border}`}>{v.severity[0]}</span>
                  </div>
                  <div className="text-xs text-gray-500 mt-0.5">{v.cwe} · {v.category}</div>
                </button>
              );
            })}
          </div>
          <div className="p-3 border-t border-gray-800 text-xs text-gray-600 text-center">{filtered.length} / {VULNERABILITIES.length} vulns</div>
        </aside>

        {/* Main */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {!selected ? (
            <div className="flex-1 flex flex-col items-center justify-center p-10 text-center">
              <div className="text-5xl mb-4">🛡️</div>
              <h2 className="text-2xl font-bold text-white mb-2">Select a Vulnerability</h2>
              <p className="text-gray-500 text-sm max-w-sm mb-8">Choose any vulnerability from the sidebar to start learning with AI-powered explanations, attack demos, defensive guidance, and interactive quizzes.</p>
              <div className="grid grid-cols-2 gap-3 max-w-xs">
                {MODES.map(m => (
                  <div key={m.key} className="bg-gray-900 border border-gray-800 rounded-xl p-4 text-center">
                    <div className="text-2xl mb-1">{m.icon}</div>
                    <div className="text-xs font-medium text-gray-300">{m.label}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <>
              {/* Vuln bar */}
              <div className="flex-shrink-0 border-b border-gray-800 bg-gray-900 px-5 py-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <h2 className="font-bold text-white text-lg">{selected.name}</h2>
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${SEV[selected.severity]?.bg} ${SEV[selected.severity]?.text} ${SEV[selected.severity]?.border}`}>{selected.severity}</span>
                    <span className="text-xs text-gray-500">{selected.cwe}</span>
                  </div>
                </div>
                <div className="flex gap-2">
                  {MODES.map(m => (
                    <button key={m.key} onClick={() => switchMode(m.key)}
                      className={`px-3 py-1.5 text-xs rounded-lg border transition-all font-medium flex items-center gap-1.5 ${mode === m.key ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-300" : "border-gray-700 text-gray-500 hover:border-gray-500 hover:text-gray-300"}`}>
                      <span>{m.icon}</span>{m.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Chat */}
              <div className="flex-1 overflow-y-auto p-5 space-y-5">
                {loading && messages.length === 0 && (
                  <div className="flex gap-3 items-start">
                    <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-xs text-cyan-400 flex-shrink-0">AI</div>
                    <div className="flex gap-1 mt-2">
                      {[0, 150, 300].map(d => <span key={d} className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{ animationDelay: `${d}ms` }} />)}
                    </div>
                  </div>
                )}
                {messages.map((msg, i) => (
                  <div key={i} className={`flex gap-3 ${msg.role === "user" ? "flex-row-reverse" : "flex-row"}`}>
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${msg.role === "user" ? "bg-blue-500/20 border border-blue-500/40 text-blue-400" : "bg-cyan-500/20 border border-cyan-500/30 text-cyan-400"}`}>
                      {msg.role === "user" ? "You" : "AI"}
                    </div>
                    <div className={`max-w-2xl text-sm ${msg.role === "user" ? "bg-blue-500/10 border border-blue-500/20 rounded-2xl rounded-tr-sm px-4 py-3 text-gray-200" : ""}`}>
                      {parseContent(msg.content)}
                    </div>
                  </div>
                ))}
                {loading && messages.length > 0 && (
                  <div className="flex gap-3 items-start">
                    <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-xs text-cyan-400 flex-shrink-0">AI</div>
                    <div className="flex gap-1 mt-2">
                      {[0, 150, 300].map(d => <span key={d} className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{ animationDelay: `${d}ms` }} />)}
                    </div>
                  </div>
                )}
                <div ref={chatEnd} />
              </div>

              {/* Input */}
              <div className="flex-shrink-0 border-t border-gray-800 bg-gray-900 p-4">
                <div className="flex gap-2">
                  <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && send()}
                    placeholder={mode === "Quiz" ? "Type your answers (e.g. 1:A, 2:True, 3:...)..." : "Ask a follow-up question..."}
                    disabled={loading}
                    className="flex-1 bg-gray-800 border border-gray-700 rounded-xl px-4 py-2.5 text-sm placeholder-gray-600 focus:outline-none focus:border-cyan-500 disabled:opacity-50 text-gray-200" />
                  <button onClick={send} disabled={loading || !input.trim()}
                    className="px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 disabled:text-gray-500 text-white rounded-xl text-sm font-semibold transition-colors">
                    Send
                  </button>
                </div>
                <p className="text-center text-xs text-gray-700 mt-2">Educational use only · WebVuln-Plus by mngugi</p>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}