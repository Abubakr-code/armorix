import { useCallback, useEffect, useRef, useState } from "react";

import { api, connect, waitFor } from "./api";
import { STRINGS } from "./i18n";

const SEVERITIES = ["critical", "high", "medium", "low"];
const readLang = () => {
  try {
    return localStorage.getItem("armorix_lang") || "uz";
  } catch {
    return "uz";
  }
};

const Shield = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
    <rect width="64" height="64" rx="16" fill="var(--accent)" />
    <path d="M32 12 48 18v13c0 10.5-6.8 18.6-16 21.9C22.8 49.6 16 41.5 16 31V18z" fill="#fff" />
    <circle cx="32" cy="29" r="5" fill="var(--accent)" />
    <path d="M30 32h4l1.5 9h-7z" fill="var(--accent)" />
  </svg>
);

let seq = 0;
const nextId = () => ++seq;

export default function App() {
  const [lang, setLang] = useState(readLang);
  const t = STRINGS[lang];
  const [ready, setReady] = useState(false);
  const [status, setStatus] = useState(null);
  const [folder, setFolder] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const bottom = useRef(null);

  const push = useCallback((msg) => {
    const id = nextId();
    setMessages((m) => [...m, { id, ...msg }]);
    return id;
  }, []);
  const patch = useCallback((id, changes) => setMessages((m) => m.map((x) => (x.id === id ? { ...x, ...changes } : x))), []);

  const refresh = useCallback(() => api.status().then(setStatus).catch(() => {}), []);

  useEffect(() => {
    connect().then(() => {
      setReady(true);
      refresh();
    });
  }, [refresh]);

  useEffect(() => {
    try {
      localStorage.setItem("armorix_lang", lang);
    } catch {
      /* private storage */
    }
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    // Braces matter: newer Chromium returns a Promise from scrollIntoView, which React would call as a cleanup.
    bottom.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  const follow = useCallback(
    async (jobId, kind, path) => {
      const msgId = push({ role: "job", kind, path, job: { id: jobId, status: "running" } });
      const view = await waitFor(jobId, (v) => patch(msgId, { job: v }));
      if (kind === "ai-setup" || kind === "db-update") refresh();
      return view;
    },
    [patch, push, refresh]
  );

  const runTask = useCallback(
    async (text) => {
      if (!text.trim() || busy) return;
      setBusy(true);
      push({ role: "user", text });
      try {
        const reply = await api.task(text, folder, lang);
        push({ role: "assistant", text: reply.reply });
        if (reply.job) {
          if (reply.path && reply.path !== folder) setFolder(reply.path);
          await follow(reply.job, reply.kind, reply.path);
        }
      } catch (err) {
        push({ role: "assistant", text: `${t.failed}: ${err.message}`, tone: "error" });
      } finally {
        setBusy(false);
      }
    },
    [busy, folder, follow, lang, push, t.failed]
  );

  const startJob = useCallback(
    async (kind, params = {}) => {
      setBusy(true);
      try {
        const { job } = await api.start(kind, { lang, ...params });
        await follow(job, kind, params.path);
      } catch (err) {
        push({ role: "assistant", text: `${t.failed}: ${err.message}`, tone: "error" });
      } finally {
        setBusy(false);
      }
    },
    [follow, lang, push, t.failed]
  );

  const chooseFolder = async () => {
    const dir = await window.armorix.chooseFolder();
    if (dir) setFolder(dir);
  };

  const importModel = async () => {
    const file = await window.armorix.chooseModel();
    if (!file) return;
    try {
      await api.importModel(file);
      refresh();
      push({ role: "assistant", text: t.setupDone });
    } catch (err) {
      push({ role: "assistant", text: `${t.failed}: ${err.message}`, tone: "error" });
    }
  };

  const ai = status?.ai;
  const dbCount = status?.db?.advisories ? Object.values(status.db.advisories).reduce((a, b) => a + b, 0) : 0;

  return (
    <div className="app">
      <aside className="side">
        <div className="brand">
          <Shield />
          <span>Armorix</span>
          <small>v{status?.version || "…"}</small>
        </div>

        <button className="folder" onClick={chooseFolder} disabled={!ready}>
          <span className="folder-label">{t.choose}</span>
          <span className="folder-path" title={folder || ""}>{folder || t.noFolder}</span>
        </button>

        <p className="side-title">{t.actions}</p>
        <div className="quick">
          <button disabled={!folder || busy} onClick={() => runTask(t.scanTask)}>⌕ {t.scan}</button>
          <button disabled={!folder || busy} onClick={() => runTask(t.deepTask)}>◎ {t.deep}</button>
          <button disabled={!folder || busy || !ai?.ready} onClick={() => runTask(t.fixTask)}>✦ {t.fix}</button>
        </div>

        <div className="panel">
          <p className="side-title">{t.engine}</p>
          <p className={`state ${ai?.ready ? "ok" : "warn"}`}>
            <i /> {ai?.ready ? `${t.aiReady}${ai.ollama ? ` · ${t.aiOllama}` : ""}` : t.aiMissing}
          </p>
          {ai && !ai.ready && (
            <>
              <button className="primary" disabled={busy} onClick={() => startJob("ai-setup")}>{t.aiSetup}</button>
              <button className="ghost" disabled={busy} onClick={importModel}>{t.aiImport}</button>
              <p className="hint">{t.aiNote}</p>
            </>
          )}
        </div>

        <div className="panel">
          <p className="side-title">{t.db}</p>
          <p className={`state ${dbCount ? "ok" : "warn"}`}>
            <i /> {dbCount ? `${dbCount.toLocaleString()} ${t.advisories}` : t.dbMissing}
          </p>
          <button className="ghost" disabled={busy} onClick={() => startJob("db-update")}>{t.dbUpdate}</button>
        </div>

        <div className="side-foot">
          <div className="langs">
            {["uz", "ru", "en"].map((l) => (
              <button key={l} className={l === lang ? "on" : ""} onClick={() => setLang(l)}>{l.toUpperCase()}</button>
            ))}
          </div>
          <span className="offline"><i /> {t.offline}</span>
        </div>
      </aside>

      <main className="chat">
        <div className="thread">
          <div className="msg assistant">
            <Shield size={30} />
            <div className="bubble">
              <p>{t.greeting}</p>
              <div className="chips">
                {t.examples.map((ex) => (
                  <button key={ex} onClick={() => setInput(ex)}>{ex}</button>
                ))}
              </div>
            </div>
          </div>
          {messages.map((m) => (
            <Message key={m.id} m={m} t={t} lang={lang} onFix={(path, ids) => startJob("fix", { path, findings: ids, limit: 8 })} push={push} busy={busy} />
          ))}
          <div ref={bottom} />
        </div>

        <form
          className="composer"
          onSubmit={(e) => {
            e.preventDefault();
            const text = input;
            setInput("");
            runTask(text);
          }}
        >
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder={t.placeholder} disabled={!ready} />
          <button type="submit" disabled={!ready || busy || !input.trim()}>{t.send} ↵</button>
        </form>
      </main>
    </div>
  );
}

function Message({ m, t, lang, onFix, push, busy }) {
  if (m.role === "user") {
    return (
      <div className="msg user">
        <div className="bubble">{m.text}</div>
      </div>
    );
  }
  if (m.role === "assistant") {
    return (
      <div className={`msg assistant ${m.tone || ""}`}>
        <Shield size={30} />
        <div className="bubble"><p>{m.text}</p></div>
      </div>
    );
  }
  return (
    <div className="msg assistant">
      <Shield size={30} />
      <div className="bubble wide">
        <JobCard m={m} t={t} lang={lang} onFix={onFix} push={push} busy={busy} />
      </div>
    </div>
  );
}

function JobCard({ m, t, onFix, push, busy }) {
  const job = m.job;
  if (job.status === "running") {
    const pct = job.total ? Math.round((job.done / job.total) * 100) : null;
    return (
      <div className="progress">
        <div className="progress-top">
          <span className="spinner" />
          <b>{t.phases[job.phase] || t.running}</b>
          <span className="muted">{job.total ? `${job.done}/${job.total}` : ""} · {job.elapsed}s</span>
          <button className="link" onClick={() => api.cancel(job.id)}>{t.cancel}</button>
        </div>
        <div className="bar"><span style={{ width: pct == null ? "30%" : `${pct}%` }} className={pct == null ? "indeterminate" : ""} /></div>
        {job.detail && <p className="detail">{job.detail}</p>}
      </div>
    );
  }
  if (job.status === "error") return <p className="error-text">{t.failed}: {job.error}</p>;
  if (job.status === "cancelled") return <p className="muted">{t.cancelled}</p>;
  if (m.kind === "ai-setup") return <p>{t.setupDone}</p>;
  if (m.kind === "db-update") return <p>{t.dbDone}</p>;
  if (m.kind === "fix") return <FixCard job={job} t={t} push={push} />;
  return <ScanCard job={job} kind={m.kind} t={t} onFix={onFix} busy={busy} />;
}

function ScanCard({ job, kind, t, onFix, busy }) {
  const r = job.result;
  const [open, setOpen] = useState(() => new Set(r.findings.slice(0, 1).map((f) => f.id)));
  const toggle = (id) => setOpen((s) => {
    const n = new Set(s);
    n.has(id) ? n.delete(id) : n.add(id);
    return n;
  });
  const fixable = r.findings.filter((f) => f.fixable && ["critical", "high"].includes(f.severity)).map((f) => f.id);
  return (
    <div className="result">
      <p className="result-head">
        {kind === "deep" && <b>{t.deepDone} </b>}
        {r.findings.length ? <><b>{r.findings.length}</b> {t.found}</> : t.clean}
        {kind === "deep" && !r.ai_used && <span className="muted"> · {t.aiSkipped}</span>}
      </p>
      <p className="meta">
        {r.files} {t.files} · {r.lines.toLocaleString()} {t.lines} · {r.dependencies} {t.packages} · {job.elapsed} {t.seconds}
      </p>
      <div className="counts">
        {SEVERITIES.map((s) => (
          <span key={s} className={`count ${s}`}><b>{r.counts[s]}</b>{s}</span>
        ))}
      </div>
      <ul className="findings">
        {r.findings.map((f) => (
          <li key={f.id} className={open.has(f.id) ? "open" : ""}>
            <button className="f-row" onClick={() => toggle(f.id)}>
              <span className={`sev ${f.severity}`}>{f.severity_label}</span>
              {f.ai && <span className="ai-badge">{t.aiBadge}</span>}
              <span className="f-title">{f.title}</span>
              <span className="f-loc">{f.file}:{f.line}</span>
            </button>
            {open.has(f.id) && (
              <div className="f-body">
                <p>{f.message}</p>
                <pre>
                  {(f.trace.length ? f.trace : [{ line: f.line, code: f.snippet, label: "" }]).map((s, i) => (
                    <div key={i}><span className="lab">{s.label}</span><span className="ln">{s.line}</span>{s.code}</div>
                  ))}
                </pre>
                <p className="fix"><b>{t.fixLabel}:</b> {f.fix} <span className="cwe">{f.cwe}</span></p>
              </div>
            )}
          </li>
        ))}
      </ul>
      <div className="row-actions">
        <button className="ghost" onClick={() => window.armorix.open(api.reportUrl(job.id))}>{t.openReport} ↗</button>
        {fixable.length > 0 && <button className="primary" disabled={busy} onClick={() => onFix(r.root, fixable)}>✦ {t.fixAll} ({Math.min(8, fixable.length)})</button>}
      </div>
    </div>
  );
}

function FixCard({ job, t, push }) {
  const patches = job.result.patches;
  const [chosen, setChosen] = useState(() => new Set(patches.filter((p) => p.verified).map((p) => p.id)));
  const [done, setDone] = useState(false);
  if (!patches.length) return <p>{t.noPatches}</p>;
  const apply = async () => {
    const res = await api.apply(job.id, [...chosen]);
    setDone(true);
    push({ role: "assistant", text: t.applied(res.applied, res.remaining) });
  };
  return (
    <div className="result">
      <p className="result-head"><b>{t.patches}:</b> {patches.filter((p) => p.verified).length}/{patches.length} {t.verified.toLowerCase()}</p>
      {patches.map((p) => (
        <div key={p.id} className={`patch ${p.verified ? "ok" : "bad"}`}>
          <label className="patch-top">
            <input type="checkbox" disabled={!p.verified || done} checked={chosen.has(p.id)}
              onChange={(e) => setChosen((s) => { const n = new Set(s); e.target.checked ? n.add(p.id) : n.delete(p.id); return n; })} />
            <span className={`sev ${p.finding.severity}`}>{p.finding.severity_label}</span>
            <span className="f-title">{p.finding.title}</span>
            <span className="f-loc">{p.finding.file}:{p.finding.line}</span>
            <span className={`verdict ${p.verified ? "ok" : "bad"}`}>{p.verified ? `✓ ${t.verified}` : `✗ ${t.rejected}`}</span>
          </label>
          {!p.verified && <p className="muted small">{p.reason}</p>}
          {p.diff && (
            <pre className="diff">
              {p.diff.split("\n").slice(2).map((line, i) => (
                <div key={i} className={line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : line.startsWith("@@") ? "hunk" : ""}>{line || " "}</div>
              ))}
            </pre>
          )}
        </div>
      ))}
      {!done && chosen.size > 0 && (
        <div className="row-actions"><button className="primary" onClick={apply}>{t.apply} ({chosen.size})</button></div>
      )}
    </div>
  );
}
