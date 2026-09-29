// Task chat: "shu papkani chuqur tekshir", "xatolarni tuzat" … — the original way to drive Armorix, kept
// for people who prefer typing. Results land in the project view too.
import { useEffect, useRef, useState } from "react";
import { ArrowRight, CornerDownLeft } from "lucide-react";

import { api, waitFor } from "../api";
import { Logo } from "../components/Sidebar";
import { Patches } from "../components/FixModal";
import { SEVERITIES, basename } from "../util";

function ScanSummary({ t, result, kind, openResult }) {
  return (
    <div className="chat-result">
      <p>
        {kind === "deep" && <b>{t.deepDone} </b>}
        {result.findings.length ? <><b>{result.findings.length}</b> {t.found}</> : t.clean}
      </p>
      <div className="project-counts">
        {SEVERITIES.map((s) => <span key={s} className={`pill ${s} ${result.counts[s] ? "" : "zero"}`}>{result.counts[s] || 0}</span>)}
      </div>
      <ul className="top-list compact">
        {result.findings.slice(0, 4).map((f) => (
          <li key={f.fingerprint}><span className={`sev ${f.severity}`}>{f.severity_label}</span> <span className="ellipsis grow">{f.title}</span> <span className="f-loc">{basename(f.file)}:{f.line}</span></li>
        ))}
      </ul>
      <button className="ghost small" onClick={openResult}>{t.openResults} <ArrowRight size={14} /></button>
    </div>
  );
}

function FixSummary({ t, job, result, onApplied }) {
  const [chosen, setChosen] = useState(() => new Set(result.patches.filter((p) => p.verified).map((p) => p.id)));
  const [done, setDone] = useState(false);
  if (!result.patches.length) return <p>{t.noPatches}</p>;
  return (
    <div className="chat-result">
      <p>{t.patchSummary(result.patches.filter((p) => p.verified).length, result.patches.length)}</p>
      <Patches t={t} patches={result.patches} chosen={chosen} setChosen={setChosen} done={done} />
      {!done && chosen.size > 0 && (
        <div className="row-actions">
          <button className="primary" onClick={async () => { const res = await api.apply(job, [...chosen]); setDone(true); onApplied(res); }}>
            {t.applyN(chosen.size)}
          </button>
        </div>
      )}
    </div>
  );
}

export default function Assistant({ t, lang, current, messages, setMessages, busy, setBusy, adoptResult, openProject, runScan }) {
  const [input, setInput] = useState("");
  const bottom = useRef(null);

  useEffect(() => {
    // Braces matter: newer Chromium returns a Promise from scrollIntoView, which React would call as a cleanup.
    bottom.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  const push = (msg) => setMessages((m) => [...m, { id: `${Date.now()}-${Math.random()}`, ...msg }]);
  const patch = (id, changes) => setMessages((m) => m.map((x) => (x.id === id ? { ...x, ...changes } : x)));

  const send = async (text) => {
    if (!text.trim() || busy) return;
    setBusy(true);
    push({ role: "user", text });
    try {
      const reply = await api.task(text, current, lang);
      push({ role: "assistant", text: reply.reply });
      if (reply.job) {
        const id = `${reply.job}-card`;
        setMessages((m) => [...m, { id, role: "job", kind: reply.kind, path: reply.path, job: reply.job, view: null }]);
        const view = await waitFor(reply.job, (v) => patch(id, { view: v }));
        if (view.status === "done" && (reply.kind === "scan" || reply.kind === "deep")) adoptResult(reply.path, reply.kind, reply.job, view.result);
      }
    } catch (err) {
      push({ role: "assistant", text: `${t.failed}: ${err.message}`, tone: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page chat">
      <div className="thread">
        <div className="msg assistant">
          <Logo size={30} />
          <div className="bubble">
            <p>{t.greeting}</p>
            <div className="chips">
              {t.examples.map((ex) => <button key={ex} onClick={() => setInput(ex)}>{ex}</button>)}
            </div>
            {current && <p className="muted small">{t.chatFolder(basename(current))}</p>}
          </div>
        </div>
        {messages.map((m) => {
          if (m.role === "user") return <div key={m.id} className="msg user"><div className="bubble">{m.text}</div></div>;
          if (m.role === "assistant") {
            return <div key={m.id} className={`msg assistant ${m.tone || ""}`}><Logo size={30} /><div className="bubble"><p>{m.text}</p></div></div>;
          }
          const v = m.view;
          let body;
          if (!v || v.status === "running") {
            const pct = v?.total ? Math.round((v.done / v.total) * 100) : null;
            body = (
              <div className="progress">
                <div className="progress-top"><span className="spinner" /><b>{t.phases[v?.phase] || t.running}</b>
                  <span className="muted">{v?.total ? `${v.done}/${v.total}` : ""} {v?.elapsed != null ? `· ${v.elapsed}s` : ""}</span>
                  {v && <button className="link" onClick={() => api.cancel(v.id)}>{t.cancel}</button>}
                </div>
                <div className="bar"><span style={{ width: pct == null ? "30%" : `${pct}%` }} className={pct == null ? "indeterminate" : ""} /></div>
                {v?.detail && <p className="detail mono small ellipsis">{v.detail}</p>}
              </div>
            );
          } else if (v.status === "error") body = <p className="error-text">{t.failed}: {v.error}</p>;
          else if (v.status === "cancelled") body = <p className="muted">{t.cancelled}</p>;
          else if (m.kind === "fix") body = <FixSummary t={t} job={m.job} result={v.result} onApplied={(res) => { push({ role: "assistant", text: t.applied(res.applied, res.remaining) }); runScan(m.path, "scan", { quiet: true }); }} />;
          else body = <ScanSummary t={t} result={v.result} kind={m.kind} openResult={() => openProject(m.path, { keep: true })} />;
          return <div key={m.id} className="msg assistant"><Logo size={30} /><div className="bubble wide">{body}</div></div>;
        })}
        <div ref={bottom} />
      </div>
      <form className="composer" onSubmit={(e) => { e.preventDefault(); const text = input; setInput(""); send(text); }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} placeholder={t.placeholder} />
        <button type="submit" className="primary" disabled={busy || !input.trim()}>{t.send} <CornerDownLeft size={15} /></button>
      </form>
    </div>
  );
}
