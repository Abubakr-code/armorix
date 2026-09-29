// AI fix flow: the local model writes a patch for each chosen finding, the engine re-parses and re-scans it,
// and only verified patches can be applied. Shown side by side (original | patched).
import { useEffect, useRef, useState } from "react";
import { CheckCircle2, ShieldAlert, Sparkles, X, XCircle } from "lucide-react";

import { api, waitFor } from "../api";
import { languageOf } from "../util";
import DiffView from "./DiffView";

export function Patches({ t, patches, chosen, setChosen, done }) {
  return patches.map((p) => (
    <div key={p.id} className={`patch ${p.verified ? "ok" : "bad"}`}>
      <label className="patch-top">
        <input type="checkbox" disabled={!p.verified || done} checked={chosen.has(p.id)}
          onChange={(e) => setChosen((s) => {
            const n = new Set(s);
            if (e.target.checked) n.add(p.id);
            else n.delete(p.id);
            return n;
          })} />
        <span className={`sev ${p.finding.severity}`}>{p.finding.severity_label}</span>
        <span className="ellipsis grow"><b>{p.finding.title}</b></span>
        <span className="f-loc">{p.finding.file}:{p.finding.line}</span>
        <span className={`verdict ${p.verified ? "ok" : "bad"}`}>
          {p.verified ? <CheckCircle2 size={14} /> : <XCircle size={14} />} {p.verified ? t.verified : t.rejected}
        </span>
      </label>
      {!p.verified && <p className="muted small">{p.reason}</p>}
      {p.diff && <DiffView diff={p.diff} language={languageOf(p.finding.file)} labels={[t.before, t.after]} />}
    </div>
  ));
}

export default function FixModal({ t, lang, root, findings, onClose, onApplied, settings }) {
  const [job, setJob] = useState(null);
  const [view, setView] = useState(null);
  const [error, setError] = useState(null);
  const [chosen, setChosen] = useState(new Set());
  const [applying, setApplying] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    (async () => {
      try {
        const { job: id } = await api.start("fix", {
          path: root, lang, fingerprints: findings.map((f) => f.fingerprint), limit: findings.length,
          disable: settings.disabled, include_tests: settings.includeTests,
        });
        setJob(id);
        const final = await waitFor(id, setView, 500);
        if (final.status === "error") setError(final.error);
        else if (final.status === "done") setChosen(new Set(final.result.patches.filter((p) => p.verified).map((p) => p.id)));
      } catch (err) {
        setError(err.message);
      }
    })();
  }, [root, findings, lang, settings]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && !applying && close();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const close = () => {
    if (view?.status === "running" && job) api.cancel(job);
    onClose();
  };

  const apply = async () => {
    setApplying(true);
    try {
      const res = await api.apply(job, [...chosen]);
      onApplied(res);
    } catch (err) {
      setError(err.message);
      setApplying(false);
    }
  };

  const running = !view || view.status === "running";
  const patches = view?.result?.patches || [];
  const pct = view?.total ? Math.round((view.done / view.total) * 100) : null;

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !running && close()}>
      <div className="modal wide" role="dialog" aria-modal="true">
        <header className="modal-head">
          <h2><Sparkles size={18} /> {t.aiFixTitle}</h2>
          <button className="icon-btn" onClick={close} aria-label={t.close}><X size={18} /></button>
        </header>
        <div className="modal-body">
          {error ? (
            <div className="notice error"><ShieldAlert size={18} /> {t.failed}: {error}</div>
          ) : running ? (
            <div className="fix-running">
              <span className="spinner big" />
              <div className="grow">
                <b>{t.phases[view?.phase] || t.aiStarting}</b>
                <div className="bar"><span style={{ width: pct == null ? "30%" : `${pct}%` }} className={pct == null ? "indeterminate" : ""} /></div>
                <p className="muted small mono">{view?.detail || ""} {view?.elapsed != null ? `· ${view.elapsed} ${t.seconds}` : ""}</p>
                <p className="muted small">{t.aiFixHint}</p>
              </div>
            </div>
          ) : patches.length === 0 ? (
            <p>{t.noPatches}</p>
          ) : (
            <>
              <p className="muted">{t.patchSummary(patches.filter((p) => p.verified).length, patches.length)}</p>
              <Patches t={t} patches={patches} chosen={chosen} setChosen={setChosen} done={applying} />
            </>
          )}
        </div>
        <footer className="modal-foot">
          <span className="muted small">{t.backupNote}</span>
          <button className="ghost" onClick={close}>{running ? t.cancel : t.close}</button>
          <button className="primary" disabled={running || !chosen.size || applying} onClick={apply}>
            {applying ? <span className="spinner" /> : <CheckCircle2 size={15} />} {t.applyN(chosen.size)}
          </button>
        </footer>
      </div>
    </div>
  );
}
