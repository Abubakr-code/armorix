import { useEffect, useRef, useState } from "react";
import { Download, Eye, EyeOff, FolderOpen, Radar, RotateCw, ShieldCheck, Sparkles, Square } from "lucide-react";

import { api } from "../api";
import ShieldCanvas from "../components/ShieldCanvas";
import { basename } from "../util";
import Findings from "./Findings";
import History from "./History";
import Overview from "./Overview";

function ScanProgress({ t, state, onCancel }) {
  const job = state.progress;
  const pct = job?.total ? Math.round((job.done / job.total) * 100) : null;
  return (
    <div className="scan-progress">
      <ShieldCanvas size={260} scanning />
      <div className="scan-progress-text">
        <p className="eyebrow"><i className="live" /> {state.kind === "deep" ? t.deepScanning : t.scanning}</p>
        <h2>{t.phases[job?.phase] || t.preparing}</h2>
        <div className="bar big"><span style={{ width: pct == null ? "30%" : `${pct}%` }} className={pct == null ? "indeterminate" : ""} /></div>
        <p className="muted mono small ellipsis">{job?.total ? `${job.done}/${job.total} · ` : ""}{job?.detail || " "}</p>
        <p className="muted small">{job?.elapsed != null ? `${job.elapsed} ${t.seconds}` : ""}</p>
        {job?.id && <button className="ghost" onClick={() => onCancel(job.id)}><Square size={14} /> {t.cancel}</button>}
      </div>
    </div>
  );
}

function ExportMenu({ t, onExport, open, setOpen }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const close = (e) => { if (!ref.current?.contains(e.target)) setOpen(false); };
    window.addEventListener("pointerdown", close);
    return () => window.removeEventListener("pointerdown", close);
  }, [open, setOpen]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button className="ghost" onClick={() => setOpen(!open)}><Download size={15} /> {t.export}</button>
      {open && (
        <div className="menu-pop">
          {[["pdf", t.exportPdf], ["html", t.exportHtml], ["sarif", t.exportSarif], ["json", t.exportJson]].map(([fmt, label]) => (
            <button key={fmt} onClick={() => { setOpen(false); onExport(fmt); }}>{label}</button>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Project(props) {
  const { t, root, state, tab, setTab, runScan, settings, update, status, openFix, toast, exportOpen, setExportOpen, lang } = props;
  const result = state?.result;
  const [focusId, setFocusId] = useState(null);
  const ai = status?.ai;

  const exportReport = async (format) => {
    if (!state?.job) return;
    const saved = await window.armorix.saveReport({ url: api.reportUrl(state.job, format === "pdf" ? "html" : format, lang), format, name: `armorix-${basename(root)}` });
    if (saved) toast(t.saved(saved));
  };

  const showFinding = (fingerprint) => {
    setFocusId(fingerprint);
    setTab("findings");
  };

  return (
    <div className="page project">
      <header className="project-head">
        <div className="project-title">
          <h1>{basename(root)}</h1>
          <button className="path link-like" onClick={() => window.armorix.open(root)} title={t.openFolder}>
            <FolderOpen size={13} /> {root}
          </button>
        </div>
        <div className="head-actions">
          <button className={`toggle ${settings.watch ? "on" : ""}`} onClick={() => update({ watch: !settings.watch })} title={t.watchHint}>
            {settings.watch ? <Eye size={15} /> : <EyeOff size={15} />} {t.watch}
          </button>
          {result && <ExportMenu t={t} onExport={exportReport} open={exportOpen} setOpen={setExportOpen} />}
          <button className="ghost" disabled={state?.running} onClick={() => runScan(root, "deep")} title={t.deepHint}>
            <Radar size={15} /> {t.deep}
          </button>
          <button className="primary" disabled={state?.running} onClick={() => runScan(root, "scan")}>
            <RotateCw size={15} className={state?.running ? "spin" : ""} /> {t.scan}
          </button>
        </div>
      </header>

      {state?.running && !result ? (
        <ScanProgress t={t} state={state} onCancel={(id) => api.cancel(id)} />
      ) : !result ? (
        <div className="empty-state">
          <ShieldCheck size={42} strokeWidth={1.2} />
          <p>{state?.error ? `${t.failed}: ${state.error}` : t.notScanned}</p>
          <button className="primary" onClick={() => runScan(root)}>{t.scan}</button>
        </div>
      ) : (
        <>
          {state?.running && (
            <div className="rescan-banner">
              <span className="spinner" /> {t.phases[state.progress?.phase] || t.scanning}
              <span className="muted mono small ellipsis">{state.progress?.detail}</span>
              <button className="link" onClick={() => state.progress?.id && api.cancel(state.progress.id)}>{t.cancel}</button>
            </div>
          )}
          <div className="tabs" role="tablist">
            {[["overview", t.tabOverview], ["findings", `${t.tabFindings} · ${result.findings.length}`], ["history", t.tabHistory]].map(([id, label]) => (
              <button key={id} data-tab={id} role="tab" aria-selected={tab === id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>{label}</button>
            ))}
            {result.findings.some((f) => f.fixable && ["critical", "high"].includes(f.severity)) && (
              <button className="primary small tab-cta" disabled={!ai?.ready || state?.running}
                title={ai?.ready ? "" : t.aiNeeded}
                onClick={() => openFix(root, result.findings.filter((f) => f.fixable && ["critical", "high"].includes(f.severity)).slice(0, 8))}>
                <Sparkles size={14} /> {t.fixAll}
              </button>
            )}
          </div>
          {tab === "overview" && <Overview t={t} result={result} state={state} root={root} onShow={showFinding} setTab={setTab} toast={toast} runScan={runScan} />}
          {tab === "findings" && (
            <Findings t={t} result={result} root={root} focusId={focusId} setFocusId={setFocusId} aiReady={ai?.ready} openFix={openFix}
              toast={toast} runScan={runScan} newSet={new Set(result.history?.diff?.new || [])} />
          )}
          {tab === "history" && <History t={t} root={root} lang={lang} current={result.history?.id} />}
        </>
      )}
    </div>
  );
}
