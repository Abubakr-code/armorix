import { useState } from "react";
import { Cpu, Database, Download, FolderOpen, Globe, Info, Palette, RefreshCw, ScanSearch, Trash2, Upload } from "lucide-react";

import { api, waitFor } from "../api";

function Row({ title, hint, children }) {
  return (
    <div className="set-row">
      <div className="set-text">
        <b>{title}</b>
        {hint && <p className="muted small">{hint}</p>}
      </div>
      <div className="set-control">{children}</div>
    </div>
  );
}

function Switch({ on, onChange, label }) {
  return <button role="switch" aria-checked={on} aria-label={label} className={`switch ${on ? "on" : ""}`} onClick={() => onChange(!on)}><i /></button>;
}

function Segmented({ value, options, onChange }) {
  return (
    <div className="segmented">
      {options.map(([v, label]) => <button key={v} className={value === v ? "on" : ""} onClick={() => onChange(v)}>{label}</button>)}
    </div>
  );
}

export function useJob(onDone) {
  const [view, setView] = useState(null);
  const run = async (kind, params = {}) => {
    const { job } = await api.start(kind, params);
    const final = await waitFor(job, setView, 400);
    setView(final);
    onDone?.(final);
    return final;
  };
  return [view, run];
}

export function Progress({ t, view }) {
  if (!view) return null;
  if (view.status === "error") return <p className="error-text small">{t.failed}: {view.error}</p>;
  if (view.status !== "running") return null;
  const pct = view.total ? Math.round((view.done / view.total) * 100) : null;
  return (
    <div className="inline-progress">
      <div className="bar"><span style={{ width: pct == null ? "30%" : `${pct}%` }} className={pct == null ? "indeterminate" : ""} /></div>
      <span className="muted small mono">{pct != null ? `${pct}% · ${(view.done / 1e6).toFixed(0)} / ${(view.total / 1e6).toFixed(0)} MB` : view.detail}</span>
    </div>
  );
}

export default function Settings({ t, lang, settings, update, status, refreshStatus, appInfo, toast, checkUpdate, updateInfo, installUpdate, updating }) {
  const [aiJob, runAi] = useJob(refreshStatus);
  const [dbJob, runDb] = useJob(refreshStatus);
  const ai = status?.ai;
  const db = status?.db;
  const dbCount = db?.advisories ? Object.values(db.advisories).reduce((a, b) => a + b, 0) : 0;
  const busyAi = aiJob?.status === "running";
  const busyDb = dbJob?.status === "running";

  const importModel = async () => {
    const file = await window.armorix.chooseModel();
    if (!file) return;
    try {
      await api.importModel(file);
      refreshStatus();
      toast(t.setupDone);
    } catch (err) {
      toast(`${t.failed}: ${err.message}`, "error");
    }
  };

  const importDb = async () => {
    const dir = await window.armorix.chooseFolder();
    if (dir) runDb("db-update", { from_dir: dir, lang }).then((v) => v.status === "done" && toast(t.dbDone));
  };

  return (
    <div className="page settings">
      <header className="page-head"><h1>{t.navSettings}</h1></header>

      <section className="card set-card">
        <h2 className="card-title"><Palette size={16} /> {t.setGeneral}</h2>
        <Row title={t.setLanguage}>
          <Segmented value={settings.lang} onChange={(v) => update({ lang: v })} options={[["uz", "O'zbekcha"], ["ru", "Русский"], ["en", "English"]]} />
        </Row>
        <Row title={t.setTheme}>
          <Segmented value={settings.theme} onChange={(v) => update({ theme: v })} options={[["system", t.themeSystem], ["dark", t.themeDark], ["light", t.themeLight]]} />
        </Row>
      </section>

      <section className="card set-card">
        <h2 className="card-title"><ScanSearch size={16} /> {t.setScan}</h2>
        <Row title={t.setTests} hint={t.setTestsHint}><Switch on={settings.includeTests} onChange={(v) => update({ includeTests: v })} label={t.setTests} /></Row>
        <Row title={t.watch} hint={t.watchHint}><Switch on={settings.watch} onChange={(v) => update({ watch: v })} label={t.watch} /></Row>
        <Row title={t.setNotify} hint={t.setNotifyHint}><Switch on={settings.notify} onChange={(v) => update({ notify: v })} label={t.setNotify} /></Row>
        <Row title={t.setCache} hint={t.setCacheHint}>
          <button className="ghost" onClick={async () => { await api.clearCache(); toast(t.cacheCleared); }}><Trash2 size={15} /> {t.clear}</button>
        </Row>
      </section>

      <section className="card set-card">
        <h2 className="card-title"><Cpu size={16} /> {t.aiEngine}</h2>
        <Row title={ai?.ready ? t.aiReady : t.aiMissing} hint={ai?.ready ? (ai.ollama ? t.aiViaOllama : t.aiBundled) : t.aiNote}>
          <span className={`status-dot ${ai?.ready ? "ok" : "warn"}`} />
        </Row>
        {!ai?.ready && (
          <Row title={t.aiDownloadTitle} hint={t.aiDownloadHint}>
            <div className="btn-col">
              <button className="primary" disabled={busyAi} onClick={() => runAi("ai-setup", { lang }).then((v) => v.status === "done" && toast(t.setupDone))}>
                <Download size={15} /> {t.aiSetup}
              </button>
              <button className="ghost" disabled={busyAi} onClick={importModel}><Upload size={15} /> {t.aiImport}</button>
            </div>
          </Row>
        )}
        <Progress t={t} view={aiJob} />
      </section>

      <section className="card set-card">
        <h2 className="card-title"><Database size={16} /> {t.vulnDb}</h2>
        <Row title={dbCount ? t.dbCount(dbCount.toLocaleString()) : t.dbMissing}
          hint={db?.updated ? t.dbUpdated(new Date(db.updated).toLocaleDateString()) : t.dbHint}>
          <div className="btn-col">
            <button className="ghost" disabled={busyDb} onClick={() => runDb("db-update", { lang }).then((v) => v.status === "done" && toast(t.dbDone))}>
              <RefreshCw size={15} className={busyDb ? "spin" : ""} /> {t.dbUpdate}
            </button>
            <button className="ghost" disabled={busyDb} onClick={importDb} title={t.dbImportHint}><FolderOpen size={15} /> {t.dbImport}</button>
          </div>
        </Row>
        {busyDb && <p className="muted small mono">{dbJob.detail}</p>}
        <Progress t={t} view={dbJob?.status === "error" ? dbJob : null} />
      </section>

      <section className="card set-card">
        <h2 className="card-title"><Globe size={16} /> {t.setUpdates}</h2>
        <Row title={t.setAutoUpdate} hint={t.setAutoUpdateHint}>
          <Switch on={settings.autoUpdate} onChange={(v) => update({ autoUpdate: v })} label={t.setAutoUpdate} />
        </Row>
        <Row title={updateInfo?.available ? t.updateAvailable(updateInfo.latest) : updateInfo?.error ? `${t.failed}: ${updateInfo.error}` : updateInfo ? t.upToDate : t.checkUpdates}
          hint={t.updateHint}>
          <div className="btn-col">
            <button className="ghost" onClick={checkUpdate} disabled={updating}><RefreshCw size={15} /> {t.checkNow}</button>
            {updateInfo?.available && (
              <button className="primary" onClick={installUpdate} disabled={updating}><Download size={15} /> {updateInfo.selfUpdate ? t.installUpdate : t.downloadUpdate}</button>
            )}
          </div>
        </Row>
      </section>

      <section className="card set-card">
        <h2 className="card-title"><Info size={16} /> {t.about}</h2>
        <Row title={`Armorix ${appInfo?.version || status?.version || ""}`} hint={t.aboutHint}>
          <div className="btn-col">
            <button className="ghost" onClick={() => window.armorix.open("https://abubakr-code.github.io")}>{t.website}</button>
            <button className="ghost" onClick={() => window.armorix.open("https://github.com/Abubakr-code/armorix")}>GitHub</button>
          </div>
        </Row>
        {status?.data_dir && (
          <Row title={t.dataDir} hint={status.data_dir}>
            <button className="ghost" onClick={() => window.armorix.open(status.data_dir)}><FolderOpen size={15} /> {t.open}</button>
          </Row>
        )}
      </section>
    </div>
  );
}
