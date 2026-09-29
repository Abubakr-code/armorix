// First run: language → local AI → vulnerability database → updates. Every download is optional.
import { useState } from "react";
import { ArrowRight, Check, Cpu, Database, Download, FolderOpen, Globe, Upload } from "lucide-react";

import { api } from "../api";
import { Logo } from "../components/Sidebar";
import ShieldCanvas from "../components/ShieldCanvas";
import { Progress, useJob } from "./Settings";

export default function Onboarding({ t, lang, settings, update, status, refreshStatus, finish }) {
  const [step, setStep] = useState(0);
  const [aiJob, runAi] = useJob(refreshStatus);
  const [dbJob, runDb] = useJob(refreshStatus);
  const ai = status?.ai;
  const dbCount = status?.db?.advisories ? Object.values(status.db.advisories).reduce((a, b) => a + b, 0) : 0;
  const steps = [t.obLanguage, t.aiEngine, t.vulnDb, t.setUpdates];
  const next = () => (step < steps.length - 1 ? setStep(step + 1) : finish());

  const importModel = async () => {
    const file = await window.armorix.chooseModel();
    if (file) {
      await api.importModel(file).catch(() => {});
      refreshStatus();
    }
  };

  return (
    <div className="modal-backdrop onboarding">
      <div className="modal ob">
        <div className="ob-art">
          <ShieldCanvas size={220} />
          <div className="ob-brand"><Logo size={26} /> Armorix</div>
          <ol className="ob-steps">
            {steps.map((s, i) => <li key={s} className={i === step ? "on" : i < step ? "done" : ""}>{i < step ? <Check size={13} /> : i + 1}. {s}</li>)}
          </ol>
        </div>
        <div className="ob-body">
          {step === 0 && (
            <>
              <h2>{t.obWelcome}</h2>
              <p className="muted">{t.obWelcomeLead}</p>
              <div className="lang-cards">
                {[["uz", "O'zbekcha"], ["ru", "Русский"], ["en", "English"]].map(([code, label]) => (
                  <button key={code} className={settings.lang === code ? "on" : ""} onClick={() => update({ lang: code })}>
                    <b>{label}</b><span className="mono">{code.toUpperCase()}</span>
                  </button>
                ))}
              </div>
            </>
          )}
          {step === 1 && (
            <>
              <h2><Cpu size={20} /> {t.aiEngine}</h2>
              <p className="muted">{t.obAiLead}</p>
              {ai?.ready ? (
                <div className="notice ok"><Check size={16} /> {ai.ollama ? t.aiViaOllama : t.aiReady}</div>
              ) : (
                <div className="btn-col">
                  <button className="primary" disabled={aiJob?.status === "running"} onClick={() => runAi("ai-setup", { lang })}><Download size={15} /> {t.aiSetup}</button>
                  <button className="ghost" disabled={aiJob?.status === "running"} onClick={importModel}><Upload size={15} /> {t.aiImport}</button>
                </div>
              )}
              <Progress t={t} view={aiJob} />
              <p className="muted small">{t.aiNote}</p>
            </>
          )}
          {step === 2 && (
            <>
              <h2><Database size={20} /> {t.vulnDb}</h2>
              <p className="muted">{t.obDbLead}</p>
              {dbCount ? (
                <div className="notice ok"><Check size={16} /> {t.dbCount(dbCount.toLocaleString())}</div>
              ) : (
                <div className="btn-col">
                  <button className="primary" disabled={dbJob?.status === "running"} onClick={() => runDb("db-update", { lang })}><Download size={15} /> {t.dbDownload}</button>
                  <button className="ghost" disabled={dbJob?.status === "running"} onClick={async () => { const dir = await window.armorix.chooseFolder(); if (dir) runDb("db-update", { from_dir: dir, lang }); }}>
                    <FolderOpen size={15} /> {t.dbImport}
                  </button>
                </div>
              )}
              {dbJob?.status === "running" && <p className="muted small mono">{dbJob.detail}</p>}
              <Progress t={t} view={dbJob?.status === "error" ? dbJob : null} />
            </>
          )}
          {step === 3 && (
            <>
              <h2><Globe size={20} /> {t.setUpdates}</h2>
              <p className="muted">{t.obUpdatesLead}</p>
              <label className="check-row">
                <input type="checkbox" checked={settings.autoUpdate} onChange={(e) => update({ autoUpdate: e.target.checked })} />
                <span>{t.setAutoUpdate}</span>
              </label>
              <p className="muted small">{t.setAutoUpdateHint}</p>
            </>
          )}
          <div className="ob-foot">
            {step > 0 && <button className="ghost" onClick={() => setStep(step - 1)}>{t.back}</button>}
            <span className="grow" />
            {step > 0 && step < 3 && <button className="link" onClick={next}>{t.later}</button>}
            <button className="primary" onClick={next}>{step === steps.length - 1 ? t.start : t.next} <ArrowRight size={15} /></button>
          </div>
        </div>
      </div>
    </div>
  );
}
