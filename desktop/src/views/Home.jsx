import { ArrowRight, Cpu, Database, FolderPlus, ListChecks, RotateCw, Trash2 } from "lucide-react";

import ScoreRing from "../components/ScoreRing";
import ShieldCanvas from "../components/ShieldCanvas";
import { SEVERITIES, relativeTime } from "../util";

export default function Home({ t, projects, openProject, chooseFolder, status, engine, scans, runScan, forget, setView }) {
  const ai = status?.ai;
  const dbCount = status?.db?.advisories ? Object.values(status.db.advisories).reduce((a, b) => a + b, 0) : 0;
  return (
    <div className="page home">
      <section className="hero">
        <div className="hero-text">
          <p className="eyebrow"><i /> {t.heroBadge}</p>
          <h1>{t.heroTitle}</h1>
          <p className="lead">{t.heroLead}</p>
          <button className="drop" onClick={chooseFolder} disabled={!engine.ready}>
            <FolderPlus size={22} strokeWidth={1.6} />
            <span>
              <b>{t.chooseFolder}</b>
              <small>{t.dropHint}</small>
            </span>
            <kbd>{window.armorix?.platform === "darwin" ? "⌘O" : "Ctrl+O"}</kbd>
          </button>
        </div>
        <div className="hero-art">
          <ShieldCanvas size={340} />
        </div>
      </section>

      <section className="status-row">
        <button className="status-card" onClick={() => setView("settings")}>
          <Cpu size={18} />
          <div>
            <b>{t.aiEngine}</b>
            <span className={ai?.ready ? "ok-text" : "warn-text"}>{ai?.ready ? (ai.ollama ? `${t.aiReady} · Ollama` : t.aiReady) : t.aiMissing}</span>
          </div>
          <ArrowRight size={16} className="chev" />
        </button>
        <button className="status-card" onClick={() => setView("settings")}>
          <Database size={18} />
          <div>
            <b>{t.vulnDb}</b>
            <span className={dbCount ? "ok-text" : "warn-text"}>{dbCount ? t.dbCount(dbCount.toLocaleString()) : t.dbMissing}</span>
          </div>
          <ArrowRight size={16} className="chev" />
        </button>
        <button className="status-card" onClick={() => setView("rules")}>
          <ListChecks size={18} />
          <div>
            <b>{t.rulesTitle}</b>
            <span>{t.rulesCount(status?.rules || "…")}</span>
          </div>
          <ArrowRight size={16} className="chev" />
        </button>
      </section>

      {projects.length > 0 && (
        <section>
          <h2 className="section-title">{t.recentProjects}</h2>
          <div className="project-grid">
            {projects.map((p) => {
              const running = scans[p.root]?.running;
              const total = SEVERITIES.reduce((a, s) => a + (p.counts[s] || 0), 0);
              return (
                <div key={p.root} className={`project-card ${p.exists ? "" : "missing"}`}>
                  <button className="project-open" onClick={() => openProject(p.root)} disabled={!p.exists}>
                    <ScoreRing score={p.score} grade={p.grade} size={64} stroke={6} label={p.score} />
                    <div className="project-meta">
                      <b>{p.name}</b>
                      <span className="path" title={p.root}>{p.root}</span>
                      <span className="muted small">{running ? t.scanning : `${relativeTime(p.started, t)} · ${t.nFindings(total)}`}</span>
                    </div>
                  </button>
                  <div className="project-counts">
                    {SEVERITIES.map((s) => (
                      <span key={s} className={`pill ${s} ${p.counts[s] ? "" : "zero"}`}>{p.counts[s] || 0}</span>
                    ))}
                  </div>
                  <div className="project-actions">
                    <button className="icon-btn" title={t.rescan} disabled={running || !p.exists || !engine.ready} onClick={() => runScan(p.root)}>
                      <RotateCw size={15} className={running ? "spin" : ""} />
                    </button>
                    <button className="icon-btn" title={t.forget} onClick={() => forget(p.root)}>
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}
    </div>
  );
}
