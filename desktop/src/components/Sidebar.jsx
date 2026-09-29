import { FolderOpen, Home, ListChecks, MessageSquareText, Settings as Gear } from "lucide-react";

import { basename, gradeColor } from "../util";

export function Logo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <rect width="64" height="64" rx="16" fill="var(--accent)" />
      <path d="M32 12 48 18v13c0 10.5-6.8 18.6-16 21.9C22.8 49.6 16 41.5 16 31V18z" fill="#fff" />
      <circle cx="32" cy="29" r="5" fill="var(--accent)" />
      <path d="M30 32h4l1.5 9h-7z" fill="var(--accent)" />
    </svg>
  );
}

export default function Sidebar({ t, view, setView, current, projects, openProject, status, engine, version, scans }) {
  const nav = [
    { id: "home", icon: Home, label: t.navHome },
    ...(current ? [{ id: "project", icon: FolderOpen, label: basename(current) }] : []),
    { id: "assistant", icon: MessageSquareText, label: t.navAssistant },
    { id: "rules", icon: ListChecks, label: t.navRules },
    { id: "settings", icon: Gear, label: t.navSettings },
  ];
  const ai = status?.ai;
  const dbCount = status?.db?.advisories ? Object.values(status.db.advisories).reduce((a, b) => a + b, 0) : 0;
  return (
    <aside className="side">
      <div className="brand">
        <Logo />
        <span>Armorix</span>
        <small>v{version || status?.version || "…"}</small>
      </div>

      <nav className="nav">
        {nav.map(({ id, icon: Icon, label }) => (
          <button key={id} className={view === id ? "on" : ""} onClick={() => setView(id)} title={label}>
            <Icon size={17} strokeWidth={1.8} />
            <span>{label}</span>
            {id === "project" && scans[current]?.running && <i className="dot-pulse" />}
          </button>
        ))}
      </nav>

      {projects.length > 0 && (
        <div className="recent">
          <p className="side-title">{t.recent}</p>
          {projects.slice(0, 6).map((p) => (
            <button key={p.root} className={`recent-item ${p.root === current ? "on" : ""}`} onClick={() => openProject(p.root)} title={p.root}>
              <span className="grade-dot" style={{ background: gradeColor(p.grade) }}>{p.grade}</span>
              <span className="recent-name">{p.name}</span>
              {scans[p.root]?.running && <i className="dot-pulse" />}
            </button>
          ))}
        </div>
      )}

      <div className="side-foot">
        <div className="engine-line">
          <i className={engine.ready ? "ok" : engine.error ? "bad" : "wait"} />
          <span>{engine.ready ? t.engineOn : engine.error ? t.engineDown : t.engineStarting}</span>
        </div>
        <div className="engine-line">
          <i className={ai?.ready ? "ok" : "warn"} />
          <span>{ai?.ready ? t.aiReadyShort : t.aiMissingShort}</span>
        </div>
        <div className="engine-line">
          <i className={dbCount ? "ok" : "warn"} />
          <span>{dbCount ? t.dbShort(dbCount.toLocaleString()) : t.dbMissingShort}</span>
        </div>
        <span className="offline"><i /> {t.offline}</span>
      </div>
    </aside>
  );
}
