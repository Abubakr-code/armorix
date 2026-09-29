import { useEffect, useMemo, useRef, useState } from "react";
import { BellOff, Copy, ExternalLink, FileCode2, Search, Sparkles } from "lucide-react";

import { api } from "../api";
import CodeView from "../components/CodeView";
import { SEVERITIES, basename, cweUrl, joinPath, languageOf } from "../util";

function Detail({ t, f, root, aiReady, openFix, toast, runScan, isNew }) {
  const [file, setFile] = useState(null);
  const [error, setError] = useState(null);
  const [focus, setFocus] = useState(f.line);
  const full = joinPath(root, f.file);

  useEffect(() => {
    let alive = true;
    setFile(null);
    setError(null);
    setFocus(f.line);
    api.file(full).then((d) => alive && setFile(d.text)).catch((err) => alive && setError(err.message));
    return () => {
      alive = false;
    };
  }, [full, f.line]);

  const marks = useMemo(() => {
    const m = {};
    const steps = f.trace || [];
    steps.forEach((s, i) => {
      m[s.line] = { kind: i === 0 ? "source" : i === steps.length - 1 ? "sink" : "flow", label: s.label };
    });
    if (!steps.length) m[f.line] = { kind: "sink", label: "" };
    return m;
  }, [f]);

  const suppress = async () => {
    try {
      await api.suppress(full, f.line, f.rule);
      toast(t.suppressed);
      runScan(root, "scan", { quiet: true });
    } catch (err) {
      toast(`${t.failed}: ${err.message}`, "error");
    }
  };

  return (
    <div className="detail">
      <div className="detail-head">
        <div className="detail-badges">
          <span className={`sev ${f.severity}`}>{f.severity_label}</span>
          {isNew && <span className="chip bad">{t.newBadge}</span>}
          {f.ai && <span className="chip ai">{t.aiBadge}</span>}
          <span className="chip mono">{f.rule}</span>
          <button className="chip mono link-chip" onClick={() => window.armorix.open(cweUrl(f.cwe))}>{f.cwe} <ExternalLink size={11} /></button>
        </div>
        <h2>{f.title}</h2>
        <button className="loc link-like" onClick={() => window.armorix.openInEditor(full, f.line)} title={t.openInEditor}>
          <FileCode2 size={14} /> {f.file}:{f.line}
        </button>
      </div>

      <p className="detail-msg">{f.message}</p>

      {f.trace?.length > 0 && (
        <ol className="trace">
          {f.trace.map((s, i) => (
            <li key={i} className={i === 0 ? "source" : i === f.trace.length - 1 ? "sink" : "flow"}>
              <button onClick={() => setFocus(s.line)}>
                <span className="trace-label">{s.label}</span>
                <span className="ln mono">{s.line}</span>
                <code className="ellipsis">{s.code}</code>
              </button>
            </li>
          ))}
        </ol>
      )}

      {file != null ? (
        <CodeView text={file} language={languageOf(f.file)} focus={focus} marks={marks} height={360} />
      ) : error ? (
        <pre className="code-fallback"><span className="ln">{f.line}</span>{f.snippet}</pre>
      ) : (
        <div className="code-loading"><span className="spinner" /></div>
      )}

      <div className="fix-box">
        <b>{t.fixLabel}</b>
        <p>{f.fix}</p>
      </div>

      <div className="row-actions start">
        {f.fixable && (
          <button className="primary" disabled={!aiReady} title={aiReady ? t.fixHint : t.aiNeeded} onClick={() => openFix(root, [f])}>
            <Sparkles size={15} /> {t.fixWithAi}
          </button>
        )}
        <button className="ghost" onClick={() => window.armorix.openInEditor(full, f.line)}><FileCode2 size={15} /> {t.openInEditor}</button>
        <button className="ghost" onClick={suppress} title={t.suppressHint}><BellOff size={15} /> {t.suppress}</button>
        <button className="ghost" onClick={() => { navigator.clipboard.writeText(`${f.file}:${f.line} ${f.rule} ${f.title}`); toast(t.copied); }}>
          <Copy size={15} />
        </button>
      </div>
    </div>
  );
}

export default function Findings({ t, result, root, focusId, setFocusId, aiReady, openFix, toast, runScan, newSet }) {
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState(() => new Set(SEVERITIES));
  const [group, setGroup] = useState("severity");
  const [onlyNew, setOnlyNew] = useState(false);
  const search = useRef(null);

  useEffect(() => {
    const focusSearch = () => search.current?.focus();
    window.addEventListener("armorix:search", focusSearch);
    return () => window.removeEventListener("armorix:search", focusSearch);
  }, []);

  const list = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return result.findings.filter((f) => sev.has(f.severity) && (!onlyNew || newSet.has(f.fingerprint)) &&
      (!needle || `${f.title} ${f.message} ${f.file} ${f.rule} ${f.cwe}`.toLowerCase().includes(needle)));
  }, [result, query, sev, onlyNew, newSet]);

  const groups = useMemo(() => {
    if (group === "severity") return SEVERITIES.map((s) => [t.sev[s], list.filter((f) => f.severity === s)]).filter(([, v]) => v.length);
    const key = group === "file" ? (f) => f.file : (f) => `${f.title} · ${f.rule}`;
    const map = new Map();
    for (const f of list) map.set(key(f), [...(map.get(key(f)) || []), f]);
    return [...map.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [list, group, t]);

  const selected = list.find((f) => f.fingerprint === focusId) || list[0];

  useEffect(() => {
    const onKey = (e) => {
      if (e.target.tagName === "INPUT" || !list.length) return;
      const i = list.findIndex((f) => f.fingerprint === selected?.fingerprint);
      if (e.key === "ArrowDown" || e.key === "j") setFocusId(list[Math.min(list.length - 1, i + 1)].fingerprint);
      if (e.key === "ArrowUp" || e.key === "k") setFocusId(list[Math.max(0, i - 1)].fingerprint);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [list, selected, setFocusId]);

  useEffect(() => {
    document.querySelector(".finding-item.on")?.scrollIntoView({ block: "nearest" });
  }, [selected?.fingerprint]);

  const toggleSev = (s) => setSev((cur) => {
    const next = new Set(cur);
    if (next.has(s) && next.size > 1) next.delete(s);
    else next.add(s);
    return next;
  });

  if (!result.findings.length) {
    return <div className="empty-state"><p>{t.clean}</p></div>;
  }

  return (
    <div className="findings">
      <div className="findings-list">
        <div className="filters">
          <label className="search">
            <Search size={15} />
            <input ref={search} value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t.searchPlaceholder} />
          </label>
          <div className="sev-filter">
            {SEVERITIES.map((s) => (
              <button key={s} className={`pill ${s} ${sev.has(s) ? "" : "off"}`} onClick={() => toggleSev(s)} title={t.sev[s]}>
                {result.counts[s] || 0}
              </button>
            ))}
            {newSet.size > 0 && <button className={`chip ${onlyNew ? "bad" : ""}`} onClick={() => setOnlyNew(!onlyNew)}>{t.onlyNew}</button>}
          </div>
          <div className="group-by">
            <span className="muted small">{t.groupBy}</span>
            {[["severity", t.bySeverity], ["file", t.byFileShort], ["rule", t.byRuleShort]].map(([id, label]) => (
              <button key={id} className={group === id ? "on" : ""} onClick={() => setGroup(id)}>{label}</button>
            ))}
          </div>
        </div>
        <div className="finding-groups">
          {groups.map(([name, items]) => (
            <div key={name} className="finding-group">
              <p className="group-name"><span className="ellipsis">{name}</span><b>{items.length}</b></p>
              {items.map((f) => (
                <button key={f.fingerprint} className={`finding-item ${selected?.fingerprint === f.fingerprint ? "on" : ""}`} onClick={() => setFocusId(f.fingerprint)}>
                  <span className={`sev-dot ${f.severity}`} />
                  <span className="fi-text">
                    <b className="ellipsis">{f.title}</b>
                    <span className="ellipsis mono">{basename(f.file)}:{f.line}</span>
                  </span>
                  {newSet.has(f.fingerprint) && <span className="new-dot" title={t.newBadge} />}
                </button>
              ))}
            </div>
          ))}
          {!list.length && <p className="muted pad">{t.nothingMatches}</p>}
        </div>
      </div>
      {selected ? (
        <Detail key={selected.fingerprint} t={t} f={selected} root={root} aiReady={aiReady} openFix={openFix} toast={toast} runScan={runScan}
          isNew={newSet.has(selected.fingerprint)} />
      ) : <div className="detail empty-state"><p className="muted">{t.nothingMatches}</p></div>}
    </div>
  );
}
