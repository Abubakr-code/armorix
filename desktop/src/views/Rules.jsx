import { useEffect, useMemo, useState } from "react";
import { ExternalLink, Search } from "lucide-react";

import { api } from "../api";
import { cweUrl, ruleGroup } from "../util";

const ORDER = ["injection", "secrets", "config", "memory", "infra", "deps"];

export default function Rules({ t, lang, settings, update, engine }) {
  const [rules, setRules] = useState(null);
  const [query, setQuery] = useState("");
  useEffect(() => {
    if (engine.ready) api.rules(lang).then((d) => setRules(d.rules)).catch(() => setRules([]));
  }, [lang, engine.ready]);

  const disabled = new Set(settings.disabled);
  const toggle = (id) => update((s) => ({ disabled: disabled.has(id) ? s.disabled.filter((x) => x !== id) : [...s.disabled, id] }));

  const groups = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const list = (rules || []).filter((r) => !needle || `${r.id} ${r.cwe} ${r.title} ${r.description}`.toLowerCase().includes(needle));
    return ORDER.map((g) => [g, list.filter((r) => ruleGroup(r.id) === g)]).filter(([, v]) => v.length);
  }, [rules, query]);

  return (
    <div className="page rules">
      <header className="page-head">
        <div>
          <h1>{t.rulesTitle}</h1>
          <p className="muted">{t.rulesLead(rules?.length || "…", settings.disabled.length)}</p>
        </div>
        <label className="search wide">
          <Search size={15} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t.rulesSearch} />
        </label>
      </header>
      {!rules ? <div className="code-loading"><span className="spinner" /></div> : groups.map(([g, list]) => (
        <section key={g} className="rule-group">
          <h2 className="section-title">{t.ruleGroups[g]} <span className="muted">{list.length}</span></h2>
          <div className="rule-list">
            {list.map((r) => (
              <div key={r.id} className={`rule ${disabled.has(r.id) ? "off" : ""}`}>
                <div className="rule-main">
                  <div className="rule-top">
                    <b>{r.title}</b>
                    <span className="chip mono">{r.id}</span>
                    <button className="chip mono link-chip" onClick={() => window.armorix.open(cweUrl(r.cwe))}>{r.cwe} <ExternalLink size={11} /></button>
                  </div>
                  <p className="muted small">{r.description}</p>
                </div>
                <button role="switch" aria-checked={!disabled.has(r.id)} className={`switch ${disabled.has(r.id) ? "" : "on"}`} onClick={() => toggle(r.id)}
                  title={disabled.has(r.id) ? t.ruleOff : t.ruleOn}>
                  <i />
                </button>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
