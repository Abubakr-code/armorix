import { useMemo } from "react";
import { ArrowDownRight, ArrowUpRight, BadgeCheck, CheckCircle2, FileWarning, Layers, Minus, Sparkles } from "lucide-react";

import { api } from "../api";
import ScoreRing from "../components/ScoreRing";
import { SEVERITIES, basename, gradeOf, scoreOf } from "../util";

const FAMILY = { js: "JavaScript / TypeScript", py: "Python", c: "C / C++", php: "PHP", go: "Go", java: "Java" };

function Bars({ items, max, onPick }) {
  return (
    <ul className="bars">
      {items.map(([label, n, sev, key]) => (
        <li key={key || label}>
          <button onClick={() => onPick?.(key || label)} className="bar-row" title={label}>
            <span className="bar-label ellipsis">{label}</span>
            <span className="bar-track"><span className={`bar-fill ${sev || ""}`} style={{ width: `${Math.max(4, (n / max) * 100)}%` }} /></span>
            <b>{n}</b>
          </button>
        </li>
      ))}
    </ul>
  );
}

export default function Overview({ t, result, state, root, onShow, setTab, toast, runScan }) {
  const counts = result.counts;
  const score = result.history?.score ?? scoreOf(counts);
  const grade = result.history?.grade ?? gradeOf(score);
  const prev = result.history?.previous_score;
  const diff = result.history?.diff;

  const byRule = useMemo(() => {
    const map = new Map();
    for (const f of result.findings) {
      const cur = map.get(f.rule) || { n: 0, title: f.title, sev: f.severity, first: f.fingerprint };
      cur.n += 1;
      map.set(f.rule, cur);
    }
    return [...map.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, 7);
  }, [result]);

  const byFile = useMemo(() => {
    const map = new Map();
    for (const f of result.findings) map.set(f.file, (map.get(f.file) || 0) + 1);
    return [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 7);
  }, [result]);

  const top = result.findings.slice(0, 5);

  const makeBaseline = async () => {
    try {
      const res = await api.baseline(root);
      toast(t.baselineDone(res.count));
      runScan(root, "scan", { quiet: true });
    } catch (err) {
      toast(`${t.failed}: ${err.message}`, "error");
    }
  };

  return (
    <div className="overview">
      <div className="card score-card">
        <ScoreRing score={score} grade={grade} size={132} stroke={11} />
        <div className="score-text">
          <p className="eyebrow">{t.securityScore}</p>
          <h2>{score}<small>/100</small></h2>
          {prev != null && prev !== score && (
            <p className={`delta ${score > prev ? "up" : "down"}`}>
              {score > prev ? <ArrowUpRight size={15} /> : <ArrowDownRight size={15} />} {t.sinceLast(Math.abs(score - prev), score > prev)}
            </p>
          )}
          {prev != null && prev === score && <p className="delta flat"><Minus size={15} /> {t.noChange}</p>}
          {diff && !diff.first && (
            <div className="diff-chips">
              <span className={`chip ${diff.new.length ? "bad" : ""}`}>{t.newCount(diff.new.length)}</span>
              <span className={`chip ${diff.fixed ? "good" : ""}`}>{t.fixedCount(diff.fixed)}</span>
            </div>
          )}
          {diff?.first && <p className="muted small">{t.firstScan}</p>}
        </div>
      </div>

      <div className="sev-cards">
        {SEVERITIES.map((s) => (
          <button key={s} className={`card sev-card ${s}`} onClick={() => setTab("findings")}>
            <b>{counts[s] || 0}</b>
            <span>{t.sev[s]}</span>
          </button>
        ))}
      </div>

      <div className="card meta-card">
        <div><span className="muted">{t.files}</span><b>{result.files.toLocaleString()}</b></div>
        <div><span className="muted">{t.lines}</span><b>{result.lines.toLocaleString()}</b></div>
        <div><span className="muted">{t.packages}</span><b>{result.db ? result.dependencies.toLocaleString() : "—"}</b></div>
        <div><span className="muted">{t.time}</span><b>{result.seconds}s</b></div>
        <div className="langs-list">
          {Object.entries(result.languages || {}).map(([k, v]) => <span key={k} className="chip">{FAMILY[k] || k} · {v}</span>)}
          {result.cached > 0 && <span className="chip subtle" title={t.cacheHint}>{t.cached(result.cached)}</span>}
          {(result.suppressed > 0 || result.baselined > 0) && <span className="chip subtle">{t.hidden(result.baselined, result.suppressed)}</span>}
        </div>
      </div>

      {result.findings.length === 0 ? (
        <div className="card clean-card">
          <CheckCircle2 size={40} strokeWidth={1.4} />
          <div>
            <h3>{t.clean}</h3>
            <p className="muted">{t.cleanHint}</p>
          </div>
        </div>
      ) : (
        <>
          <div className="card">
            <h3 className="card-title"><FileWarning size={16} /> {t.topFindings}</h3>
            <ul className="top-list">
              {top.map((f) => (
                <li key={f.fingerprint}>
                  <button onClick={() => onShow(f.fingerprint)}>
                    <span className={`sev ${f.severity}`}>{f.severity_label}</span>
                    <span className="ellipsis grow">{f.title}</span>
                    <span className="f-loc">{basename(f.file)}:{f.line}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
          <div className="card">
            <h3 className="card-title"><Layers size={16} /> {t.byRule}</h3>
            <Bars items={byRule.map(([rule, v]) => [v.title, v.n, v.sev, v.first])} max={byRule[0]?.[1].n || 1} onPick={onShow} />
          </div>
          <div className="card">
            <h3 className="card-title"><FileWarning size={16} /> {t.byFile}</h3>
            <Bars items={byFile.map(([file, n]) => [file, n, "", result.findings.find((f) => f.file === file)?.fingerprint])} max={byFile[0]?.[1] || 1} onPick={onShow} />
          </div>
          <div className="card actions-card">
            <h3 className="card-title"><Sparkles size={16} /> {t.nextSteps}</h3>
            <p className="muted small">{t.nextStepsHint}</p>
            <div className="row-actions start">
              <button className="ghost" onClick={() => setTab("findings")}>{t.reviewFindings}</button>
              <button className="ghost" onClick={makeBaseline} title={t.baselineHint}><BadgeCheck size={15} /> {t.makeBaseline}</button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
