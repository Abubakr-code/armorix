import { useEffect, useState } from "react";

import { api } from "../api";
import { SEVERITIES, formatDate, gradeColor } from "../util";

function Chart({ scans }) {
  const pts = [...scans].reverse();
  if (pts.length < 2) return null;
  const w = 720;
  const h = 160;
  const pad = 24;
  const x = (i) => pad + (i / (pts.length - 1)) * (w - pad * 2);
  const y = (v) => pad + (1 - v / 100) * (h - pad * 2);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.score).toFixed(1)}`).join(" ");
  const area = `${line} L${x(pts.length - 1)},${h - pad} L${x(0)},${h - pad} Z`;
  return (
    <svg className="chart" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" aria-hidden="true">
      {[0, 50, 100].map((v) => <line key={v} x1={pad} x2={w - pad} y1={y(v)} y2={y(v)} className="grid" />)}
      <path d={area} className="area" />
      <path d={line} className="line" />
      {pts.map((p, i) => <circle key={p.id} cx={x(i)} cy={y(p.score)} r="4" fill={gradeColor(p.grade)} />)}
    </svg>
  );
}

export default function History({ t, root, lang, current }) {
  const [scans, setScans] = useState(null);
  useEffect(() => {
    api.history(root).then((d) => setScans(d.scans)).catch(() => setScans([]));
  }, [root, current]);
  if (!scans) return <div className="code-loading"><span className="spinner" /></div>;
  return (
    <div className="history">
      <div className="card">
        <h3 className="card-title">{t.scoreTrend}</h3>
        {scans.length > 1 ? <Chart scans={scans} /> : <p className="muted small">{t.trendHint}</p>}
      </div>
      <div className="card">
        <table className="table">
          <thead>
            <tr>
              <th>{t.when}</th><th>{t.kind}</th><th>{t.securityScore}</th>
              {SEVERITIES.map((s) => <th key={s}>{t.sev[s]}</th>)}
              <th>{t.files}</th><th>{t.time}</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className={s.id === current ? "on" : ""}>
                <td>{formatDate(s.started, lang)}</td>
                <td>{s.kind === "deep" ? t.deep : t.scan}</td>
                <td><b style={{ color: gradeColor(s.grade) }}>{s.grade}</b> · {s.score}</td>
                {SEVERITIES.map((sev) => <td key={sev}><span className={`pill ${sev} ${s.counts[sev] ? "" : "zero"}`}>{s.counts[sev] || 0}</span></td>)}
                <td>{s.files}</td>
                <td>{s.seconds}s</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
