// Side-by-side view of a unified diff: original on the left, the AI patch on the right.
import { useMemo } from "react";

import { escapeHtml, highlightLines } from "./CodeView";

function parse(diff) {
  const rows = [];
  let left = 0;
  let right = 0;
  let dels = [];
  let adds = [];
  const flush = () => {
    const n = Math.max(dels.length, adds.length);
    for (let i = 0; i < n; i++) rows.push({ l: dels[i] || null, r: adds[i] || null });
    dels = [];
    adds = [];
  };
  for (const line of diff.split("\n")) {
    if (line.startsWith("---") || line.startsWith("+++")) continue;
    const hunk = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)/);
    if (hunk) {
      flush();
      left = Number(hunk[1]);
      right = Number(hunk[2]);
      rows.push({ hunk: line });
    } else if (line.startsWith("-")) {
      dels.push({ n: left++, text: line.slice(1), kind: "del" });
    } else if (line.startsWith("+")) {
      adds.push({ n: right++, text: line.slice(1), kind: "add" });
    } else if (line.length) {
      flush();
      const text = line.slice(1);
      rows.push({ l: { n: left++, text, kind: "ctx" }, r: { n: right++, text, kind: "ctx" } });
    }
  }
  flush();
  return rows;
}

function Cell({ cell, language }) {
  if (!cell) return <div className="diff-cell empty" />;
  const html = language ? highlightLines(cell.text, language)[0] : escapeHtml(cell.text);
  return (
    <div className={`diff-cell ${cell.kind}`}>
      <span className="ln">{cell.n}</span>
      <span className="sign">{cell.kind === "add" ? "+" : cell.kind === "del" ? "−" : " "}</span>
      <code dangerouslySetInnerHTML={{ __html: html || " " }} />
    </div>
  );
}

export default function DiffView({ diff, language, labels = ["", ""] }) {
  const rows = useMemo(() => parse(diff || ""), [diff]);
  return (
    <div className="diff-view hljs">
      <div className="diff-head">
        <span>{labels[0]}</span>
        <span>{labels[1]}</span>
      </div>
      {rows.map((row, i) =>
        row.hunk ? (
          <div key={i} className="diff-hunk">{row.hunk}</div>
        ) : (
          <div key={i} className="diff-row">
            <Cell cell={row.l} language={language} />
            <Cell cell={row.r} language={language} />
          </div>
        )
      )}
    </div>
  );
}
