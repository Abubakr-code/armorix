// Read-only code viewer: highlight.js colours, line numbers, the finding's line and its taint path marked.
import { useEffect, useMemo, useRef } from "react";
import hljs from "highlight.js/lib/core";
import bash from "highlight.js/lib/languages/bash";
import c from "highlight.js/lib/languages/c";
import cpp from "highlight.js/lib/languages/cpp";
import dockerfile from "highlight.js/lib/languages/dockerfile";
import go from "highlight.js/lib/languages/go";
import ini from "highlight.js/lib/languages/ini";
import java from "highlight.js/lib/languages/java";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import php from "highlight.js/lib/languages/php";
import python from "highlight.js/lib/languages/python";
import typescript from "highlight.js/lib/languages/typescript";
import xml from "highlight.js/lib/languages/xml";
import yaml from "highlight.js/lib/languages/yaml";

Object.entries({ bash, c, cpp, dockerfile, go, ini, java, javascript, json, php, python, typescript, xml, yaml }).forEach(([n, l]) =>
  hljs.registerLanguage(n, l));

const MAX_LINES = 6000;

/** Highlighted HTML split into lines, re-opening spans that cross a line break. */
export function highlightLines(code, language) {
  let html;
  try {
    html = hljs.getLanguage(language) ? hljs.highlight(code, { language, ignoreIllegals: true }).value : escapeHtml(code);
  } catch {
    html = escapeHtml(code);
  }
  const out = [];
  let open = [];
  for (const raw of html.split("\n")) {
    const line = open.join("") + raw;
    const tags = raw.match(/<span[^>]*>|<\/span>/g) || [];
    for (const tag of tags) {
      if (tag === "</span>") open.pop();
      else open.push(tag);
    }
    out.push(line + "</span>".repeat(open.length));
  }
  return out;
}

export const escapeHtml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

export default function CodeView({ text, language, focus, marks = {}, height = 380 }) {
  const box = useRef(null);
  const lines = useMemo(() => {
    const all = text.split("\n");
    let start = 0;
    let body = text;
    if (all.length > MAX_LINES) {
      start = Math.max(0, (focus || 1) - 200);
      body = all.slice(start, start + 400).join("\n");
    }
    return { start, rows: highlightLines(body, language) };
  }, [text, language, focus]);

  useEffect(() => {
    const el = box.current?.querySelector(`[data-line="${focus}"]`);
    if (el && box.current) box.current.scrollTop = el.offsetTop - box.current.clientHeight / 2 + 12;
  }, [focus, lines]);

  return (
    <div className="code-view hljs" ref={box} style={{ maxHeight: height }}>
      {lines.rows.map((html, i) => {
        const n = lines.start + i + 1;
        const mark = marks[n];
        return (
          <div key={n} data-line={n} className={`code-line ${n === focus ? "focus" : ""} ${mark ? `mark ${mark.kind}` : ""}`}>
            <span className="ln">{n}</span>
            {mark && <span className={`code-tag ${mark.kind}`}>{mark.label}</span>}
            <code dangerouslySetInnerHTML={{ __html: html || " " }} />
          </div>
        );
      })}
    </div>
  );
}
