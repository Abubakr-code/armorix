export const SEVERITIES = ["critical", "high", "medium", "low"];
export const RANK = { critical: 4, high: 3, medium: 2, low: 1 };
export const UNFIXABLE = /^(ARX-DEP|ARX-SECRET-HISTORY|ARX-NOAUTH)$/;

export const basename = (p) => String(p || "").split(/[/\\]/).filter(Boolean).pop() || p;
export const joinPath = (root, rel) => `${String(root).replace(/[/\\]+$/, "")}${root.includes("\\") ? "\\" : "/"}${rel}`;

export function gradeColor(grade) {
  return { A: "var(--ok)", B: "var(--accent-2)", C: "var(--med)", D: "var(--high)", F: "var(--crit)" }[grade] || "var(--muted)";
}

export function scoreOf(counts) {
  const w = { critical: 40, high: 12, medium: 3, low: 1 };
  const penalty = Object.entries(w).reduce((a, [k, v]) => a + v * (counts?.[k] || 0), 0);
  return Math.round(100 * Math.exp(-penalty / 60));
}

export function gradeOf(score) {
  return score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
}

export function relativeTime(ts, t) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return t.justNow;
  if (s < 3600) return t.minutesAgo(Math.floor(s / 60));
  if (s < 86400) return t.hoursAgo(Math.floor(s / 3600));
  return t.daysAgo(Math.floor(s / 86400));
}

const MONTHS = {
  uz: ["yan", "fev", "mar", "apr", "may", "iyun", "iyul", "avg", "sen", "okt", "noy", "dek"],
  ru: ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"],
  en: ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
};

export function formatDate(ts, lang) {
  const d = new Date(ts * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getDate()} ${(MONTHS[lang] || MONTHS.en)[d.getMonth()]}, ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

const LANGUAGE_BY_EXT = {
  js: "javascript", mjs: "javascript", cjs: "javascript", jsx: "javascript", ts: "typescript", mts: "typescript", cts: "typescript",
  tsx: "typescript", py: "python", c: "c", h: "cpp", cc: "cpp", cpp: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp", json: "json",
  yml: "yaml", yaml: "yaml", toml: "ini", ini: "ini", cfg: "ini", conf: "ini", properties: "ini", sh: "bash", xml: "xml", tf: "ini",
  go: "go", java: "java", php: "php", env: "bash",
};

export function languageOf(file) {
  const name = basename(file).toLowerCase();
  if (name.startsWith("dockerfile") || name.endsWith(".dockerfile")) return "dockerfile";
  if (name.startsWith(".env")) return "bash";
  return LANGUAGE_BY_EXT[name.split(".").pop()] || "plaintext";
}

export const cweUrl = (cwe) => `https://cwe.mitre.org/data/definitions/${String(cwe).replace("CWE-", "")}.html`;

export function ruleGroup(id) {
  if (id.startsWith("ARX-C-")) return "memory";
  if (/^ARX-(GHA|DOCKER|CONTAINER|TF)/.test(id)) return "infra";
  if (id === "ARX-DEP") return "deps";
  if (/^ARX-(SECRET|SIGNKEY)/.test(id)) return "secrets";
  if (/^ARX-(JWT|CORS|TLS|DEBUG|WEAKHASH|COOKIE|RANDOM|PERMS|TMPFILE|CSRF|AUTOESCAPE)/.test(id)) return "config";
  return "injection";
}

export function plural(n, forms) {
  return `${n} ${forms}`;
}
