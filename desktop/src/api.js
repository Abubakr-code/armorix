// Thin client for the local engine API (127.0.0.1, per-launch token).
let base = "";
let token = "";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Waits until the engine has started (the window opens before it is ready). */
export async function connect(onError) {
  for (;;) {
    const info = await window.armorix.engine();
    if (info?.port) {
      base = `http://127.0.0.1:${info.port}`;
      token = info.token;
      return info;
    }
    if (info?.error) {
      onError?.(info.error);
      throw new Error(info.error);
    }
    await sleep(250);
  }
}

async function call(method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: { "X-Armorix-Token": token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

const q = encodeURIComponent;

export const api = {
  status: () => call("GET", "/status"),
  task: (text, path, lang) => call("POST", "/task", { text, path, lang }),
  job: (id) => call("GET", `/jobs/${id}`),
  start: (kind, params) => call("POST", "/jobs", { kind, ...params }),
  cancel: (id) => call("POST", `/jobs/${id}/cancel`),
  apply: (id, patches) => call("POST", `/jobs/${id}/apply`, { patches }),
  importModel: (file) => call("POST", "/ai/import", { file }),
  projects: () => call("GET", "/projects"),
  history: (root) => call("GET", `/history?root=${q(root)}`),
  scan: (id, lang) => call("GET", `/scans/${id}?lang=${lang}`),
  rules: (lang) => call("GET", `/rules?lang=${lang}`),
  file: (path) => call("GET", `/file?path=${q(path)}`),
  suppress: (path, line, rule) => call("POST", "/suppress", { path, line, rule }),
  baseline: (root) => call("POST", "/baseline", { root }),
  forget: (root) => call("POST", "/projects/forget", { root }),
  clearCache: () => call("POST", "/cache/clear"),
  reportUrl: (id, format = "html", lang = "en") => `${base}/report/${id}.${format}?token=${q(token)}&lang=${lang}`,
};

export async function waitFor(id, onUpdate, interval = 300) {
  for (;;) {
    const view = await api.job(id);
    onUpdate?.(view);
    if (view.status !== "running") return view;
    await sleep(interval);
  }
}
