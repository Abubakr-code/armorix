// Thin client for the local engine API (127.0.0.1, per-launch token).
let base = "";
let token = "";

export async function connect() {
  const info = await window.armorix.engine();
  base = `http://127.0.0.1:${info.port}`;
  token = info.token;
  return info;
}

async function call(method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: { "X-Armorix-Token": token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

export const api = {
  status: () => call("GET", "/status"),
  task: (text, path, lang) => call("POST", "/task", { text, path, lang }),
  job: (id) => call("GET", `/jobs/${id}`),
  start: (kind, params) => call("POST", "/jobs", { kind, ...params }),
  cancel: (id) => call("POST", `/jobs/${id}/cancel`),
  apply: (id, patches) => call("POST", `/jobs/${id}/apply`, { patches }),
  importModel: (file) => call("POST", "/ai/import", { file }),
  reportUrl: (id) => `${base}/report/${id}.html?token=${encodeURIComponent(token)}`,
};

export async function waitFor(id, onUpdate) {
  for (;;) {
    const view = await api.job(id);
    onUpdate(view);
    if (view.status !== "running") return view;
    await new Promise((r) => setTimeout(r, 400));
  }
}
