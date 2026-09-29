import { useCallback, useEffect, useRef, useState } from "react";
import { Download, FolderInput, RefreshCw, X } from "lucide-react";

import { api, connect, waitFor } from "./api";
import FixModal from "./components/FixModal";
import Sidebar from "./components/Sidebar";
import Toasts, { useToasts } from "./components/Toasts";
import { STRINGS } from "./i18n";
import { useResolvedTheme, useSettings } from "./settings";
import { basename } from "./util";
import Assistant from "./views/Assistant";
import Home from "./views/Home";
import Onboarding from "./views/Onboarding";
import Project from "./views/Project";
import Rules from "./views/Rules";
import Settings from "./views/Settings";

export default function App() {
  const [settings, update] = useSettings();
  const lang = settings.lang;
  const t = STRINGS[lang] || STRINGS.en;
  const theme = useResolvedTheme(settings.theme);
  const toasts = useToasts();
  const toast = toasts.push;

  const [engine, setEngine] = useState({ ready: false, error: null });
  const [status, setStatus] = useState(null);
  const [appInfo, setAppInfo] = useState(null);
  const [projects, setProjects] = useState([]);
  const [view, setView] = useState("home");
  const [tab, setTab] = useState("overview");
  const [current, setCurrent] = useState(null);
  const [scans, setScans] = useState({}); // root → { running, kind, job, result, progress, error }
  const [fix, setFix] = useState(null); // { root, findings }
  const [exportOpen, setExportOpen] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [updateInfo, setUpdateInfo] = useState(null);
  const [updating, setUpdating] = useState(null);
  const [chat, setChat] = useState([]);
  const [chatBusy, setChatBusy] = useState(false);
  const scansRef = useRef(scans);
  scansRef.current = scans;

  // ── engine & data ──────────────────────────────────────────
  const refreshStatus = useCallback(() => api.status().then(setStatus).catch(() => {}), []);
  const refreshProjects = useCallback(() => api.projects().then((d) => setProjects(d.projects)).catch(() => {}), []);

  const boot = useCallback(() => {
    setEngine({ ready: false, error: null });
    connect((error) => setEngine({ ready: false, error }))
      .then(() => {
        setEngine({ ready: true, error: null });
        refreshStatus();
        refreshProjects();
      })
      .catch(() => {});
  }, [refreshStatus, refreshProjects]);

  useEffect(() => {
    boot();
    window.armorix.appInfo().then(setAppInfo);
    return window.armorix.onEngine((info) => {
      if (info?.error) setEngine({ ready: false, error: info.error });
    });
  }, [boot]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.lang = lang;
  }, [theme, lang]);

  // ── scanning ───────────────────────────────────────────────
  const setScan = (root, patch) => setScans((s) => ({ ...s, [root]: { ...(s[root] || {}), ...patch } }));

  const notify = useCallback((title, body) => {
    if (!settings.notify || document.hasFocus()) return;
    try {
      new Notification(title, { body, silent: false });
      window.armorix.attention();
    } catch {
      /* notifications blocked */
    }
  }, [settings.notify]);

  const runScan = useCallback(async (root, kind = "scan", { quiet = false } = {}) => {
    if (!root || scansRef.current[root]?.running) return;
    setScan(root, { running: true, kind, progress: null, error: null });
    try {
      const { job } = await api.start(kind, { path: root, lang, disable: settings.disabled, include_tests: settings.includeTests });
      const final = await waitFor(job, (v) => setScan(root, { progress: v }), kind === "deep" ? 600 : 250);
      if (final.status === "done") {
        setScan(root, { running: false, kind, job, result: final.result, progress: null });
        refreshProjects();
        const n = final.result.findings.length;
        if (!quiet || final.result.history?.diff?.new?.length) {
          notify(`Armorix · ${basename(root)}`, n ? t.notifyFound(n, final.result.history?.grade) : t.clean);
        }
      } else {
        setScan(root, { running: false, progress: null, error: final.status === "error" ? final.error : null });
        if (final.status === "error") toast(`${t.failed}: ${final.error}`, "error");
      }
    } catch (err) {
      setScan(root, { running: false, progress: null, error: err.message });
      toast(`${t.failed}: ${err.message}`, "error");
    }
  }, [lang, settings.disabled, settings.includeTests, refreshProjects, notify, t, toast]);

  const openProject = useCallback((root, { keep = false } = {}) => {
    setCurrent(root);
    setView("project");
    if (!keep) setTab("overview");
    const known = scansRef.current[root];
    if (!known?.result && !known?.running) runScan(root);
  }, [runScan]);

  const adoptResult = useCallback((root, kind, job, result) => {
    setScan(root, { running: false, kind, job, result });
    setCurrent(root);
    refreshProjects();
  }, [refreshProjects]);

  const chooseFolder = useCallback(async () => {
    const dir = await window.armorix.chooseFolder();
    if (dir) openProject(dir);
  }, [openProject]);

  const forget = async (root) => {
    await api.forget(root).catch(() => {});
    if (root === current) {
      setCurrent(null);
      setView("home");
    }
    refreshProjects();
  };

  // Results are localised by the engine: re-read them (cheap, cached) when the language changes.
  const lastLang = useRef(lang);
  useEffect(() => {
    if (lastLang.current === lang) return;
    lastLang.current = lang;
    if (current && scansRef.current[current]?.result) runScan(current, scansRef.current[current].kind === "deep" ? "scan" : "scan", { quiet: true });
  }, [lang, current, runScan]);

  // ── watch mode ─────────────────────────────────────────────
  useEffect(() => {
    if (!settings.watch || !current) {
      window.armorix.unwatch();
      return undefined;
    }
    window.armorix.watch(current);
    const off = window.armorix.onFsChanged(({ root }) => {
      if (root === current) runScan(root, "scan", { quiet: true });
    });
    return () => {
      off();
      window.armorix.unwatch();
    };
  }, [settings.watch, current, runScan]);

  // ── updates (opt-in) ───────────────────────────────────────
  const checkUpdate = useCallback(async () => {
    setUpdating("check");
    const info = await window.armorix.checkUpdate();
    setUpdateInfo(info);
    setUpdating(null);
    return info;
  }, []);
  const installUpdate = async () => {
    setUpdating("install");
    const res = await window.armorix.installUpdate();
    if (res?.error) toast(`${t.failed}: ${res.error}`, "error");
    setUpdating(null);
  };
  useEffect(() => {
    if (settings.autoUpdate && settings.onboarded) checkUpdate();
  }, [settings.autoUpdate, settings.onboarded, checkUpdate]);
  const [updPct, setUpdPct] = useState(null);
  useEffect(() => window.armorix.onUpdateProgress(({ done, total }) => setUpdPct(total ? Math.round((done / total) * 100) : null)), []);

  // ── menu, open-path, drag & drop ───────────────────────────
  // Folders from the command line / a second launch / the smoke test wait until the engine is up.
  const [pendingOpen, setPendingOpen] = useState(null);
  useEffect(() => window.armorix.onOpenPath((dir) => setPendingOpen(dir)), []);
  useEffect(() => {
    if (engine.ready && pendingOpen) {
      openProject(pendingOpen);
      setPendingOpen(null);
    }
  }, [engine.ready, pendingOpen, openProject]);
  useEffect(() => window.armorix.onMenu((action) => {
    if (action === "open") chooseFolder();
    else if (action === "rescan" && current) runScan(current);
    else if (action === "deep" && current) runScan(current, "deep");
    else if (action === "export" && current) { setView("project"); setExportOpen(true); }
    else if (action === "settings") setView("settings");
    else if (action === "assistant" || action === "rules") setView(action);
    else if ((action === "findings" || action === "overview") && current) { setView("project"); setTab(action); }
    else if (action === "search" && current) { setView("project"); setTab("findings"); setTimeout(() => window.dispatchEvent(new Event("armorix:search")), 50); }
    else if (action === "theme") update((s) => ({ theme: (s.theme === "dark" || (s.theme === "system" && theme === "dark")) ? "light" : "dark" }));
    else if (action === "update") { setView("settings"); checkUpdate(); }
    else if (action === "about") setView("settings");
  }), [chooseFolder, current, runScan, update, theme, checkUpdate]);

  useEffect(() => {
    let depth = 0;
    const over = (e) => { if (e.dataTransfer?.types?.includes("Files")) e.preventDefault(); };
    const enter = (e) => { if (e.dataTransfer?.types?.includes("Files")) { depth += 1; setDragging(true); } };
    const leave = () => { depth = Math.max(0, depth - 1); if (!depth) setDragging(false); };
    const drop = (e) => {
      e.preventDefault();
      depth = 0;
      setDragging(false);
      const file = e.dataTransfer?.files?.[0];
      const dir = file && window.armorix.pathForFile(file);
      if (dir) openProject(dir);
    };
    window.addEventListener("dragover", over);
    window.addEventListener("dragenter", enter);
    window.addEventListener("dragleave", leave);
    window.addEventListener("drop", drop);
    return () => {
      window.removeEventListener("dragover", over);
      window.removeEventListener("dragenter", enter);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("drop", drop);
    };
  }, [openProject]);

  const state = current ? scans[current] : null;
  const version = appInfo?.version;

  return (
    <div className={`app ${dragging ? "dragging" : ""}`}>
      <Sidebar t={t} view={view} setView={setView} current={current} projects={projects} openProject={openProject}
        status={status} engine={engine} version={version} scans={scans} />

      <main className="main">
        {updateInfo?.available && view !== "settings" && (
          <div className="update-banner">
            <Download size={15} /> {t.updateAvailable(updateInfo.latest)}
            {updPct != null && <span className="mono small">{updPct}%</span>}
            <button className="primary small" disabled={Boolean(updating)} onClick={installUpdate}>
              {updateInfo.selfUpdate ? t.installUpdate : t.downloadUpdate}
            </button>
            <button className="icon-btn" onClick={() => setUpdateInfo(null)} aria-label={t.close}><X size={15} /></button>
          </div>
        )}
        {engine.error && (
          <div className="engine-error">
            <b>{t.engineDown}</b> <span className="mono small">{engine.error}</span>
            <button className="primary small" onClick={async () => { await window.armorix.restartEngine(); boot(); }}><RefreshCw size={14} /> {t.restart}</button>
          </div>
        )}

        {view === "home" && (
          <Home t={t} projects={projects} openProject={openProject} chooseFolder={chooseFolder} status={status} engine={engine}
            scans={scans} runScan={runScan} forget={forget} setView={setView} />
        )}
        {view === "project" && current && (
          <Project t={t} lang={lang} root={current} state={state} tab={tab} setTab={setTab} runScan={runScan} settings={settings} update={update}
            status={status} openFix={(root, findings) => setFix({ root, findings })} toast={toast} exportOpen={exportOpen} setExportOpen={setExportOpen} />
        )}
        {view === "assistant" && (
          <Assistant t={t} lang={lang} current={current} messages={chat} setMessages={setChat} busy={chatBusy} setBusy={setChatBusy}
            adoptResult={adoptResult} openProject={openProject} runScan={runScan} />
        )}
        {view === "rules" && <Rules t={t} lang={lang} settings={settings} update={update} engine={engine} />}
        {view === "settings" && (
          <Settings t={t} lang={lang} settings={settings} update={update} status={status} refreshStatus={refreshStatus} appInfo={appInfo}
            toast={toast} checkUpdate={checkUpdate} updateInfo={updateInfo} installUpdate={installUpdate} updating={updating} />
        )}
      </main>

      {fix && (
        <FixModal t={t} lang={lang} root={fix.root} findings={fix.findings} settings={settings} onClose={() => setFix(null)}
          onApplied={(res) => {
            setFix(null);
            toast(t.applied(res.applied, res.remaining));
            runScan(fix.root, "scan", { quiet: true });
          }} />
      )}

      {!settings.onboarded && engine.ready && (
        <Onboarding t={t} lang={lang} settings={settings} update={update} status={status} refreshStatus={refreshStatus}
          finish={() => update({ onboarded: true })} />
      )}

      {dragging && (
        <div className="drop-overlay">
          <FolderInput size={48} strokeWidth={1.3} />
          <p>{t.dropHere}</p>
        </div>
      )}
      <Toasts items={toasts.items} />
    </div>
  );
}
