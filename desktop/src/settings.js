// Per-user preferences, kept in localStorage (the engine stays stateless apart from scan history).
import { useCallback, useEffect, useState } from "react";

const KEY = "armorix_settings";
export const DEFAULTS = {
  lang: "uz",
  theme: "system", // system | dark | light
  includeTests: false,
  disabled: [], // rule ids turned off
  watch: false, // re-scan when files change
  notify: true, // OS notification when a long scan finishes
  autoUpdate: false, // opt-in: ask GitHub for the latest version on start
  onboarded: false,
  recentOpen: true,
};

function read() {
  try {
    const legacyLang = localStorage.getItem("armorix_lang");
    const saved = JSON.parse(localStorage.getItem(KEY) || "{}");
    return { ...DEFAULTS, ...(legacyLang ? { lang: legacyLang } : {}), ...saved };
  } catch {
    return { ...DEFAULTS };
  }
}

export function useSettings() {
  const [settings, setSettings] = useState(read);
  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(settings));
    } catch {
      /* private storage */
    }
  }, [settings]);
  const update = useCallback((patch) => setSettings((s) => ({ ...s, ...(typeof patch === "function" ? patch(s) : patch) })), []);
  return [settings, update];
}

/** "dark" | "light" after resolving "system". */
export function useResolvedTheme(theme) {
  const query = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  const [systemDark, setSystemDark] = useState(query ? query.matches : true);
  useEffect(() => {
    if (!query) return undefined;
    const listener = (e) => setSystemDark(e.matches);
    query.addEventListener("change", listener);
    return () => query.removeEventListener("change", listener);
  }, [query]);
  return theme === "system" ? (systemDark ? "dark" : "light") : theme;
}
