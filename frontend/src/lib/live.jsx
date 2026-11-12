import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

// One WebSocket for the whole app. Every page reads the same live state from here.
const LiveContext = createContext(null);
export const useLive = () => useContext(LiveContext);

const MAX_EVENTS = 300;
const wsUrl = () => `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/live/ws`;

export function LiveProvider({ children }) {
  const [state, setState] = useState({ connected: false, status: null, stats: null, timeline: [], events: [] });
  const [toasts, setToasts] = useState([]);
  const [osAlerts, setOsAlerts] = useState(false);
  const lastToast = useRef({});
  const osRef = useRef(false);
  osRef.current = osAlerts;

  const dismiss = useCallback((id) => setToasts((t) => t.filter((x) => x.id !== id)), []);

  const notify = useCallback((events) => {
    // Group a burst of attack flows into one alert per (class, source) so a flood doesn't spam the screen.
    const groups = {};
    for (const e of events) {
      if (!e.is_attack || !["high", "critical"].includes(e.severity)) continue;
      const key = `${e.label}|${e.meta?.src_ip}`;
      const g = (groups[key] ||= { label: e.label, severity: e.severity, count: 0, meta: e.meta });
      g.count++;
    }
    const now = Date.now();
    for (const [key, g] of Object.entries(groups)) {
      if (now - (lastToast.current[key] || 0) < 6000) continue;
      lastToast.current[key] = now;
      const toast = { id: now + key, ...g };
      setToasts((t) => [toast, ...t].slice(0, 4));
      setTimeout(() => dismiss(toast.id), 7000);
      if (osRef.current && g.severity === "critical" && "Notification" in window && Notification.permission === "granted") {
        new Notification(`CYBER ATTACK DETECTION SYSTEM: ${g.label} detected`, {
          body: `${g.meta?.src_ip ?? "?"} → ${g.meta?.dst_ip ?? "?"}:${g.meta?.dst_port ?? "?"}`,
        });
      }
    }
  }, [dismiss]);

  useEffect(() => {
    let ws, timer, closed = false, retry = 0;
    const connect = () => {
      ws = new WebSocket(wsUrl());
      ws.onopen = () => { retry = 0; };
      ws.onmessage = (e) => {
        const m = JSON.parse(e.data);
        if (m.type === "snapshot") {
          setState({ connected: true, status: m.status, stats: m.stats, timeline: m.timeline, events: m.events });
        } else if (m.type === "status") {
          setState((s) => ({ ...s, connected: true, status: m.status, stats: m.stats, timeline: m.timeline }));
        } else if (m.type === "flows") {
          setState((s) => ({ ...s, events: [...m.events.slice().reverse(), ...s.events].slice(0, MAX_EVENTS) }));
          notify(m.events);
        }
      };
      ws.onclose = () => {
        setState((s) => ({ ...s, connected: false }));
        if (!closed) timer = setTimeout(connect, Math.min(5000, 500 * 2 ** retry++));
      };
    };
    connect();
    return () => { closed = true; clearTimeout(timer); ws?.close(); };
  }, [notify]);

  const enableOsAlerts = async () => {
    if (!("Notification" in window)) return;
    if (osAlerts) return setOsAlerts(false);
    const perm = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
    setOsAlerts(perm === "granted");
  };

  return (
    <LiveContext.Provider value={{ ...state, toasts, dismiss, osAlerts, enableOsAlerts }}>
      {children}
    </LiveContext.Provider>
  );
}
