import { NavLink, Link, useNavigate } from "react-router-dom";
import { useLive } from "../lib/live.jsx";

export function LogoMark() {
  return (
    <svg viewBox="0 0 18 22" aria-hidden="true">
      <path d="M0 0h18v7h-7v-.01H7V7h4v7H7v-.01H0z" fill="#f23d4b" />
      <rect y="17" width="7" height="5" fill="#f1e6e8" />
    </svg>
  );
}

export function sourceLabel(status, connected) {
  if (!connected || !status) return "CONNECTING";
  if (status.mode === "live") return "LIVE · YOUR NETWORK";
  if (status.mode === "pcap") return "REPLAY · CAPTURE FILE";
  if (status.mode === "demo") return "DEMO · HELD-OUT FLOWS";
  return "IDLE";
}

export function Nav() {
  const { status, connected } = useLive();
  const navigate = useNavigate();
  const on = connected && status?.running;
  return (
    <header className="nav">
      <Link to="/" className="logo"><LogoMark />CYBER ATTACK DETECTION SYSTEM</Link>
      <nav className="nav-links">
        <NavLink to="/monitor" className="link">Monitor</NavLink>
        <NavLink to="/analyze" className="link">Analyze</NavLink>
        <NavLink to="/performance" className="link">Performance</NavLink>
        <span className="livechip mono"><i className={`dot ${on ? "on" : ""}`} />{sourceLabel(status, connected)}</span>
        <button className="btn sm" onClick={() => navigate("/monitor")}>Open console ↗</button>
      </nav>
    </header>
  );
}

export function Toasts() {
  const { toasts, dismiss } = useLive();
  const navigate = useNavigate();
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div key={t.id} className="toast" onClick={() => { dismiss(t.id); navigate("/monitor"); }}>
          <b>{t.label}</b> <span className="chip critical" style={t.severity === "critical" ? {} : { background: "none", color: "var(--red)" }}>{t.severity}</span>
          <div className="mono dim" style={{ marginTop: 6 }}>
            {t.count} flow{t.count > 1 ? "s" : ""} · {t.meta?.src_ip} → {t.meta?.dst_ip}:{t.meta?.dst_port}
          </div>
        </div>
      ))}
    </div>
  );
}

export function Frame({ children, toasts = true }) {
  return (
    <div className="frame">
      <Nav />
      {children}
      {toasts && <Toasts />}
    </div>
  );
}

export function SeverityChip({ event }) {
  if (!event.is_attack) return <span className="chip ok">benign</span>;
  return <span className={`chip ${event.severity}`}>{event.label}</span>;
}
