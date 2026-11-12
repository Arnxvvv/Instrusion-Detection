import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Frame } from "../components/Shell.jsx";
import Tunnel from "../components/Tunnel.jsx";
import { api, fmt, pct } from "../lib/api.js";
import { useLive } from "../lib/live.jsx";

const PILLS = [
  { t: "BENIGN", l: 37, b: 14, r: -48, d: 0.1 },
  { t: "DoS", l: 41, b: 74, r: 44, d: 0.65, hot: true },
  { t: "CICFlowMeter", l: 49, b: 12, r: 6, d: 0.3 },
  { t: "DDoS", l: 52, b: 82, r: -14, d: 0.25, hot: true },
  { t: "PortScan", l: 60, b: 46, r: 12, d: 0.4, hot: true },
  { t: "LightGBM", l: 67, b: 10, r: -6, d: 0.35 },
  { t: "Brute Force", l: 68, b: 86, r: 4, d: 0.5, hot: true },
  { t: "Bot", l: 80, b: 60, r: -22, d: 0.6, hot: true },
  { t: "44 features", l: 82, b: 12, r: 3, d: 0.3 },
  { t: "Web Attack", l: 86, b: 92, r: 40, d: 0.55, hot: true },
];

function Burst({ n = 16 }) {
  const pts = Array.from({ length: n * 2 }, (_, i) => {
    const a = (i / (n * 2)) * Math.PI * 2, r = i % 2 ? 30 : 36;
    return `${36 + r * Math.cos(a)},${36 + r * Math.sin(a)}`;
  }).join(" ");
  return (
    <svg className="badge" viewBox="0 0 72 72" aria-hidden="true">
      <polygon points={pts} fill="none" stroke="#f23d4b" strokeWidth="2.5" strokeLinejoin="round" />
      <circle cx="36" cy="36" r="4" fill="#f1e6e8" />
    </svg>
  );
}

export default function Home() {
  const { stats, status } = useLive();
  const [info, setInfo] = useState(null);
  useEffect(() => { api("/model/info").then(setInfo).catch(() => {}); }, []);
  const m = info?.metadata?.test_metrics;
  const support = m?.per_class?.["macro avg"]?.support;

  return (
    <Frame toasts={false}>
      <main className="home-main">
        <section className="hero">
          <div className="headline">
            <div className="slash a" /><div className="slash b" />
            <h1 className="display">Catch<br />attacks<br />as they<br />happen</h1>
          </div>
          <p className="hero-copy">
            CYBER ATTACK DETECTION SYSTEM watches your network, rebuilds every connection into a flow and classifies it with a model trained on CICIDS2017. Open it and it starts on its own.
          </p>
          <div className="hero-cta">
            <Link to="/monitor" className="btn">Start monitoring</Link>
            <Link to="/monitor" className="watch"><span className="ring"><i /></span>Watch live feed</Link>
          </div>
          <div className="pile">
            {PILLS.map((p) => (
              <span key={p.t} className={`pill ${p.hot ? "hot" : ""}`} style={{ left: `${(p.l - 37) * 1.55}%`, bottom: p.b, "--r": `${p.r}deg`, "--d": `${p.d}s` }}>{p.t}</span>
            ))}
          </div>
        </section>
        <Tunnel />
      </main>
      <section className="strip">
        <div><div className="wordmarks"><span>CICIDS2017</span><span>LightGBM</span><span>FastAPI</span></div></div>
        <div>
          <div>
            <div className="bignum">{fmt(stats?.total_flows ?? 0)}</div>
            <div className="dim" style={{ marginTop: 6 }}>flows classified since start{status?.mode === "demo" ? " (demo feed)" : ""}</div>
          </div>
        </div>
        <div>
          <Burst />
          <div>
            {m ? (
              <>
                <b>{pct(m.accuracy, 2)}</b> accuracy on {fmt(support)} flows the model never saw.
                <div className="dim">Macro F1 {m.macro_f1.toFixed(3)} · 7 classes</div>
              </>
            ) : "Loading model metrics…"}
          </div>
        </div>
      </section>
    </Frame>
  );
}
