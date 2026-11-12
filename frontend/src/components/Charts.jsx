import { useEffect, useRef, useState } from "react";

// Stacked bars, one per second: benign (light) with attacks (red) on top. Plain SVG, no chart library.
export function Timeline({ data }) {
  const box = useRef(null);
  const [w, setW] = useState(800);
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setW(Math.max(300, Math.floor(e.contentRect.width))));
    ro.observe(box.current);
    return () => ro.disconnect();
  }, []);
  const H = 210, pad = 22;
  const max = Math.max(5, ...data.map((d) => d.benign + d.attack));
  const bw = w / Math.max(1, data.length);
  const y = (v) => H - pad - (v / max) * (H - pad - 16);
  return (
    <div ref={box}>
      <svg className="chart" viewBox={`0 0 ${w} ${H}`} role="img" aria-label="Flows per second">
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1="0" x2={w} y1={y(max * f)} y2={y(max * f)} stroke="rgba(241,230,232,.16)" />
            <text x="2" y={y(max * f) - 4} fill="rgba(241,230,232,.5)" fontSize="10" fontFamily="JetBrains Mono Variable, monospace">{Math.round(max * f)}</text>
          </g>
        ))}
        {data.map((d, i) => (
          <g key={d.t}>
            <rect x={i * bw + 1} y={y(d.benign)} width={Math.max(1, bw - 2)} height={H - pad - y(d.benign)} fill="#f1e6e8" opacity=".82" />
            <rect x={i * bw + 1} y={y(d.benign + d.attack)} width={Math.max(1, bw - 2)} height={y(d.benign) - y(d.benign + d.attack)} fill="#f23d4b" />
          </g>
        ))}
        <text x="2" y={H - 5} fill="rgba(241,230,232,.5)" fontSize="10" fontFamily="JetBrains Mono Variable, monospace">−{data.length}s</text>
        <text x={w - 2} y={H - 5} textAnchor="end" fill="rgba(241,230,232,.5)" fontSize="10" fontFamily="JetBrains Mono Variable, monospace">now</text>
      </svg>
    </div>
  );
}

export function ClassBars({ counts, order }) {
  const entries = (order || Object.keys(counts)).map((k) => [k, counts[k] || 0]);
  const max = Math.max(1, ...entries.map(([, v]) => v));
  return (
    <div className="bars">
      {entries.map(([k, v]) => (
        <div className="row" key={k}>
          <span>{k}</span>
          <div className="track"><div className={`fill ${k === "BENIGN" ? "" : "atk"}`} style={{ width: `${(v / max) * 100}%` }} /></div>
          <span className="n">{v.toLocaleString("en-US")}</span>
        </div>
      ))}
    </div>
  );
}

export function ProbBars({ probs }) {
  const entries = Object.entries(probs).sort((a, b) => b[1] - a[1]);
  return (
    <div className="bars">
      {entries.map(([k, v]) => (
        <div className="row" key={k}>
          <span>{k}</span>
          <div className="track"><div className={`fill ${k === "BENIGN" ? "" : "atk"}`} style={{ width: `${v * 100}%` }} /></div>
          <span className="n">{(v * 100).toFixed(1)}%</span>
        </div>
      ))}
    </div>
  );
}
