import { useEffect, useState } from "react";
import { Frame } from "../components/Shell.jsx";
import { api, fmt, pct } from "../lib/api.js";

export default function Performance() {
  const [info, setInfo] = useState(null);
  const [err, setErr] = useState("");
  useEffect(() => { api("/model/info").then(setInfo).catch((e) => setErr(e.message)); }, []);
  const md = info?.metadata, m = md?.test_metrics;
  const classes = info?.classes ?? [];

  return (
    <Frame>
      <div className="page">
        <div className="pagehead">
          <h1 className="display">How good<br />is the model</h1>
          <p>Numbers from the held-out test split of CICIDS2017: flows the model never saw while training.</p>
        </div>
        {err && <div className="banner"><b>Error</b>{err}</div>}
        {m && (
          <>
            <section className="kpis">
              <div className="kpi"><span className="label dim">Accuracy</span><div className="v">{pct(m.accuracy, 2)}</div></div>
              <div className="kpi"><span className="label dim">Macro F1</span><div className="v">{m.macro_f1.toFixed(3)}</div></div>
              <div className="kpi"><span className="label dim">Test flows</span><div className="v">{fmt(md.split?.test)}</div></div>
              <div className="kpi"><span className="label dim">Features</span><div className="v">{md.n_features}</div></div>
            </section>
            <section className="grid2">
              <div className="cell">
                <div className="cell-head"><span className="label">Per class</span></div>
                <table className="plain">
                  <thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Test flows</th></tr></thead>
                  <tbody>
                    {classes.map((c) => { const r = m.per_class[c]; return (
                      <tr key={c}><td>{c}</td><td className="num">{pct(r.precision, 2)}</td><td className="num">{pct(r.recall, 2)}</td><td className="num">{r["f1-score"].toFixed(3)}</td><td className="num">{fmt(r.support)}</td></tr>
                    ); })}
                  </tbody>
                </table>
              </div>
              <div className="cell">
                <div className="cell-head"><span className="label">Model</span></div>
                <dl className="kv">
                  <dt>Algorithm</dt><dd>{md.model_name}</dd>
                  <dt>Trained</dt><dd>{new Date(md.trained_at).toLocaleDateString("en-GB")}</dd>
                  <dt>Train / val / test</dt><dd>{fmt(md.split.train)} / {fmt(md.split.validation)} / {fmt(md.split.test)}</dd>
                  {Object.entries(md.hyperparameters).filter(([k]) => k !== "verbose").map(([k, v]) => (<><dt key={`k${k}`}>{k}</dt><dd key={`v${k}`}>{String(v)}</dd></>))}
                </dl>
              </div>
            </section>
            <section className="grid2">
              <div className="cell">
                <div className="cell-head"><span className="label">Confusion matrix · rows are the truth</span></div>
                <div className="matrix" style={{ gridTemplateColumns: `100px repeat(${classes.length}, 1fr)` }}>
                  <div className="h" />
                  {classes.map((c) => <div className="h" key={c}>{c.slice(0, 7)}</div>)}
                  {m.confusion_matrix.matrix.map((row, i) => {
                    const sum = row.reduce((a, b) => a + b, 0) || 1;
                    return [<div className="h" key={`r${i}`} style={{ textAlign: "right", paddingRight: 8 }}>{classes[i]}</div>,
                      ...row.map((v, j) => (
                        <div key={`${i}-${j}`} style={{ background: v === 0 ? undefined : i === j ? `rgba(241,230,232,${0.2 + 0.7 * v / sum})` : `rgba(242,61,75,${0.45 + 0.55 * Math.min(1, v / sum * 8)})`, color: v && i === j && v / sum > 0.5 ? "#1b1919" : undefined }}>{v || "·"}</div>
                      ))];
                  })}
                </div>
              </div>
              <div className="cell">
                <div className="cell-head"><span className="label">Read this before trusting it</span></div>
                <div className="note">
                  <b>These scores are on CICIDS2017.</b> That dataset was recorded in a lab in 2017. On your own network, traffic looks different, so expect more false alarms and misses than the table suggests. CYBER ATTACK DETECTION SYSTEM rebuilds flows itself and copies CICFlowMeter's quirks, but it is not byte-identical. Use live results as a demonstration, not as a security control.
                </div>
              </div>
            </section>
            <section className="cell" style={{ borderBottom: 0, borderRight: 0 }}>
              <div className="cell-head"><span className="label">The {info.features.length} features the model reads</span></div>
              <div className="chips">{info.features.map((f) => <span className="tag mono" key={f}>{f}</span>)}</div>
            </section>
          </>
        )}
      </div>
    </Frame>
  );
}
