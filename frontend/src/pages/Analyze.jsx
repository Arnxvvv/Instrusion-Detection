import { useState } from "react";
import { Frame } from "../components/Shell.jsx";
import FlowTable from "../components/FlowTable.jsx";
import { ClassBars } from "../components/Charts.jsx";
import { api, fmt, post, pct, upload } from "../lib/api.js";

const CLASSES = ["BENIGN", "DDoS", "DoS", "PortScan", "Brute Force", "Bot", "Web Attack"];

function Drop({ title, hint, accept, onFile, busy }) {
  const [over, setOver] = useState(false);
  return (
    <label className={`dropzone ${over ? "over" : ""}`}
      onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
      onDrop={(e) => { e.preventDefault(); setOver(false); e.dataTransfer.files[0] && onFile(e.dataTransfer.files[0]); }}>
      <input type="file" accept={accept} disabled={busy} onChange={(e) => e.target.files[0] && onFile(e.target.files[0])} />
      <b>{title}</b><span className="dim">{hint}</span>
    </label>
  );
}

function Matrix({ cm }) {
  const n = cm.labels.length;
  return (
    <div className="matrix" style={{ gridTemplateColumns: `90px repeat(${n}, 1fr)`, marginTop: 8 }}>
      <div className="h" />
      {cm.labels.map((l) => <div className="h" key={l}>{l.slice(0, 6)}</div>)}
      {cm.matrix.map((row, i) => {
        const sum = row.reduce((a, b) => a + b, 0) || 1;
        return [
          <div className="h" key={`r${i}`} style={{ textAlign: "right", paddingRight: 8 }}>{cm.labels[i]}</div>,
          ...row.map((v, j) => (
            <div key={`${i}-${j}`} style={{ background: v === 0 ? undefined : i === j ? `rgba(241,230,232,${0.15 + 0.75 * v / sum})` : `rgba(242,61,75,${0.35 + 0.65 * Math.min(1, v / sum * 6)})`, color: v && i === j && v / sum > 0.5 ? "#1b1919" : undefined }}>{v || ""}</div>
          )),
        ];
      })}
    </div>
  );
}

export default function Analyze() {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState(null);

  const run = async (fn) => {
    setBusy(true); setErr("");
    try { setRes(await fn()); } catch (e) { setErr(e.message); }
    setBusy(false);
  };

  const onPcap = (f) => run(async () => {
    const r = await upload("/live/analyze-pcap", f);
    return { title: r.filename, counts: r.predicted_counts, total: r.flows, attacks: r.attacks, rows: r.preview,
      note: `${fmt(r.capture.packets)} packets → ${fmt(r.flows)} flows (${fmt(r.capture.single_packet_flows_ignored)} one-packet flows ignored) in ${r.latency_ms} ms` };
  });

  const onCsv = (f) => run(async () => {
    const r = await upload("/predict/csv?return_predictions=true&max_rows=20000", f);
    const rows = [...r.predictions.filter((p) => p.is_attack), ...r.predictions.filter((p) => !p.is_attack)].slice(0, 300);
    return { title: f.name, counts: r.predicted_counts, total: r.rows, attacks: r.attacks, rows, evaluation: r.evaluation,
      note: `${fmt(r.rows)} flows scored in ${r.latency_ms} ms` };
  });

  const onSample = (label) => run(async () => {
    const { flows } = await api(`/sample?label=${encodeURIComponent(label)}&n=40`);
    const r = await post("/predict/batch", { flows });
    const counts = {};
    r.predictions.forEach((p) => (counts[p.label] = (counts[p.label] || 0) + 1));
    return { title: `40 held-out ${label} flows`, counts, total: r.count, attacks: r.attacks, rows: r.predictions, truth: true,
      note: `Real flows from the held-out test set — the model has never seen them. Scored in ${r.latency_ms} ms.` };
  });

  return (
    <Frame>
      <div className="page">
        <div className="pagehead">
          <h1 className="display">Analyze<br />a capture</h1>
          <p>Drop in a Wireshark capture and CYBER ATTACK DETECTION SYSTEM rebuilds its flows and classifies every one. Or upload a CICIDS CSV, or try real held-out flows.</p>
        </div>
        <section className="grid2" style={{ borderBottom: "1px solid var(--line)" }}>
          <div className="cell" style={{ display: "grid", gap: 16, gridTemplateColumns: "1fr 1fr" }}>
            <Drop title="Capture · .pcap / .pcapng" hint="up to 50 MB" accept=".pcap,.pcapng,.cap" onFile={onPcap} busy={busy} />
            <Drop title="Flows · .csv" hint="CICFlowMeter columns" accept=".csv" onFile={onCsv} busy={busy} />
          </div>
          <div className="cell">
            <span className="label dim">Or try held-out samples</span>
            <div className="chips" style={{ marginTop: 14 }}>
              {CLASSES.map((c) => <button key={c} disabled={busy} className={`tag ${c === "BENIGN" ? "" : "hot"}`} onClick={() => onSample(c)}>{c}</button>)}
            </div>
          </div>
        </section>
        {err && <div className="banner"><b>Error</b>{err}</div>}
        {busy && <div className="cell"><span className="label dim">Working…</span></div>}
        {res && !busy && (
          <>
            <section className="kpis" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
              <div className="kpi"><span className="label dim">Flows</span><div className="v">{fmt(res.total)}</div></div>
              <div className="kpi"><span className="label dim">Attacks flagged</span><div className={`v ${res.attacks ? "hot" : ""}`}>{fmt(res.attacks)}</div></div>
              <div className="kpi"><span className="label dim">Source</span><div className="v" style={{ fontSize: 22, wordBreak: "break-all" }}>{res.title}</div></div>
            </section>
            <section className="grid2" style={{ borderBottom: 0, flex: 1 }}>
              <div className="cell">
                <div className="cell-head"><span className="label">Flows · attacks first</span><span className="mono dim">{res.note}</span></div>
                <FlowTable rows={res.rows} showTruth={res.truth} />
              </div>
              <div className="cell">
                <div className="cell-head"><span className="label">By class</span></div>
                <ClassBars counts={res.counts} order={CLASSES} />
                {res.evaluation?.accuracy != null && (
                  <div style={{ marginTop: 28 }}>
                    <span className="label dim">Against the file's Label column</span>
                    <div className="bignum" style={{ marginTop: 10 }}>{pct(res.evaluation.accuracy, 2)}</div>
                    <div className="dim">accuracy · macro F1 {res.evaluation.macro_f1.toFixed(3)} · {fmt(res.evaluation.evaluated_rows)} rows</div>
                    <Matrix cm={res.evaluation.confusion_matrix} />
                  </div>
                )}
              </div>
            </section>
          </>
        )}
      </div>
    </Frame>
  );
}
