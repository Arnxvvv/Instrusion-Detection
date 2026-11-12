import { useEffect, useMemo, useState } from "react";
import { Frame, SeverityChip } from "../components/Shell.jsx";
import FlowTable from "../components/FlowTable.jsx";
import { ClassBars, ProbBars, Timeline } from "../components/Charts.jsx";
import { api, bytes, fmt, micros, post } from "../lib/api.js";
import { useLive } from "../lib/live.jsx";

const CLASSES = ["BENIGN", "DDoS", "DoS", "PortScan", "Brute Force", "Bot", "Web Attack"];

function SourceBar() {
  const { status, osAlerts, enableOsAlerts } = useLive();
  const [ifaces, setIfaces] = useState([]);
  const [iface, setIface] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    api("/live/interfaces").then((r) => {
      setIfaces(r.interfaces);
      setIface(r.interfaces.find((i) => i.default)?.id ?? r.interfaces[0]?.id ?? "");
    }).catch(() => {});
  }, []);

  const switchTo = async (mode) => {
    setBusy(true); setErr("");
    try {
      const s = await post("/live/source", { mode, iface: mode === "live" ? iface || null : null });
      if (s.error && mode !== "demo") setErr(s.error);
    } catch (e) { setErr(e.message); }
    setBusy(false);
  };

  const mode = status?.mode;
  return (
    <>
      <div className="sourcebar">
        <span className="label dim">Source</span>
        <div className="seg">
          {[["live", "Live network"], ["pcap", "Capture file"], ["demo", "Demo flows"]].map(([m, name]) => (
            <button key={m} className={mode === m ? "on" : ""} disabled={busy} onClick={() => switchTo(m)}>{name}</button>
          ))}
        </div>
        {ifaces.length > 0 && (
          <select className="sel" value={iface} onChange={(e) => setIface(e.target.value)} title="Interface used when you pick Live network">
            {ifaces.map((i) => <option key={i.id} value={i.id}>{i.name}{i.ip ? ` (${i.ip})` : ""}</option>)}
          </select>
        )}
        <span className="mono dim">{status?.detail}</span>
        <span style={{ flex: 1 }} />
        <button className={`btn sm ${osAlerts ? "" : "ghost"}`} onClick={enableOsAlerts}>Desktop alerts {osAlerts ? "on" : "off"}</button>
      </div>
      {((status?.fallback && status?.error) || err) && (
        <div className="banner">
          <b>{status?.fallback ? "Live capture unavailable — showing demo flows" : "Could not switch"}</b>
          {(err || status.error).slice(0, 220)}
          <div className="dim" style={{ marginTop: 4, fontSize: 13 }}>
            Live capture needs Npcap (Windows) or libpcap, and the server must run as Administrator / root.
          </div>
        </div>
      )}
      {mode === "live" && status?.packets === 0 && status.uptime_s > 6 && (
        <div className="banner"><b>No packets yet</b>Check that the selected interface is the one carrying your traffic.</div>
      )}
    </>
  );
}

function Detail({ event }) {
  if (!event) return <div className="empty">Select a flow to see why the model decided what it did.</div>;
  const m = event.meta || {};
  return (
    <div className="detail">
      <span className="label dim">Selected flow</span>
      <h3 className={`display ${event.is_attack ? "red" : ""}`}>{event.label}</h3>
      <div><SeverityChip event={event} /> <span className="mono dim">{(event.confidence * 100).toFixed(2)}% confident</span></div>
      <dl className="kv">
        <dt>Source</dt><dd>{m.src_ip}:{m.src_port}</dd>
        <dt>Destination</dt><dd>{m.dst_ip}:{m.dst_port}</dd>
        <dt>Protocol</dt><dd>{m.proto}</dd>
        <dt>Packets</dt><dd>{m.fwd_packets} forward · {m.bwd_packets} back</dd>
        <dt>Payload</dt><dd>{bytes(m.bytes ?? 0)}</dd>
        <dt>Duration</dt><dd>{micros(m.duration_us ?? 0)}</dd>
        {m.true_label && (<><dt>Ground truth</dt><dd>{m.true_label}</dd></>)}
        {event.imputed_values > 0 && (<><dt>Filled values</dt><dd>{event.imputed_values} unknown feature(s)</dd></>)}
      </dl>
      <span className="label dim">Class probabilities</span>
      <div style={{ marginTop: 12 }}><ProbBars probs={event.probabilities} /></div>
    </div>
  );
}

export default function Monitor() {
  const { stats, status, timeline, events } = useLive();
  const [onlyAttacks, setOnlyAttacks] = useState(false);
  const [selected, setSelected] = useState(null);
  const total = stats?.total_flows ?? 0;
  const attacks = stats?.attack_flows ?? 0;
  const rows = useMemo(() => (onlyAttacks ? events.filter((e) => e.is_attack) : events).slice(0, 120), [events, onlyAttacks]);
  const demo = status?.mode === "demo";

  return (
    <Frame>
      <div className="page">
        <SourceBar />
        <section className="kpis">
          <div className="kpi"><span className="label dim">Flows classified</span><div className="v">{fmt(total)}</div></div>
          <div className="kpi"><span className="label dim">Attacks flagged</span><div className={`v ${attacks ? "hot" : ""}`}>{fmt(attacks)}</div></div>
          <div className="kpi"><span className="label dim">Attack share</span><div className="v">{total ? ((attacks / total) * 100).toFixed(1) : "0.0"}%</div></div>
          <div className="kpi"><span className="label dim">Flows / second</span><div className="v">{status?.flows_per_s ?? 0}</div></div>
        </section>
        <section className="grid2">
          <div className="cell">
            <div className="cell-head">
              <span className="label">Traffic · last 90 s</span>
              <span className="legend label dim"><span><i />Benign</span><span><i className="r" />Attack</span></span>
            </div>
            <Timeline data={timeline} />
          </div>
          <div className="cell">
            <div className="cell-head"><span className="label">By class</span></div>
            <ClassBars counts={stats?.by_label ?? {}} order={CLASSES} />
          </div>
        </section>
        <section className="grid2" style={{ flex: 1, borderBottom: 0 }}>
          <div className="cell">
            <div className="cell-head">
              <span className="label">Live flows</span>
              <button className={`btn sm ${onlyAttacks ? "" : "ghost"}`} onClick={() => setOnlyAttacks((v) => !v)}>Attacks only</button>
            </div>
            <FlowTable rows={rows} selectedId={selected?.event_id} onSelect={setSelected} showTruth={demo} />
            {!demo && (
              <p className="mono dim" style={{ marginTop: 14 }}>
                {fmt(status?.packets)} packets seen · {fmt(status?.open_flows)} open flows · {fmt(status?.single_packet_ignored)} one-packet flows ignored
              </p>
            )}
          </div>
          <div className="cell"><Detail event={selected} /></div>
        </section>
      </div>
    </Frame>
  );
}
