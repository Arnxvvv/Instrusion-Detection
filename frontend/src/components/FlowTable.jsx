import { SeverityChip } from "./Shell.jsx";
import { clock, fmt } from "../lib/api.js";

// Used by the live monitor and by the Analyze page: one row per classified flow.
export default function FlowTable({ rows, selectedId, onSelect, showTruth = false }) {
  return (
    <div className="tablewrap">
      <table className="flows">
        <thead>
          <tr>
            <th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Pkts</th><th>Verdict</th><th>Conf.</th>
            {showTruth && <th>Truth</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((e, i) => {
            const m = e.meta || {};
            const where = m.src_ip ? `${m.src_ip}:${m.src_port}` : m.row != null ? `row ${m.row}` : "sample";
            return (
              <tr key={e.event_id ?? i} className={`${selectedId === (e.event_id ?? i) ? "sel" : ""} ${e.is_attack ? "atk" : ""}`} onClick={() => onSelect?.(e, e.event_id ?? i)}>
                <td>{e.timestamp ? clock(e.timestamp) : "–"}</td>
                <td>{where}</td>
                <td>{m.dst_ip ? `${m.dst_ip}:${m.dst_port}` : "–"}</td>
                <td>{m.proto ?? "–"}</td>
                <td>{m.fwd_packets != null ? fmt(m.fwd_packets + m.bwd_packets) : "–"}</td>
                <td><SeverityChip event={e} /></td>
                <td>{(e.confidence * 100).toFixed(1)}%</td>
                {showTruth && (
                  <td className={m.true_label && m.true_label !== e.label ? "red" : "dim"}>
                    {m.true_label ?? "–"}{m.true_label && m.true_label !== e.label ? " ✕" : ""}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
      {rows.length === 0 && <div className="empty">Waiting for traffic…</div>}
    </div>
  );
}
