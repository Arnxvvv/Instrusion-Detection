import { useEffect, useRef } from "react";

// Wireframe tunnel from the reference: a rounded-square grid receding into the dark, drifting slowly forward.
export default function Tunnel() {
  const ref = useRef(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const RINGS = 30, SPOKES = 36, N = 4.2; // N: how square the cross-section is
    let w = 0, h = 0, raf, offset = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth; h = canvas.clientHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const point = (j, s) => {
      const a = (j / SPOKES) * Math.PI * 2, c = Math.cos(a), si = Math.sin(a);
      const x = Math.sign(c) * Math.abs(c) ** (2 / N), y = Math.sign(si) * Math.abs(si) ** (2 / N);
      return [w / 2 + x * w * 0.62 * s, h / 2 + y * h * 0.62 * s];
    };
    const depth = (i) => 1 / (1 + (((i + offset) % RINGS) / RINGS) * 9); // 1 = near, ~0.1 = far

    const draw = () => {
      ctx.clearRect(0, 0, w, h);
      const pts = [];
      for (let i = 0; i < RINGS; i++) {
        const s = depth(i);
        pts.push({ s, p: Array.from({ length: SPOKES }, (_, j) => point(j, s * 1.55)) });
      }
      pts.sort((a, b) => b.s - a.s);
      // spokes
      ctx.lineWidth = 1;
      for (let j = 0; j < SPOKES; j++) {
        for (let k = 0; k < pts.length - 1; k++) {
          const a = pts[k], b = pts[k + 1];
          ctx.strokeStyle = `rgba(241,230,232,${0.05 + 0.35 * b.s})`;
          ctx.beginPath(); ctx.moveTo(...a.p[j]); ctx.lineTo(...b.p[j]); ctx.stroke();
        }
      }
      // rings + dots
      for (const { s, p } of pts) {
        if (s < 0.13) continue;
        ctx.strokeStyle = `rgba(241,230,232,${0.08 + 0.5 * s})`;
        ctx.beginPath();
        p.forEach(([x, y], j) => (j ? ctx.lineTo(x, y) : ctx.moveTo(x, y)));
        ctx.closePath(); ctx.stroke();
        ctx.fillStyle = `rgba(241,230,232,${0.2 + 0.8 * s})`;
        const r = 0.8 + 1.7 * s;
        for (const [x, y] of p) { ctx.beginPath(); ctx.arc(x, y, r, 0, 6.2832); ctx.fill(); }
      }
      if (!still) { offset += 0.012; raf = requestAnimationFrame(draw); }
    };
    resize(); draw();
    window.addEventListener("resize", resize);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", resize); };
  }, []);
  return <div className="tunnel"><canvas ref={ref} /></div>;
}
