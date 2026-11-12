// One tiny fetch helper: throws an Error with the server's own message when a request fails.
export async function api(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail?.message || body.detail || detail;
      if (body.missing_features) detail += ` (${body.missing_features.slice(0, 3).join(", ")}…)`;
    } catch {}
    throw new Error(detail);
  }
  return res.json();
}

export const post = (url, body) =>
  api(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export const upload = (url, file) => {
  const form = new FormData();
  form.append("file", file);
  return api(url, { method: "POST", body: form });
};

export const fmt = (n) => (n == null ? "–" : Number(n).toLocaleString("en-US"));
export const pct = (x, d = 1) => (x == null ? "–" : `${(x * 100).toFixed(d)}%`);
export const clock = (iso) => (iso ? new Date(iso).toLocaleTimeString("en-GB") : "");
export const bytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
export const micros = (us) => (us < 1000 ? `${us} µs` : us < 1e6 ? `${(us / 1000).toFixed(1)} ms` : `${(us / 1e6).toFixed(1)} s`);
