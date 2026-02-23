import React, { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";

type Repo = { id: string; name: string; url: string; created_at: string };
type Finding = {
  id: string;
  tool: string;
  severity: string;
  title: string;
  file_path?: string;
  line_start?: number;
  description?: string;
};

type PRResponse = {
  mode: "dry-run" | "created";
  diff: string;
  pr_url?: string;
  branch?: string;
};

function useToken() {
  const [token, setToken] = useState(localStorage.getItem("argus_token") || "");
  useEffect(() => {
    localStorage.setItem("argus_token", token);
  }, [token]);
  return { token, setToken };
}

async function apiGet<T>(path: string, token: string): Promise<T> {
  const res = await fetch(API_BASE + path, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function apiPost<T>(path: string, token: string, body?: unknown): Promise<T> {
  const res = await fetch(API_BASE + path, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export default function App() {
  const { token, setToken } = useToken();
  const [repos, setRepos] = useState<Repo[]>([]);
  const [selected, setSelected] = useState<Repo | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [name, setName] = useState("");
  const [url, setURL] = useState("");
  const [status, setStatus] = useState("");
  const [prPreview, setPRPreview] = useState<PRResponse | null>(null);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    findings.forEach((f) => (c[f.severity] = (c[f.severity] || 0) + 1));
    return c;
  }, [findings]);

  const refreshRepos = async () => {
    const rs = await apiGet<Repo[]>("/api/repos", token);
    setRepos(rs);
  };

  const refreshFindings = async (repoID: string) => {
    const fs = await apiGet<Finding[]>(`/api/repos/${repoID}/findings`, token);
    setFindings(fs);
  };

  useEffect(() => {
    if (!token) return;
    refreshRepos().catch((e) => setStatus(String(e)));
  }, [token]);

  useEffect(() => {
    if (!token || !selected) return;
    refreshFindings(selected.id).catch((e) => setStatus(String(e)));
  }, [token, selected]);

  const addRepo = async () => {
    const res = await apiPost<{ id: string }>("/api/repos", token, { name, url });
    setName("");
    setURL("");
    setStatus(`Repo added: ${res.id}`);
    await refreshRepos();
  };

  const runScan = async () => {
    if (!selected) return;
    const res = await apiPost<{ job_id: string }>(`/api/repos/${selected.id}/scans`, token);
    setStatus(`Scan queued: ${res.job_id}`);
  };

  const loadSuggestions = async () => {
    if (!selected) return;
    const res = await apiPost(`/api/repos/${selected.id}/pr-suggestions`, token);
    console.log("PR suggestions:", res);
    setStatus("Suggestions generated. See browser console.");
  };

  const createPR = async (confirm: boolean) => {
    if (!selected) return;
    const res = await apiPost<PRResponse>(`/api/repos/${selected.id}/pull-requests`, token, {
      title: "Argus: Fix findings",
      confirm,
      max_fixes: 10,
    });
    setPRPreview(res);
    if (res.mode === "created") {
      setStatus(`PR created: ${res.pr_url}`);
    } else {
      setStatus("Dry-run patch preview generated.");
    }
  };

  const copyDiff = async () => {
    if (!prPreview?.diff) return;
    await navigator.clipboard.writeText(prPreview.diff);
    setStatus("Diff copied to clipboard.");
  };

  return (
    <div style={{ fontFamily: "system-ui", maxWidth: 1100, margin: "0 auto", padding: 20 }}>
      <h1 style={{ marginBottom: 8 }}>Argus</h1>
      <p style={{ marginTop: 0, color: "#555" }>Autonomous Repository Guardian & Security</p>

      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <input
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="SSAO_TOKEN"
          style={{ width: 420, padding: 10 }}
        />
        <button onClick={refreshRepos}>Refresh</button>
        {!!status && <span>{status}</span>}
      </div>

      <div style={{ marginTop: 18, display: "grid", gridTemplateColumns: "360px 1fr", gap: 18 }}>
        <div style={{ border: "1px solid #ddd", borderRadius: 10, padding: 12 }}>
          <h3>Repos</h3>
          {repos.map((r) => (
            <button
              key={r.id}
              onClick={() => setSelected(r)}
              style={{ display: "block", width: "100%", textAlign: "left", marginBottom: 8 }}
            >
              <strong>{r.name}</strong>
              <div style={{ fontSize: 12 }}>{r.url}</div>
            </button>
          ))}

          <h4>Add repo</h4>
          <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} style={{ width: "100%" }} />
          <input
            placeholder="https://github.com/org/repo.git"
            value={url}
            onChange={(e) => setURL(e.target.value)}
            style={{ width: "100%", marginTop: 8 }}
          />
          <button onClick={addRepo} style={{ marginTop: 8, width: "100%" }}>
            Register repo
          </button>
        </div>

        <div style={{ border: "1px solid #ddd", borderRadius: 10, padding: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <h3>Findings</h3>
            <div>
              <button disabled={!selected} onClick={runScan}>Run scan</button>
              <button disabled={!selected} onClick={loadSuggestions} style={{ marginLeft: 8 }}>PR suggestions</button>
              <button disabled={!selected} onClick={() => createPR(false)} style={{ marginLeft: 8 }}>Create PR (dry-run)</button>
              <button disabled={!selected} onClick={() => createPR(true)} style={{ marginLeft: 8 }}>Create PR (confirm)</button>
            </div>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {Object.entries(counts).map(([k, v]) => (
              <span key={k}>{k.toUpperCase()}: <b>{v}</b></span>
            ))}
          </div>

          {prPreview && (
            <div style={{ marginTop: 12, border: "1px solid #ccc", borderRadius: 8, padding: 10 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong>PR Preview ({prPreview.mode})</strong>
                <button onClick={copyDiff}>Copy diff</button>
              </div>
              {prPreview.pr_url && (
                <div style={{ marginTop: 8 }}>
                  PR URL: <a href={prPreview.pr_url} target="_blank" rel="noreferrer">{prPreview.pr_url}</a>
                </div>
              )}
              <pre style={{ maxHeight: 260, overflow: "auto", background: "#fafafa", padding: 8, marginTop: 8 }}>
                {prPreview.diff.length > 12000 ? prPreview.diff.slice(0, 12000) + "\n... (truncated)" : prPreview.diff}
              </pre>
            </div>
          )}

          {findings.map((f) => (
            <div key={f.id} style={{ borderTop: "1px solid #eee", marginTop: 10, paddingTop: 10 }}>
              <strong>{f.title}</strong>
              <div>{f.tool} / {f.severity}</div>
              {f.file_path && <div>{f.file_path}{f.line_start ? `:${f.line_start}` : ""}</div>}
              {f.description && <p>{f.description}</p>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
