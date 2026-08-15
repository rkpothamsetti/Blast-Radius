import { ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import "./openai.css";

type Node = { id: string; type: string; label: string; sensitivity?: number; pii?: boolean; environment?: string };
type Edge = { from: string; to: string; relation: string };
type Graph = { nodes: Node[]; edges: Edge[] };
type Recommendation = { edge_index: number; from_label: string; to_label: string; relation: string };
type Simulation = { reachable_node_ids: string[]; impact_score: number; verdict: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; critical_paths: { target_label: string; path: string[] }[]; recommendations: Recommendation[] };
type Analysis = { verdict: string; justification: string; attacker_steps: string[] };

const api = "/api/v1";
const layers = [
  { title: "Identity", caption: "01 · WHO HAS ACCESS", types: ["employee", "identity_group"] },
  { title: "Access surface", caption: "02 · PATHS IN", types: ["application", "credential"] },
  { title: "Sensitive assets", caption: "03 · IMPACT ZONE", types: ["resource", "cloud_resource"] },
];

function tags(node: Node) {
  return [node.type.replace("_", " "), node.pii ? "PII" : "", node.environment ?? "", node.sensitivity ? `risk ${node.sensitivity}/10` : ""].filter(Boolean);
}

export default function App() {
  const [graph, setGraph] = useState<Graph | null>(null);
  const [employee, setEmployee] = useState("");
  const [simulation, setSimulation] = useState<Simulation | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [revoked, setRevoked] = useState<number[]>([]);
  const [message, setMessage] = useState("Upload an access graph to start an assessment.");
  const [busy, setBusy] = useState(false);
  const [openaiConfigured, setOpenaiConfigured] = useState<boolean | null>(null);
  const [openaiModalOpen, setOpenaiModalOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const modalRef = useRef<HTMLDivElement | null>(null);
  const closeBtnRef = useRef<HTMLButtonElement | null>(null);
  const bannerRef = useRef<HTMLDivElement | null>(null);
  const [bannerVisible, setBannerVisible] = useState<boolean>(openaiConfigured === false);
  const [bannerHiding, setBannerHiding] = useState<boolean>(false);

  useEffect(() => {
    let mounted = true;
    async function check() {
      try {
        const res = await fetch(api.replace('/api/v1', '') + '/health');
        const body = await res.json();
        if (!mounted) return;
        setOpenaiConfigured(Boolean(body?.openai_configured === 'true' || body?.openai_configured === true));
      } catch (_) {
        if (!mounted) return;
        setOpenaiConfigured(false);
      }
    }
    void check();
    return () => { mounted = false; };

    // Show/hide banner with exit animation when openaiConfigured changes
    useEffect(() => {
      if (openaiConfigured === false) {
        setBannerHiding(false);
        setBannerVisible(true);
      } else if (bannerVisible) {
        setBannerHiding(true);
        const t = setTimeout(() => { setBannerVisible(false); setBannerHiding(false); }, 320);
        return () => clearTimeout(t);
      }
    }, [openaiConfigured]);

    // Modal focus trap and ESC-to-close
    useEffect(() => {
      if (!openaiModalOpen) return;
      const modal = modalRef.current;
      const onKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') { setOpenaiModalOpen(false); }
        if (e.key === 'Tab' && modal) {
          const focusable = Array.from(modal.querySelectorAll<HTMLElement>("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])")).filter((el) => !el.hasAttribute('disabled'));
          if (focusable.length === 0) return;
          const first = focusable[0];
          const last = focusable[focusable.length - 1];
          if (e.shiftKey) {
            if (document.activeElement === first) { e.preventDefault(); last.focus(); }
          } else {
            if (document.activeElement === last) { e.preventDefault(); first.focus(); }
          }
        }
      };
      document.addEventListener('keydown', onKeyDown);
      // focus the close button initially
      setTimeout(() => { closeBtnRef.current?.focus(); }, 0);
      return () => document.removeEventListener('keydown', onKeyDown);
    }, [openaiModalOpen]);
  }, []);
  const employees = useMemo(() => graph?.nodes.filter((node) => node.type === "employee") ?? [], [graph]);
  const reached = new Set(simulation?.reachable_node_ids ?? []);

  async function upload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as Graph;
      if (!Array.isArray(parsed.nodes) || !Array.isArray(parsed.edges)) throw new Error("Expected a JSON object with nodes and edges arrays.");
      setGraph(parsed); setEmployee(parsed.nodes.find((node) => node.type === "employee")?.id ?? ""); setSimulation(null); setAnalysis(null); setRevoked([]);
      setMessage(`Graph loaded · ${parsed.nodes.length} entities · ${parsed.edges.length} relationships`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Could not read the uploaded graph."); }
  }

  async function run(nextRevoked = revoked) {
    if (!graph || !employee) return;
    if (openaiConfigured === false) { setMessage("OpenAI not configured. Add OPENAI_API_KEY to enable analysis."); return; }
    setBusy(true); setAnalysis(null); setMessage("Mapping access paths and exposure…");
    try {
      const simulationResponse = await fetch(`${api}/simulate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ graph, employee_id: employee, revoked_edges: nextRevoked }) });
      const simulationBody = await simulationResponse.json() as Simulation | { detail?: string };
      if (!simulationResponse.ok) throw new Error("detail" in simulationBody ? simulationBody.detail : "Simulation failed.");
      setSimulation(simulationBody as Simulation); setMessage("OpenAI is reviewing calculated exposure…");
      const analysisResponse = await fetch(`${api}/analyze`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ graph, simulation: simulationBody }) });
      const analysisBody = await analysisResponse.json() as Analysis | { detail?: string };
      if (!analysisResponse.ok) throw new Error("detail" in analysisBody ? analysisBody.detail : "OpenAI analysis failed.");
      setAnalysis(analysisBody as Analysis); setMessage("Assessment complete · analyst review ready.");
    } catch (error) { setMessage(error instanceof Error ? error.message : "Request failed."); }
    finally { setBusy(false); }
  }

  function toggle(edgeIndex: number) {
    const next = revoked.includes(edgeIndex) ? revoked.filter((value) => value !== edgeIndex) : [...revoked, edgeIndex];
    setRevoked(next); void run(next);
  }

  return <main className="shell">
    <header className="topbar"><a className="brand" href="#top"><b>BR</b> BLAST<span>RADIUS</span></a><p><i />ANALYSIS WORKSPACE <em>/</em> SYNTHETIC & AUTHORISED DATA ONLY</p><div style={{marginLeft:'auto',display:'flex',gap:12,alignItems:'center'}}>
      <strong>{busy ? "ASSESSING" : "READY"}<i /></strong>
      <div role="button" aria-label="OpenAI status" onClick={() => setOpenaiModalOpen(true)} style={{display:'flex',alignItems:'center',gap:8,cursor:'pointer'}}>
        <div className={`openai-badge ${openaiConfigured ? 'ready' : openaiConfigured === false ? 'missing' : 'checking'}`} />
        {openaiConfigured === null ? <span style={{fontSize:12,color:'#91a0ad'}}>Checking OpenAI…</span> : openaiConfigured ? <span style={{fontSize:12,color:'#a7ebca'}}>OpenAI ready</span> : <span style={{fontSize:12,color:'#d96b6b'}}>OpenAI missing</span>}
      </div>
    </div></header>
    <section id="top" className="hero"><div><label>ACCESS EXPOSURE INTELLIGENCE</label><h1>Make every<br /><em>permission</em> visible.</h1><p>Trace the blast radius of a compromised identity, quantify exposure, and focus attention on the few access paths that matter most.</p></div><div className="orbit" aria-hidden="true"><b>BR</b><i /><i /><i /></div></section>
    <section className="controls"><div><label>ACCESS GRAPH</label><p><label className="upload">{graph ? "Replace JSON" : "Upload JSON"}<input type="file" accept="application/json" onChange={upload} /></label><a href="/payroll-access-graph.json" download>Use sample graph ↗</a></p></div><hr /><div><label>COMPROMISED IDENTITY</label><select value={employee} disabled={!graph} onChange={(event) => setEmployee(event.target.value)}>{employees.length ? employees.map((node) => <option key={node.id} value={node.id}>{node.label}</option>) : <option>Select an employee</option>}</select></div><button disabled={!graph || !employee || busy || openaiConfigured === false} onClick={() => void run()} title={openaiConfigured === false ? "OpenAI not configured — add OPENAI_API_KEY to enable analysis" : undefined}>{busy ? "Assessing…" : "Run assessment"}<span>→</span></button></section>
    <p className="status" role="status"><i />{message}</p>
    {bannerVisible && (
      <div ref={bannerRef} className={`banner ${bannerHiding ? 'hide' : 'show'}`} role="alert">
        <div className="banner-inner">
          <strong>OpenAI analysis disabled</strong>
          <p>
            Add an <code>OPENAI_API_KEY</code> to enable analyst review. Copy <a href="/.env.example">.env.example</a> to <code>.env</code> and paste your key, or set an environment variable named <code>OPENAI_API_KEY</code> before starting the backend.
          </p>
        </div>
      </div>
    )}
    <section className="metrics"><article className="exposure"><div><label>EXPOSURE SCORE</label><h2>{simulation?.impact_score ?? "—"}<small>/100</small></h2></div><b className={simulation?.verdict?.toLowerCase() ?? "unknown"}>{simulation?.verdict ?? "NOT RUN"}</b></article><article><label>REACHABLE ENTITIES</label><h2>{simulation?.reachable_node_ids.length ?? "—"}</h2><p>Downstream from selected identity</p></article><article><label>HIGH-LEVERAGE REVIEWS</label><h2>{simulation?.recommendations.length ?? "—"}</h2><p>Minimum-cut access paths</p></article><article className="analyst"><label>ANALYST STATE</label>
      <div className="analyst-row">
        <div className={`openai-badge ${openaiConfigured ? 'ready' : openaiConfigured === false ? 'missing' : 'checking'}`} aria-hidden="true" />
        <div className="analyst-text">
          <h3>{analysis ? "OpenAI reviewed" : openaiConfigured === false ? "OpenAI missing" : openaiConfigured === null ? "Checking…" : "Pending review"}</h3>
          <p>{openaiConfigured === false ? 'Add OPENAI_API_KEY to enable automated analyst briefs.' : 'Recommendations require human approval'}</p>
        </div>
      </div>
    </article></section>

    {openaiModalOpen && (
      <div className="openai-modal" role="dialog" aria-modal="true">
        <div className="openai-modal-inner">
          <button className="openai-modal-close" onClick={() => setOpenaiModalOpen(false)} aria-label="Close">✕</button>
          <h3>Enable OpenAI analysis</h3>
          <p>To enable automated analyst briefs, add an <code>OPENAI_API_KEY</code> to your environment. You can either paste it into a `.env` file at the project root, or set it as a system environment variable.</p>
          <pre className="openai-template">OPENAI_API_KEY=YOUR_KEY_HERE
OPENAI_MODEL=gpt-5</pre>
          <div style={{display:'flex',gap:8,marginTop:12}}>
            <button onClick={async () => {
              try { await navigator.clipboard.writeText('OPENAI_API_KEY=YOUR_KEY_HERE\nOPENAI_MODEL=gpt-5'); setCopied(true); setTimeout(() => setCopied(false), 2000); }
              catch { setCopied(false); }
            }} className="btn">Copy template</button>
            <button onClick={() => setOpenaiModalOpen(false)} className="btn secondary">Close</button>
            <div style={{alignSelf:'center',color:copied ? '#a7ebca' : '#9eabb7'}}>{copied ? 'Copied ✓' : ''}</div>
          </div>
        </div>
      </div>
    )}
    <section className="workspace"><section className="map"><header><div><label>ACCESS MAP</label><h2>Exposure pathway</h2></div><p><i className="selected" />Compromised <i className="active" />Reachable <i />Unreachable</p></header>{graph ? <div className="layers">{layers.map((layer, index) => <div className="layer" key={layer.title}><header><label>{layer.caption}</label><h3>{layer.title}</h3></header><div>{graph.nodes.filter((node) => layer.types.includes(node.type)).map((node) => <article className={`${node.id === employee ? "selected" : reached.has(node.id) ? "active" : "muted"} ${node.sensitivity && node.sensitivity >= 9 ? "critical" : ""}`} key={node.id}><span>{node.type === "employee" ? "◉" : node.type === "identity_group" ? "◇" : node.type === "credential" ? "⌘" : node.type === "application" ? "▣" : "◌"}</span><small>{node.id}</small><h4>{node.label}</h4><p>{tags(node).map((tag) => <b key={tag}>{tag}</b>)}</p></article>) || <p className="empty">No entities in this layer</p>}</div>{index < layers.length - 1 && <i className="arrow">→</i>}</div>)}</div> : <div className="blank"><b>✦</b><h3>Start with an access graph</h3><p>Upload the provided JSON structure to reveal identity paths and sensitive assets.</p></div>}{simulation?.critical_paths.length ? <footer><b>TOP PATH</b>{simulation.critical_paths[0].path.map((id) => graph?.nodes.find((node) => node.id === id)?.label ?? id).join("  →  ")}</footer> : null}</section>
      <aside><section className="card"><header><label>RECOMMENDED REVIEW</label><b>{simulation?.recommendations.length ?? 0}</b></header><h2>Break the path.</h2><p>Preview revocations to see their calculated effect. Nothing is changed outside this workspace.</p>{simulation?.recommendations.length ? <div className="review">{simulation.recommendations.map((item) => <label className={revoked.includes(item.edge_index) ? "checked" : ""} key={item.edge_index}><input type="checkbox" checked={revoked.includes(item.edge_index)} onChange={() => toggle(item.edge_index)} /><i>✓</i><span><b>{item.relation.replaceAll("_", " ")}</b><small>{item.from_label} → {item.to_label}</small></span></label>)}</div> : <p className="empty">Run an assessment to calculate permission reviews.</p>}</section><section className="card ai"><label>OPENAI SECURITY BRIEF</label>{analysis ? <><h2>{analysis.verdict} exposure</h2><p>{analysis.justification}</p><ol>{analysis.attacker_steps.map((step, index) => <li key={step}><b>0{index + 1}</b>{step}</li>)}</ol></> : <><h2>Awaiting analysis</h2><p>After calculation, OpenAI turns validated graph results into a focused analyst brief.</p></>}</section></aside></section>
    <footer className="site-footer">BLAST RADIUS <i>·</i> ACCESS ANALYSIS, NOT ACCESS CONTROL <i>·</i> REMEDIATION IS PREVIEW-ONLY</footer>
  </main>;
}
