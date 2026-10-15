import React,{useEffect,useMemo,useState} from "react";
import {createRoot} from "react-dom/client";
import "./styles.css";

const API=(import.meta.env.VITE_API_URL||"http://localhost:8000").replace(/\/$/,"");
const nav=[["overview","Overview","◈"],["incidents","Incidents","⚠"],["events","Security Events","◉"],["network","Network","⌁"],["devices","Devices","▣"],["servers","Servers","▤"],["trust","Trust Matrix","◇"],["users","Users","♙"],["audit","Audit & Reports","≡"],["ml","AI Engine","✦"]];

function fmtDate(v){if(!v)return "—"; const d=new Date(v); return Number.isNaN(d.getTime())?"—":d.toLocaleString([], {month:"short",day:"2-digit",hour:"2-digit",minute:"2-digit"});}
function scoreClass(s){return s>=70?"good":s>=40?"warn":"danger";}
function severityClass(s){return String(s||"").toLowerCase();}
function App(){
 const [token,setToken]=useState(localStorage.getItem("zt_token")||"");
 const [user,setUser]=useState(null); const [page,setPage]=useState("overview"); const [toast,setToast]=useState(null);
 const [mfa,setMfa]=useState(null);
 const [loading,setLoading]=useState(false);
 const [refresh,setRefresh]=useState(0);
 const [themeMotion,setThemeMotion]=useState(true);
 function notify(message,type="ok"){setToast({message,type});setTimeout(()=>setToast(null),3500)}
 async function api(path,opts={}){
   const headers={"Content-Type":"application/json",...(opts.headers||{})}; if(token) headers.Authorization=`Bearer ${token}`;
   const res=await fetch(API+path,{...opts,headers}); const text=await res.text(); let data; try{data=text?JSON.parse(text):null}catch{data=text}
   if(res.status===401){localStorage.removeItem("zt_token");setToken("");setUser(null);throw new Error(data?.detail||"Session expired")}
   if(!res.ok) throw new Error(data?.detail||data?.message||`Request failed (${res.status})`); return data;
 }
 useEffect(()=>{if(!token)return; api("/users/me").then(setUser).catch(e=>notify(e.message,"error"))},[token]);
 useEffect(()=>{if(!token)return; const id=setInterval(()=>setRefresh(x=>x+1),15000); return()=>clearInterval(id)},[token]);
 useEffect(()=>{if(!token)return; let ws; try{const proto=API.startsWith("https")?"wss":"ws"; const host=API.replace(/^https?:\/\//,""); ws=new WebSocket(`${proto}://${host}/ws/alerts?token=${encodeURIComponent(token)}`); ws.onmessage=e=>{try{const m=JSON.parse(e.data); if(m.type==="security_event"||m.type==="alert"){notify("Live security alert received","error")} setRefresh(x=>x+1)}catch{}}}catch{} return()=>{try{ws?.close()}catch{}}},[token]);
 if(!token)return <Login onLogin={(t,u)=>{localStorage.setItem("zt_token",t);setToken(t);setUser(u)}} api={api} mfa={mfa} setMfa={setMfa} notify={notify}/>;
 return <div className={`app ${themeMotion?"motion-on":""}`}>
   <Sidebar page={page} setPage={setPage} user={user} logout={()=>{localStorage.removeItem("zt_token");setToken("");setUser(null)}}/>
   <main className="main"><Topbar user={user} page={page} onRefresh={()=>setRefresh(x=>x+1)} motion={themeMotion} setMotion={setThemeMotion}/>
    {page==="overview"&&<Overview api={api} refresh={refresh} setPage={setPage}/>}
    {page==="incidents"&&<Incidents api={api} refresh={refresh} notify={notify}/>}
    {page==="events"&&<Events api={api} refresh={refresh}/>}
    {page==="network"&&<Network api={api} refresh={refresh} notify={notify}/>}
    {page==="devices"&&<Assets type="devices" api={api} refresh={refresh} notify={notify}/>}
    {page==="servers"&&<Assets type="servers" api={api} refresh={refresh} notify={notify}/>}
    {page==="trust"&&<Trust api={api} refresh={refresh}/>}
    {page==="users"&&<Users api={api} refresh={refresh} notify={notify}/>}
    {page==="audit"&&<Audit api={api} refresh={refresh}/>}
    {page==="ml"&&<ML api={api} refresh={refresh} notify={notify}/>}
   </main>{toast&&<div className={`toast ${toast.type}`}>{toast.type==="ok"?"✓":"!"} {toast.message}</div>}
 </div>
}

function Login({onLogin,api,mfa,setMfa,notify}){
 const [username,setUsername]=useState("admin"),[password,setPassword]=useState("Admin@123"),[code,setCode]=useState(""),[busy,setBusy]=useState(false);
 async function submit(e){e.preventDefault();setBusy(true);try{
   const body=mfa?new URLSearchParams({mfa_token:mfa,code}):new URLSearchParams({username,password});
   const r=await fetch(API+(mfa?"/auth/login/mfa":"/auth/login"),{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body});
   const d=await r.json(); if(!r.ok)throw new Error(d.detail||"Authentication failed");
   if(d.mfa_required){setMfa(d.mfa_token);return}
   localStorage.setItem("zt_token",d.access_token); onLogin(d.access_token,null); setMfa(null);
 }catch(e){notify(e.message,"error")}finally{setBusy(false)}}
 return <div className="login-shell"><div className="login-orb orb-a"/><div className="login-orb orb-b"/>
  <section className="login-card glass">
   <div className="brand-mark">ZT</div><div className="eyebrow">ZERO-TRUST COMMAND CENTER</div>
   <h1>Secure every <span>connection.</span></h1><p className="muted">AI-assisted data-center security monitoring, trust scoring and incident response.</p>
   <form onSubmit={submit}><label>{mfa?"Authenticator code":"Username"}<input value={mfa?code:username} onChange={e=>mfa?setCode(e.target.value):setUsername(e.target.value)} placeholder={mfa?"6-digit code":"admin"} autoFocus/></label>
   {!mfa&&<label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)}/></label>}
   <button className="primary full" disabled={busy}>{busy?"Authenticating…":mfa?"Verify identity":"Enter command center"} <span>→</span></button></form>
   <div className="login-foot"><span>● API protected</span><span>● PostgreSQL</span><span>● ML anomaly engine</span></div>
  </section>
 </div>
}

function Sidebar({page,setPage,user,logout}){
 return <aside className="sidebar"><div className="logo"><div className="logo-box">ZT</div><div><b>ZeroTrust</b><small>COMMAND CENTER</small></div></div>
  <div className="status-pill"><i/> LIVE MONITORING</div><nav>{nav.map(([id,label,icon])=><button key={id} className={page===id?"active":""} onClick={()=>setPage(id)}><span className="nav-icon">{icon}</span>{label}{id==="incidents"&&<span className="nav-dot">!</span>}</button>)}</nav>
  <div className="side-bottom"><div className="mini-user"><div className="avatar">{(user?.username||"A")[0].toUpperCase()}</div><div><b>{user?.username||"admin"}</b><small>{user?.roles?.[0]||"operator"}</small></div><button title="Sign out" onClick={logout}>↪</button></div></div>
 </aside>
}
function Topbar({user,page,onRefresh,motion,setMotion}){return <header className="topbar"><div><span className="crumb">SECURITY / </span><b>{nav.find(x=>x[0]===page)?.[1]?.toUpperCase()}</b></div><div className="top-actions"><button className="icon-btn" onClick={onRefresh} title="Refresh">↻</button><button className={`motion-toggle ${motion?"on":""}`} onClick={()=>setMotion(!motion)}><i/>3D motion</button><div className="top-avatar">{(user?.username||"A")[0].toUpperCase()}</div></div></header>}

function Overview({api,refresh,setPage}){
 const [d,setD]=useState(null); const [err,setErr]=useState("");
 useEffect(()=>{api("/dashboard/summary?minutes=60").then(setD).catch(e=>setErr(e.message))},[refresh]);
 if(err)return <ErrorState message={err}/>; if(!d)return <Loading/>;
 const c=d.counts,t=d.trust;
 return <div className="content"><Hero title="Security posture" sub="Real-time view of your protected environment" badge="ZERO-TRUST ACTIVE"/>
  <div className="metric-grid">
   <Metric title="Protected assets" value={c.devices+c.servers} sub={`${c.online_assets} online`} icon="◈"/>
   <Metric title="Open incidents" value={c.open_incidents} sub={`${c.high_risk_events} high-risk events`} icon="⚠" tone={c.open_incidents?"danger":""}/>
   <Metric title="Anomalous traffic" value={c.anomalous_traffic} sub={`${c.traffic_flows} flows / 60m`} icon="⌁" tone={c.anomalous_traffic?"warn":""}/>
   <Metric title="Average trust" value={`${Math.round((t.devices_avg+t.servers_avg)/2)}%`} sub={`${t.low_trust} assets need attention`} icon="◇" tone={t.low_trust?"warn":""}/>
  </div>
  <div className="two-col"><Panel title="Trust posture" action="Trust matrix" onAction={()=>setPage("trust")}><TrustBars d={d}/></Panel>
   <Panel title="ML anomaly engine" action="Open engine" onAction={()=>setPage("ml")}><MLCard ml={d.ml}/></Panel></div>
  <div className="two-col"><Panel title="Recent incidents" action="View all" onAction={()=>setPage("incidents")}><IncidentList items={d.recent_incidents}/></Panel>
   <Panel title="Recent security events"><EventList items={d.recent_events}/></Panel></div>
 </div>
}
function Hero({title,sub,badge}){return <div className="hero"><div><div className="eyebrow">{badge}</div><h2>{title}</h2><p>{sub}</p></div><div className="hero-cube"><div className="cube">◈</div></div></div>}
function Metric({title,value,sub,icon,tone=""}){return <div className={`metric glass ${tone}`}><div className="metric-top"><span>{title}</span><b>{icon}</b></div><strong>{value}</strong><small>{sub}</small><div className="metric-line"><i/></div></div>}
function Panel({title,children,action,onAction}){return <section className="panel glass"><div className="panel-head"><h3>{title}</h3>{action&&<button onClick={onAction}>{action} →</button>}</div>{children}</section>}
function TrustBars({d}){
 const trust=d?.trust||{};
 const devices=trust.devices||{};
 const servers=trust.servers||{};
 const vals=[
  ["Devices",Number(trust.devices_avg??devices.avg??0),devices],
  ["Servers",Number(trust.servers_avg??servers.avg??0),servers]
 ];
 return <div className="trust-bars">{vals.map(([n,v,o])=>{
  const count=Number(o?.count??0);
  const high=Number(o?.buckets?.high??0);
  const low=Number(o?.buckets?.low??0);
  return <div key={n} className="bar-row"><div><span>{n}</span><b>{Math.round(v)}%</b></div><div className="bar"><i style={{width:`${Math.max(0,Math.min(100,v))}%`}}/></div><small>{count} assets · {high} high trust · {low} low trust</small></div>
 })}</div>}
function MLCard({ml}){return <div className="ml-card"><div className="ai-ring"><span>AI</span></div><div><b>{ml?.ready?"Anomaly model online":"Model unavailable"}</b><p>{ml?.model_path||"Train the Isolation Forest to activate scoring."}</p></div><span className={`chip ${ml?.ready?"success":"danger"}`}>{ml?.ready?"READY":"OFFLINE"}</span></div>}
function IncidentList({items=[]}){return <div className="list">{items.map(i=><div className="list-row" key={i.id}><span className={`sev ${severityClass(i.severity)}`}>{i.severity}</span><div><b>{i.title}</b><small>{fmtDate(i.created_at)}</small></div><strong>{Math.round(i.risk_score||0)}</strong></div>)}{!items.length&&<Empty/>}</div>}
function EventList({items=[]}){return <div className="list">{items.map(i=><div className="list-row" key={i.id}><span className={`sev ${severityClass(i.severity)}`}>{i.severity}</span><div><b>{i.event_type}</b><small>{i.source_ip||"internal"} · {fmtDate(i.created_at)}</small></div><strong>{i.is_anomalous?"ANOM":"OK"}</strong></div>)}{!items.length&&<Empty/>}</div>}
function Loading(){return <div className="content"><div className="skeleton hero"/><div className="metric-grid">{[1,2,3,4].map(x=><div className="skeleton metric" key={x}/>)}</div><div className="skeleton large"/></div>}
function ErrorState({message}){return <div className="content"><div className="error-box"><b>Unable to load this view</b><p>{message}</p><small>Confirm FastAPI is running on {API} and the logged-in role has read permission.</small></div></div>}
function Empty(){return <div className="empty">No records in the selected window.</div>}

function Incidents({api,refresh,notify}){const [d,setD]=useState(null),[filter,setFilter]=useState("ALL"); useEffect(()=>{api("/incidents?limit=100").then(setD).catch(e=>notify(e.message,"error"))},[refresh]); if(!d)return <Loading/>;let rows=filter==="ALL"?d.items:d.items.filter(x=>x.status===filter); async function update(id,status){try{await api(`/incidents/${id}`,{method:"PATCH",body:JSON.stringify({status})});notify("Incident status updated");setD(await api("/incidents?limit=100"))}catch(e){notify(e.message,"error")}} return <div className="content"><Hero title="Incident response" sub={`${d.total} incidents across the environment`} badge="THREAT RESPONSE"/>
 <div className="toolbar"><div className="filters">{["ALL","OPEN","INVESTIGATING","RESOLVED","CLOSED"].map(x=><button className={filter===x?"selected":""} onClick={()=>setFilter(x)} key={x}>{x}</button>)}</div></div>
 <Panel title="Incident queue"><div className="table-wrap"><table><thead><tr><th>Threat</th><th>Severity</th><th>Status</th><th>Risk</th><th>Created</th><th>Action</th></tr></thead><tbody>{rows.map(i=><tr key={i.id}><td><b>{i.title}</b><small>{i.description}</small></td><td><span className={`sev ${severityClass(i.severity)}`}>{i.severity}</span></td><td><span className={`chip ${i.status==="OPEN"?"danger":i.status==="INVESTIGATING"?"warn":"success"}`}>{i.status}</span></td><td><b className={scoreClass(i.risk_score)}>{Math.round(i.risk_score||0)}</b></td><td>{fmtDate(i.created_at)}</td><td>{(i.status==="OPEN"||i.status==="INVESTIGATING")&&<button className="tiny" onClick={()=>update(i.id,i.status==="OPEN"?"INVESTIGATING":"RESOLVED")}>{i.status==="OPEN"?"Investigate":"Resolve"}</button>}</td></tr>)}</tbody></table></div></Panel></div>}

function Events({api,refresh}){const [d,setD]=useState(null),[sev,setSev]=useState(""),[anom,setAnom]=useState(false); useEffect(()=>{let q=`/events?limit=200${sev?`&severity=${sev}`:""}${anom?"&anomalous_only=true":""}`;api(q).then(setD).catch(()=>{})},[refresh,sev,anom]); if(!d)return <Loading/>;return <div className="content"><Hero title="Security events" sub={`${d.total} telemetry events indexed`} badge="CONTINUOUS DETECTION"/><Panel title="Event stream"><div className="toolbar"><select value={sev} onChange={e=>setSev(e.target.value)}><option value="">All severities</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select><label className="check"><input type="checkbox" checked={anom} onChange={e=>setAnom(e.target.checked)}/> Anomalies only</label></div><div className="event-stream">{d.items.map(e=><div className="event-card" key={e.id}><span className={`sev ${severityClass(e.severity)}`}>{e.severity}</span><div className="event-main"><div><b>{e.event_type}</b>{e.is_anomalous&&<span className="chip danger">ML ANOMALY</span>}</div><p>{e.description}</p><small>{e.source_ip||"—"} → {e.destination_ip||"—"} · {fmtDate(e.created_at)}</small></div><div className="risk">RISK <b>{Math.round(e.risk_score||0)}</b></div></div>)}</div></Panel></div>}

function Network({api,refresh,notify}){const [d,setD]=useState(null),[traffic,setTraffic]=useState(null); useEffect(()=>{Promise.all([api("/network/stats?minutes=60"),api("/network/traffic?limit=80")]).then(([a,b])=>{setD(a);setTraffic(b)}).catch(e=>notify(e.message,"error"))},[refresh]); if(!d||!traffic)return <Loading/>; return <div className="content"><Hero title="Network observatory" sub="Flow telemetry, protocol behavior and ML risk signals" badge="NETWORK SENTINEL"/>
 <div className="metric-grid"><Metric title="Flows / hour" value={d.total_flows} sub={`${d.inbound} inbound · ${d.outbound} outbound`} icon="⌁"/><Metric title="Anomalous flows" value={d.anomalous_flows} sub={`${(d.anomaly_rate*100).toFixed(1)}% anomaly rate`} icon="⚠" tone={d.anomalous_flows?"warn":""}/><Metric title="Data moved" value={bytes(d.total_bytes)} sub="last 60 minutes" icon="⇅"/><Metric title="Avg anomaly score" value={Number(d.avg_anomaly_score||0).toFixed(2)} sub="model signal" icon="✦"/></div>
 <div className="two-col"><Panel title="Protocol activity"><div className="bars">{Object.entries(d.protocols).sort((a,b)=>b[1]-a[1]).map(([k,v])=><div className="hbar" key={k}><span>{k}</span><div><i style={{width:`${Math.min(100,v/Math.max(...Object.values(d.protocols))*100)}%`}}/></div><b>{v}</b></div>)}</div></Panel><Panel title="Top source volume"><div className="list">{d.top_sources.map(x=><div className="list-row" key={x.ip}><div><b className="mono">{x.ip}</b><small>source volume</small></div><strong>{bytes(x.bytes)}</strong></div>)}</div></Panel></div>
 <Panel title="Latest network flows"><div className="table-wrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Protocol</th><th>Direction</th><th>Bytes</th><th>ML</th><th>Time</th></tr></thead><tbody>{traffic.items.map(x=><tr key={x.id}><td className="mono">{x.source_ip}:{x.source_port}</td><td className="mono">{x.destination_ip}:{x.destination_port}</td><td>{x.protocol}</td><td>{x.direction}</td><td>{bytes(x.bytes_transferred)}</td><td><span className={`chip ${x.is_anomalous?"danger":"success"}`}>{x.is_anomalous?"ANOM":"NORMAL"}</span></td><td>{fmtDate(x.created_at)}</td></tr>)}</tbody></table></div></Panel></div>}
function bytes(n=0){if(n<1024)return `${n} B`;if(n<1048576)return `${(n/1024).toFixed(1)} KB`;if(n<1073741824)return `${(n/1048576).toFixed(1)} MB`;return `${(n/1073741824).toFixed(1)} GB`}

function Assets({type,api,refresh,notify}){const [rows,setRows]=useState(null),[q,setQ]=useState(""),[selected,setSelected]=useState(null); useEffect(()=>{api(`/${type}`).then(setRows).catch(e=>notify(e.message,"error"))},[refresh]); if(!rows)return <Loading/>;let filtered=rows.filter(x=>`${x.hostname} ${x.ip_address} ${x.operating_system||""}`.toLowerCase().includes(q.toLowerCase())); async function toggle(x){try{await api(`/${type}/${x.id}`,{method:"PATCH",body:JSON.stringify(type==="devices"?{is_trusted:!x.is_trusted}:{is_online:!x.is_online})});notify(`${x.hostname} updated`);setRows(await api(`/${type}`))}catch(e){notify(e.message,"error")}} return <div className="content"><Hero title={type==="devices"?"Device fleet":"Server fleet"} sub={`${rows.length} managed ${type}`} badge="ASSET POSTURE"/><div className="toolbar"><input className="search" placeholder="Search hostname, IP or OS…" value={q} onChange={e=>setQ(e.target.value)}/></div><div className="asset-grid">{filtered.map(x=><article className="asset-card glass" key={x.id} onClick={()=>setSelected(x)}><div className="asset-icon">{type==="devices"?"▣":"▤"}</div><div className="asset-title"><b>{x.hostname}</b><small className="mono">{x.ip_address}</small></div><span className={`trust-badge ${scoreClass(x.trust_score)}`}>{Math.round(x.trust_score||0)}</span><div className="asset-meta"><span>{x.operating_system}</span><span>{type==="devices"?x.device_type:x.zone}</span></div><div className="asset-footer"><span className={x.is_online?"online":"offline"}>● {x.is_online?"ONLINE":"OFFLINE"}</span><button className="tiny" onClick={e=>{e.stopPropagation();toggle(x)}}>{type==="devices"?(x.is_trusted?"Untrust":"Trust"):(x.is_online?"Take offline":"Bring online")}</button></div></article>)}</div>{selected&&<Modal title={selected.hostname} close={()=>setSelected(null)}><pre>{JSON.stringify(selected,null,2)}</pre></Modal>}</div>}

function Trust({api,refresh}){const [d,setD]=useState(null);useEffect(()=>{api("/trust/overview").then(setD).catch(()=>{})},[refresh]);if(!d)return <Loading/>;return <div className="content"><Hero title="Trust matrix" sub="Every asset is continuously evaluated; trust is earned, not assumed." badge="ADAPTIVE TRUST"/><div className="trust-hero glass"><div className={`big-score ${scoreClass(d.overall_avg)}`}>{Math.round(d.overall_avg)}<small>/100</small></div><div><b>Overall environment trust</b><p>Signals include posture, recent security events, ML anomalies and explicit risk factors.</p></div></div><div className="asset-grid">{[...d.low_trust_assets,...Array(Math.max(0,5-d.low_trust_assets.length)).fill(null)].map((x,i)=>x?<article className="asset-card glass" key={`${x.type}-${x.id}`}><div className="asset-icon">⚠</div><div className="asset-title"><b>{x.hostname}</b><small className="mono">{x.ip_address}</small></div><span className={`trust-badge ${scoreClass(x.trust_score)}`}>{Math.round(x.trust_score)}</span><div className="asset-footer"><span>{x.type.toUpperCase()}</span><span className="danger-text">ATTENTION</span></div></article>:<article className="asset-card glass empty-card" key={i}><div className="asset-icon">✓</div><b>No additional low-trust asset</b><small>Environment remains within threshold.</small></article>)}</div></div>}

function Users({api,refresh,notify}){const [rows,setRows]=useState(null),[form,setForm]=useState({username:"",email:"",password:"",role:"viewer"});useEffect(()=>{api("/users").then(setRows).catch(e=>notify(e.message,"error"))},[refresh]);if(!rows)return <Loading/>;async function add(e){e.preventDefault();try{await api("/users",{method:"POST",body:JSON.stringify(form)});notify("User created");setForm({username:"",email:"",password:"",role:"viewer"});setRows(await api("/users"))}catch(e){notify(e.message,"error")}}return <div className="content"><Hero title="Identity & access" sub="RBAC accounts and zero-trust identity posture" badge="IAM CONTROL"/><div className="two-col"><Panel title="Create user"><form className="compact-form" onSubmit={add}>{["username","email","password"].map(k=><input key={k} type={k==="password"?"password":"text"} placeholder={k} value={form[k]} onChange={e=>setForm({...form,[k]:e.target.value})} required/>)}<select value={form.role} onChange={e=>setForm({...form,role:e.target.value})}><option>viewer</option><option>operator</option><option>security_analyst</option><option>admin</option></select><button className="primary">Create identity</button></form></Panel><Panel title="Registered identities"><div className="list">{rows.map(x=><div className="list-row" key={x.id}><div><b>{x.username}</b><small>{x.email} · {x.mfa_enabled?"MFA enabled":"MFA not enabled"}</small></div><span className={`chip ${x.is_active?"success":"danger"}`}>{x.roles.join(", ")}</span></div>)}</div></Panel></div></div>}

function Audit({api,refresh}){const [d,setD]=useState(null);useEffect(()=>{api("/audit?limit=100").then(setD).catch(()=>{})},[refresh]);if(!d)return <Loading/>;async function downloadReport(kind){try{const res=await fetch(`${API}/export/${kind}`,{headers:{Authorization:`Bearer ${localStorage.getItem("zt_token")||""}`}});if(!res.ok){const x=await res.json().catch(()=>({}));throw new Error(x.detail||`Export failed (${res.status})`)}const blob=await res.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");a.href=url;a.download=`${kind}.csv`;a.click();URL.revokeObjectURL(url)}catch(e){alert(e.message)}}return <div className="content"><Hero title="Audit & reports" sub="Operational trail for security review and evidence export" badge="GOVERNANCE"/><Panel title="Audit trail"><div className="table-wrap"><table><thead><tr><th>Actor</th><th>Action</th><th>Resource</th><th>IP</th><th>Time</th></tr></thead><tbody>{d.items?.map(x=><tr key={x.id}><td><b>{x.username||"system"}</b></td><td>{x.action}</td><td>{x.resource_type} {x.resource_id||""}</td><td className="mono">{x.ip_address||"—"}</td><td>{fmtDate(x.created_at)}</td></tr>)}</tbody></table></div></Panel><div className="report-grid">{["events","traffic","audit","incidents"].map(x=><button className="report-card glass" onClick={()=>downloadReport(x)} key={x}><span>↓</span><b>Export {x}</b><small>Authenticated CSV report</small></button>)}</div></div>}

function ML({api,refresh,notify}){const [d,setD]=useState(null),[busy,setBusy]=useState(false);useEffect(()=>{api("/ml/status").then(setD).catch(e=>notify(e.message,"error"))},[refresh]);if(!d)return <Loading/>;async function retrain(){setBusy(true);try{let r=await api("/ml/retrain",{method:"POST"});setD(r.model);notify("Isolation Forest retrained and reloaded")}catch(e){notify(e.message,"error")}finally{setBusy(false)}}return <div className="content"><Hero title="AI anomaly engine" sub="Isolation Forest scores network behavior and feeds risk decisions." badge="MACHINE INTELLIGENCE"/><div className="ai-console glass"><div className="ai-visual"><div className="pulse-ring"/><div className="ai-core">✦</div></div><div className="ai-copy"><span className={`chip ${d.ready?"success":"danger"}`}>{d.ready?"MODEL ONLINE":"MODEL OFFLINE"}</span><h3>{d.ready?"Behavioral detection is active":"Detection model needs training"}</h3><p>{d.model_path||"No model artifact reported."}</p><button className="primary" disabled={busy} onClick={retrain}>{busy?"Training…":"Retrain Isolation Forest"} →</button></div></div></div>}

function Modal({title,close,children}){return <div className="modal-backdrop" onClick={close}><div className="modal glass" onClick={e=>e.stopPropagation()}><div className="panel-head"><h3>{title}</h3><button onClick={close}>×</button></div>{children}</div></div>}
function AppRoot(){return <App/>} createRoot(document.getElementById("root")).render(<AppRoot/>);
