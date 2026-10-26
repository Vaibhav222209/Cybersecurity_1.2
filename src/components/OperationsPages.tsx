import { useEffect, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import { Activity, ArrowDownToLine, ArrowRight, Check, ChevronDown, CircleAlert, Clock3, Database, Ellipsis, FileSearch, Filter, GitBranch, Globe2, HardDrive, Layers3, Network, Search, Server, Shield, ShieldAlert, ShieldCheck, ShieldOff, Sparkles, Terminal, Unplug, X } from 'lucide-react';
import type { ActionFn, Asset, Incident, LogEvent, Severity, WorkspaceState } from '../types';
import './operations.css';

interface BaseProps { state: WorkspaceState; onAction: ActionFn }
interface LogProps extends BaseProps { onInspect: (log: LogEvent) => void; initialSearch?: string }
const timeLabel = (time: string) => new Date(time).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const titleCase = (text: string) => text.charAt(0).toUpperCase() + text.slice(1);
function SeverityBadge({ value }: { value: Severity }) { return <span className={`op-severity op-severity-${value}`}><i />{titleCase(value)}</span>; }
function Status({ value }: { value: string }) { return <span className={`op-status op-status-${value}`}><i />{titleCase(value)}</span>; }
function PageHeading({ title, description, icon: Icon }: { title: string; description: string; icon: typeof Activity }) { return <div className="op-page-heading"><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>{title}</h1><p>{description}</p></div><div className="op-heading-symbol"><Icon size={25}/></div></div>; }
function EmptyState({ text }: { text: string }) { return <div className="op-empty"><FileSearch size={30}/><h3>No matching results</h3><p>{text}</p></div>; }

export function LogExplorer({ state, onAction, onInspect, initialSearch = '' }: LogProps) {
  const [search, setSearch] = useState(initialSearch);
  const [severity, setSeverity] = useState('all');
  const [source, setSource] = useState('all');
  const [status, setStatus] = useState('all');
  const [menu, setMenu] = useState<string | null>(null);
  const [menuPosition, setMenuPosition] = useState({ left: 0, top: 0 });
  const [pending, setPending] = useState<string | null>(null);
  useEffect(() => { setSearch(initialSearch); }, [initialSearch]);
  useEffect(() => { if (!menu) return; const close = (event: KeyboardEvent) => { if (event.key === 'Escape') setMenu(null); }; document.addEventListener('keydown', close); return () => document.removeEventListener('keydown', close); }, [menu]);
  const sources = [...new Set(state.logs.map(log => log.source))].sort();
  const logs = useMemo(() => state.logs.filter(log => {
    const match = `${log.message} ${log.ip} ${log.user} ${log.source} ${log.id} ${log.category}`.toLowerCase().includes(search.toLowerCase());
    return match && (severity === 'all' || log.severity === severity) && (source === 'all' || log.source === source) && (status === 'all' || log.status === status);
  }).sort((a, b) => +new Date(b.time) - +new Date(a.time)), [state.logs, search, severity, source, status]);
  async function act(log: LogEvent, action: string) { setPending(log.id); try { await onAction(`/api/logs/${log.id}`, action); } finally { setPending(null); setMenu(null); } }
  function exportLogs() {
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'shadow-shade-logs.json'; a.click(); URL.revokeObjectURL(url);
  }
  const activeFilters = Number(severity !== 'all') + Number(source !== 'all') + Number(status !== 'all');
  return <div className="op-page">
    <PageHeading title="Log explorer" description="Every signal has a story. Search, analyze, and take the next step." icon={Terminal}/>
    <div className="op-summary-strip">
      <div><span className="op-summary-icon"><Layers3 size={17}/></span><strong>{state.logs.length}</strong><span>Ingested events</span></div>
      <div><span className="op-summary-icon op-coral"><CircleAlert size={17}/></span><strong>{state.logs.filter(l => l.severity === 'critical' || l.severity === 'high').length}</strong><span>High-priority signals</span></div>
      <div><span className="op-summary-icon op-purple"><Database size={17}/></span><strong>{sources.length}</strong><span>Connected sources</span></div>
    </div>
    <section className="panel op-log-panel">
      <div className="op-panel-title"><div><h2>Event stream <span className="op-count">{logs.length}</span></h2><p>Search the local event dataset and inspect the evidence.</p></div><button className="btn btn-ghost" onClick={exportLogs}><ArrowDownToLine size={15}/>Export JSON</button></div>
      <div className="op-filters">
        <label className="op-search"><Search size={16}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events, IPs, users…" aria-label="Search logs"/>{search && <button onClick={() => setSearch('')} aria-label="Clear search"><X size={14}/></button>}</label>
        <label className="op-select"><Filter size={14}/><select value={severity} onChange={e => setSeverity(e.target.value)} aria-label="Filter log severity"><option value="all">All severities</option>{['critical','high','medium','low','info'].map(v => <option key={v} value={v}>{titleCase(v)}</option>)}</select><ChevronDown size={13}/></label>
        <label className="op-select"><select value={source} onChange={e => setSource(e.target.value)} aria-label="Filter log source"><option value="all">All sources</option>{sources.map(s => <option key={s}>{s}</option>)}</select><ChevronDown size={13}/></label>
        <label className="op-select"><select value={status} onChange={e => setStatus(e.target.value)} aria-label="Filter log status"><option value="all">All statuses</option>{['open','investigating','safe','blocked'].map(v => <option value={v} key={v}>{titleCase(v)}</option>)}</select><ChevronDown size={13}/></label>
        {activeFilters > 0 && <button className="op-clear" onClick={() => {setSeverity('all');setSource('all');setStatus('all');}}>Reset filters <X size={12}/></button>}
      </div>
      {logs.length ? <div className="op-table-wrap"><table className="op-log-table"><thead><tr><th>TIME <ChevronDown size={10}/></th><th>SEVERITY</th><th>EVENT / SOURCE</th><th>SOURCE IP</th><th>STATUS</th><th><span className="op-sr-only">Actions</span></th></tr></thead><tbody>{logs.map(log => <tr key={log.id}>
        <td className="op-time mono">{timeLabel(log.time)}<small>{new Date(log.time).toLocaleDateString('en-GB', {day:'2-digit',month:'short'})}</small></td>
        <td><SeverityBadge value={log.severity}/></td>
        <td className="op-message-cell"><button className="op-event-name" onClick={() => onInspect(log)} title={log.message}>{log.message}</button><span><i className="op-source-dot"/>{log.source}<span className="op-dot-divider">·</span>{log.user || 'system'}</span></td>
        <td className="mono op-ip">{log.ip || '—'}</td>
        <td><Status value={log.status}/></td>
        <td className="op-action-cell"><button className="op-icon-button" aria-label={`Actions for ${log.id}`} aria-expanded={menu === log.id} disabled={pending === log.id} onClick={event => { const rect = event.currentTarget.getBoundingClientRect(); setMenuPosition({ left: Math.max(12, rect.right - 220), top: Math.max(12, Math.min(window.innerHeight - 225, rect.bottom + 6)) }); setMenu(menu === log.id ? null : log.id); }}><Ellipsis size={18}/></button>{menu === log.id && createPortal(<><button className="op-menu-backdrop op-floating-backdrop" aria-label="Close event actions" onClick={() => setMenu(null)}/><div className="op-action-menu op-floating-menu" style={menuPosition}><span>LOG RESPONSE · SIMULATED</span><button onClick={() => {onInspect(log);setMenu(null);}}><FileSearch size={15}/>Inspect details</button><button disabled={pending === log.id} onClick={() => void act(log, 'investigate')}><Search size={15}/>Investigate</button><button disabled={pending === log.id} onClick={() => void act(log, 'safe')}><ShieldCheck size={15}/>Mark as safe</button><button className="op-danger-action" disabled={pending === log.id} onClick={() => void act(log, 'block')}><ShieldOff size={15}/>Block signal</button></div></>, document.body)}</td>
      </tr>)}</tbody></table></div> : <EmptyState text="Try a different search or clear the filters to see your events."/>}
      <div className="op-table-footer"><span><i/> {logs.length} of {state.logs.length} events displayed</span><span><Shield size={12}/> Local demo dataset</span></div>
    </section>
    <p className="op-footnote"><ShieldCheck size={13}/> Response actions update this workspace only. They do not block network traffic or change external systems.</p>
  </div>;
}

export function AssetsPage({ state, onAction }: BaseProps) {
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('all');
  const [pending, setPending] = useState<string | null>(null);
  const [menu, setMenu] = useState<string | null>(null);
  const assets = state.assets.filter(asset => `${asset.name} ${asset.ip} ${asset.role} ${asset.os}`.toLowerCase().includes(search.toLowerCase()) && (status === 'all' || asset.status === status));
  async function act(asset: Asset, action: string) { setPending(asset.id); try { await onAction(`/api/assets/${asset.id}`, action); } finally { setPending(null);setMenu(null); } }
  return <div className="op-page">
    <PageHeading title="Asset intelligence" description="Understand your infrastructure. Contain the risk before it spreads." icon={Server}/>
    <div className="op-summary-strip"><div><span className="op-summary-icon"><Server size={17}/></span><strong>{state.assets.length}</strong><span>Monitored assets</span></div><div><span className="op-summary-icon op-coral"><ShieldAlert size={17}/></span><strong>{state.assets.filter(a => a.risk >= 70).length}</strong><span>Elevated risk</span></div><div><span className="op-summary-icon op-purple"><Unplug size={17}/></span><strong>{state.assets.filter(a => a.status === 'isolated' || a.status === 'blocked').length}</strong><span>Contained assets</span></div></div>
    <div className="op-assets-toolbar"><label className="op-search"><Search size={16}/><input aria-label="Search servers" placeholder="Search servers, IPs, or roles…" value={search} onChange={e => setSearch(e.target.value)}/></label><label className="op-select"><select aria-label="Filter asset status" value={status} onChange={e => setStatus(e.target.value)}><option value="all">All asset statuses</option>{['healthy','investigating','isolated','blocked','sanitized'].map(s => <option key={s} value={s}>{titleCase(s)}</option>)}</select><ChevronDown size={13}/></label><span className="op-asset-total">{assets.length} assets</span></div>
    <div className="op-assets-grid">{assets.map(asset => <article className="panel op-asset-card" key={asset.id}>
      <div className="op-asset-top"><span className={`op-asset-icon ${asset.risk >= 70 ? 'op-asset-risk' : ''}`}><Server size={24}/></span><Status value={asset.status}/></div>
      <h2>{asset.name}</h2><div className="op-asset-ip mono"><Globe2 size={12}/>{asset.ip}</div>
      <div className="op-asset-info"><div><span>ROLE</span><strong>{asset.role}</strong></div><div><span>PLATFORM</span><strong><HardDrive size={12}/>{asset.os}</strong></div></div>
      <div className="op-risk-label"><span>Risk level</span><strong className={asset.risk >= 70 ? 'op-coral-text' : asset.risk >= 35 ? 'op-amber-text' : 'op-lime-text'}>{asset.risk}<small> / 100</small></strong></div><div className={`op-risk-bar ${asset.risk >= 70 ? 'op-risk-high' : asset.risk >= 35 ? 'op-risk-medium' : ''}`}><span style={{width:`${Math.min(100, Math.max(0, asset.risk))}%`}}/></div>
      <div className="op-asset-bottom"><span><Clock3 size={12}/>Seen {timeLabel(asset.lastSeen)}</span><div className="op-asset-menu-anchor"><button className="op-manage-btn" disabled={pending === asset.id} onClick={() => setMenu(menu === asset.id ? null : asset.id)} aria-expanded={menu === asset.id}>{pending === asset.id ? 'Updating…' : 'Respond'}<ChevronDown size={13}/></button>{menu === asset.id && <><button className="op-menu-backdrop" aria-label="Close server actions" onClick={() => setMenu(null)}/><div className="op-action-menu"><span>SERVER RESPONSE · SIMULATED</span><button onClick={() => void act(asset,'investigate')}><Search size={15}/>Investigate server</button><button onClick={() => void act(asset,'sanitize')}><Sparkles size={15}/>Sanitize server</button><button onClick={() => void act(asset,'isolate')}><Unplug size={15}/>Isolate server</button><button className="op-danger-action" onClick={() => void act(asset,'block')}><ShieldOff size={15}/>Block server</button></div></>}</div></div>
    </article>)}</div>{!assets.length && <section className="panel"><EmptyState text="No servers match this search and status. Try resetting your filters."/></section>}
    <section className="panel op-audit-panel"><div className="op-panel-title"><div><h2>Response audit trail</h2><p>A record of the decisions made in this workspace.</p></div><Activity size={18}/></div><div className="op-audit-list">{state.audit.length ? [...state.audit].sort((a,b) => +new Date(b.time) - +new Date(a.time)).slice(0,6).map(item => <div className="op-audit-row" key={item.id}><span className="op-audit-check"><Check size={13}/></span><div><strong>{item.action.replaceAll('_',' ')}</strong><span className="mono">{item.target}</span></div><time>{timeLabel(item.time)}</time></div>) : <p className="op-audit-empty">No actions yet. Investigate an asset to begin an audit trail.</p>}</div></section>
    <p className="op-footnote"><ShieldCheck size={13}/> Containment and sanitization are simulated state changes. No external server is modified.</p>
  </div>;
}

export function IncidentsPage({ state, onAction, onInspect }: Omit<LogProps, 'initialSearch'>) {
  const [selectedId, setSelectedId] = useState(state.incidents[0]?.id ?? '');
  const [filter, setFilter] = useState('all');
  const [pending, setPending] = useState(false);
  const incidents = useMemo(() => state.incidents.filter(i => filter === 'all' || i.status === filter).sort((a,b) => +new Date(b.time) - +new Date(a.time)), [state.incidents,filter]);
  const selected = incidents.find(i => i.id === selectedId) ?? incidents[0];
  const evidence = selected ? state.logs.filter(log => selected.logIds.includes(log.id)).sort((a,b) => +new Date(a.time) - +new Date(b.time)) : [];
  async function act(incident: Incident, action: string) { setPending(true); try { await onAction(`/api/incidents/${incident.id}`, action); } finally { setPending(false); } }
  return <div className="op-page">
    <PageHeading title="Threat investigations" description="Connect the signals. Build the timeline. See the bigger picture." icon={GitBranch}/>
    <div className="op-summary-strip"><div><span className="op-summary-icon op-coral"><ShieldAlert size={17}/></span><strong>{state.incidents.filter(i => i.status === 'open').length}</strong><span>Open incidents</span></div><div><span className="op-summary-icon op-purple"><FileSearch size={17}/></span><strong>{state.incidents.filter(i => i.status === 'investigating').length}</strong><span>In investigation</span></div><div><span className="op-summary-icon"><ShieldCheck size={17}/></span><strong>{state.incidents.filter(i => i.status === 'resolved').length}</strong><span>Resolved incidents</span></div></div>
    <div className="op-investigation-grid"><aside className="panel op-incident-list"><div className="op-list-heading"><h2>Correlated incidents</h2><label className="op-select"><select value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter incidents"><option value="all">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select><ChevronDown size={12}/></label></div>{incidents.map(incident => <button className={`op-incident-item ${selected?.id === incident.id ? 'op-incident-selected' : ''}`} key={incident.id} onClick={() => setSelectedId(incident.id)}><div><SeverityBadge value={incident.severity}/><time>{timeLabel(incident.time)}</time></div><h3>{incident.title}</h3><p>{incident.description}</p><footer><Status value={incident.status}/><span><GitBranch size={12}/>{incident.logIds.length} events</span></footer></button>)}{!incidents.length && <EmptyState text="There are no incidents with this status."/>}</aside>
      {selected ? <section className="panel op-investigation-detail"><div className="op-investigation-head"><span className="eyebrow">INCIDENT <span className="mono">{selected.id}</span></span><SeverityBadge value={selected.severity}/></div><h2>{selected.title}</h2><p className="op-investigation-description">{selected.description}</p><div className="op-incident-meta"><div><span>STATUS</span><Status value={selected.status}/></div><div><span>DETECTION CONFIDENCE</span><strong className="op-lime-text">{selected.confidence}%<i className="op-confidence-meter"><i style={{width:`${selected.confidence}%`}}/></i></strong></div><div><span>LINKED EVENTS</span><strong><Layers3 size={14}/>{evidence.length}</strong></div></div>
      <div className="op-tactics"><span>ATT&CK CONTEXT</span>{selected.tactics.map(tactic => <span key={tactic} className="op-tactic"><Network size={11}/>{tactic}</span>)}</div>
      <div className="op-timeline-heading"><h3><GitBranch size={16}/>Event correlation</h3><span>Chronological evidence</span></div>
      <div className="op-timeline">{evidence.map((log,index) => <div className="op-timeline-item" key={log.id}><div className={`op-timeline-node op-timeline-${log.severity}`}>{index === evidence.length - 1 ? <ShieldAlert size={13}/> : <i/>}</div><div className="op-timeline-content"><div><span className="mono">{timeLabel(log.time)}</span><span>{log.source}</span><SeverityBadge value={log.severity}/></div><button onClick={() => onInspect(log)}>{log.message}<ArrowRight size={13}/></button><footer><span className="mono">{log.ip}</span><span>{log.user || 'system'}</span></footer></div></div>)}{!evidence.length && <p className="op-muted">No linked log evidence is available for this incident.</p>}</div>
      <div className="op-incident-actions"><p><Shield size={13}/>Local demo response</p><div><button className="btn btn-ghost" disabled={pending || selected.status === 'investigating'} onClick={() => void act(selected,'investigate')}><Search size={14}/>Investigate</button><button className="btn btn-primary" disabled={pending || selected.status === 'resolved'} onClick={() => void act(selected,'resolve')}><Check size={14}/>{selected.status === 'resolved' ? 'Resolved' : 'Resolve incident'}</button></div></div>
      </section> : <section className="panel"><EmptyState text="Ingest suspicious events to create correlated incidents."/></section>}
    </div>
  </div>;
}
