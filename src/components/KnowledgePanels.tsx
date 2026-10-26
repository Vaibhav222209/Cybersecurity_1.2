import { useState } from 'react';
import { ArrowRight, BookOpen, Check, CheckCheck, CheckCircle2, ChevronRight, Code2, Copy, Crosshair, FileCheck2, Fingerprint, GraduationCap, Info, LockKeyhole, RotateCcw, Search, Shield, ShieldCheck, Sparkles, Target, ToggleLeft, ToggleRight, Workflow, X } from 'lucide-react';
import './knowledge.css';

type Rule = { id: string; title: string; category: string; severity: string; description: string; technique: string; schema: string; spl: string; kql: string; };
const rules: Rule[] = [
  {
    id: 'SS-001', title: 'Impossible travel', category: 'VPN & identity', severity: 'critical', technique: 'T1078 · Valid accounts',
    description: 'Find successful VPN sign-ins from different countries within 30 minutes. Investigate geolocation accuracy, corporate proxies, and legitimate travel before containment.',
    schema: 'SPL: index=vpn with action, user, country, src_ip. KQL: custom VPNLogs_CL with Result_s, User_s, Country_s, SourceIP_s.',
    spl: String.raw`index=vpn action=success user!="" country!=""
| sort 0 user _time
| streamstats current=f last(_time) AS previous_time
    last(country) AS previous_country BY user
| eval minutes_between=(_time-previous_time)/60
| where country!=previous_country
    AND minutes_between>=0 AND minutes_between<=30
| table _time user src_ip previous_country country minutes_between`,
    kql: String.raw`VPNLogs_CL
| where Result_s == "success" and isnotempty(Country_s)
| sort by User_s asc, TimeGenerated asc
| serialize
| extend PreviousUser = prev(User_s),
         PreviousCountry = prev(Country_s),
         PreviousTime = prev(TimeGenerated)
| where User_s == PreviousUser and Country_s != PreviousCountry
| extend MinutesBetween = datetime_diff("minute", TimeGenerated, PreviousTime)
| where MinutesBetween between (0 .. 30)
| project TimeGenerated, User_s, SourceIP_s, PreviousCountry, Country_s, MinutesBetween`,
  },
  {
    id: 'SS-002', title: 'Password spray', category: 'Authentication', severity: 'high', technique: 'T1110.003 · Password spraying',
    description: 'Detect one source failing authentication against at least five accounts in a five-minute window. Exclude known identity scanners only after verifying ownership.',
    schema: 'SPL: Windows Security events with EventCode, IpAddress, TargetUserName. KQL: Microsoft Sentinel SecurityEvent table.',
    spl: String.raw`index=wineventlog EventCode=4625
| where isnotnull(IpAddress) AND IpAddress!="-"
| bin _time span=5m
| stats dc(TargetUserName) AS targeted_accounts
    count AS failed_attempts BY _time IpAddress
| where targeted_accounts>=5 AND failed_attempts>=10
| sort - failed_attempts`,
    kql: String.raw`SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress) and IpAddress != "-"
| summarize TargetedAccounts = dcount(TargetUserName),
            FailedAttempts = count()
    by IpAddress, bin(TimeGenerated, 5m)
| where TargetedAccounts >= 5 and FailedAttempts >= 10
| order by FailedAttempts desc`,
  },
  {
    id: 'SS-003', title: 'Encoded PowerShell', category: 'Endpoint security', severity: 'high', technique: 'T1059.001 · PowerShell',
    description: 'Identify PowerShell executions with encoded command arguments. Inspect the parent process, decode the payload safely, and verify approved automation.',
    schema: 'SPL: Sysmon process creation EventCode=1 with Image and CommandLine. KQL: Defender XDR DeviceProcessEvents.',
    spl: String.raw`index=sysmon EventCode=1
| where match(Image, "(?i)powershell\\.exe$|pwsh\\.exe$")
| where match(CommandLine, "(?i)\\s-(enc|encodedcommand)\\s+")
| table _time host User Image CommandLine ParentImage
| sort - _time`,
    kql: String.raw`DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(enc|encodedcommand)\s+"
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc`,
  },
  {
    id: 'SS-004', title: 'Unusual outbound transfer', category: 'Network activity', severity: 'high', technique: 'T1041 · Exfiltration over C2',
    description: 'Find more than 500 MB sent from one host to one destination in 15 minutes. Validate business context and destination ownership; volume alone is not proof of exfiltration.',
    schema: 'SPL: index=firewall fields src_ip, dest_ip, bytes_out, direction. KQL: custom FirewallLogs_CL fields SourceIP_s, DestinationIP_s, BytesOut_d, Direction_s.',
    spl: String.raw`index=firewall direction=outbound
| bin _time span=15m
| stats sum(bytes_out) AS bytes_sent
    count AS connections BY _time src_ip dest_ip
| where bytes_sent>500000000
| eval megabytes=round(bytes_sent/1000000, 2)
| sort - bytes_sent`,
    kql: String.raw`FirewallLogs_CL
| where Direction_s == "outbound"
| summarize BytesSent = sum(BytesOut_d), Connections = count()
    by SourceIP_s, DestinationIP_s, bin(TimeGenerated, 15m)
| where BytesSent > 500000000
| extend Megabytes = round(BytesSent / 1000000.0, 2)
| order by BytesSent desc`,
  },
  {
    id: 'SS-005', title: 'VPN from a hosting network', category: 'VPN & identity', severity: 'medium', technique: 'T1090 · Proxy',
    description: 'Flag successful VPN sessions from a curated hosting/proxy ASN watchlist. The example ASN is illustrative and must be replaced with your reviewed threat-intelligence list.',
    schema: 'SPL: vpn logs enriched with src_asn. KQL: VPNLogs_CL with Result_s, SourceASN_d, User_s, SourceIP_s. ASN 64500 is a documentation example.',
    spl: String.raw`index=vpn action=success
| where src_asn IN (64500)
| stats count AS sessions values(src_ip) AS source_ips
    earliest(_time) AS first_seen latest(_time) AS last_seen
    BY user src_asn
| convert ctime(first_seen) ctime(last_seen)`,
    kql: String.raw`let ReviewedProxyASNs = dynamic([64500]);
VPNLogs_CL
| where Result_s == "success"
| where tolong(SourceASN_d) in (ReviewedProxyASNs)
| summarize Sessions = count(), SourceIPs = make_set(SourceIP_s),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by User_s, SourceASN_d`,
  },
];

export function RuleStudio() {
  const [selectedId, setSelectedId] = useState('SS-001');
  const [language, setLanguage] = useState<'spl' | 'kql'>('spl');
  const [query, setQuery] = useState('');
  const [enabled, setEnabled] = useState<string[]>(rules.map(r => r.id));
  const [copyStatus, setCopyStatus] = useState('');
  const selected = rules.find(rule => rule.id === selectedId)!;
  const filtered = rules.filter(rule => `${rule.title} ${rule.category} ${rule.id}`.toLowerCase().includes(query.toLowerCase()));
  async function copy() {
    try { await navigator.clipboard.writeText(selected[language]); setCopyStatus('Copied'); }
    catch { setCopyStatus('Clipboard unavailable — select the query to copy.'); }
    setTimeout(() => setCopyStatus(''), 3000);
  }
  return <div className="kp-page">
    <div className="kp-page-heading"><div><div className="kp-eyebrow">DETECTION ENGINEERING</div><h1>Detection rules<span className="kp-title-dot">.</span></h1><p>Turn signals into intelligence. Explore the logic behind every detection.</p></div><div className="kp-heading-tag"><Code2 size={15} /> 5 reference rules</div></div>
    <div className="kp-callout"><Info size={16} /><span>Reference library for your SIEM. Templates need schema mapping and tuning in Splunk or Microsoft Sentinel; switches below only change this session’s reference selection.</span></div>
    <div className="kp-rule-layout">
      <section className="kp-panel kp-rule-list"><div className="kp-panel-heading"><h2>Rule library</h2><span className="kp-muted">{rules.length} rules</span></div><label className="kp-search"><Search size={16}/><input aria-label="Search detection rules" placeholder="Search rules…" value={query} onChange={e => setQuery(e.target.value)} /></label><div className="kp-rule-items">{filtered.length ? filtered.map(rule => <button className={`kp-rule-item ${selectedId === rule.id ? 'kp-rule-selected' : ''}`} key={rule.id} onClick={() => { setSelectedId(rule.id); setCopyStatus(''); }}><div className="kp-rule-line"><span className="kp-rule-id">{rule.id}</span><span className={`kp-severity kp-${rule.severity}`}>{rule.severity}</span></div><strong>{rule.title}</strong><span>{rule.category}<ChevronRight size={14}/></span></button>) : <p className="kp-empty">No rules match your search.</p>}</div><div className="kp-list-foot"><ShieldCheck size={15}/><span>{enabled.length} reference selections enabled</span></div></section>
      <section className="kp-panel kp-rule-detail"><div className="kp-rule-description"><div className="kp-detail-meta"><span className="kp-rule-id">{selected.id}</span><span className={`kp-severity kp-${selected.severity}`}>{selected.severity}</span></div><div className="kp-detail-title"><h2>{selected.title}</h2><button className="kp-rule-toggle" aria-label={`${enabled.includes(selected.id) ? 'Disable' : 'Enable'} reference ${selected.title}`} aria-pressed={enabled.includes(selected.id)} onClick={() => setEnabled(list => list.includes(selected.id) ? list.filter(id => id !== selected.id) : [...list, selected.id])}>{enabled.includes(selected.id) ? <ToggleRight size={30}/> : <ToggleLeft size={30}/>}<span>{enabled.includes(selected.id) ? 'Selected' : 'Unselected'}</span></button></div><p>{selected.description}</p><span className="kp-technique"><Crosshair size={13}/>{selected.technique}</span></div><div className="kp-code-toolbar"><div className="kp-segment"><button aria-pressed={language === 'spl'} className={language === 'spl' ? 'kp-active' : ''} onClick={() => { setLanguage('spl'); setCopyStatus(''); }}>Splunk SPL</button><button aria-pressed={language === 'kql'} className={language === 'kql' ? 'kp-active' : ''} onClick={() => { setLanguage('kql'); setCopyStatus(''); }}>Microsoft KQL</button></div><button className="kp-copy" onClick={copy}>{copyStatus === 'Copied' ? <Check size={14}/> : <Copy size={14}/>} {copyStatus === 'Copied' ? 'Copied' : 'Copy query'}</button></div><div className="kp-code-box" tabIndex={0} aria-label={`${language.toUpperCase()} query`}><pre><code>{selected[language].split('\n').map((line, index) => <span className="kp-code-line" key={`${selected.id}-${language}-${index}`}><span className="kp-line-number" aria-hidden="true">{index + 1}</span><span>{line || ' '}</span></span>)}</code></pre></div><div className="kp-schema"><Fingerprint size={16}/><div><strong>Schema assumptions</strong><p>{selected.schema}</p></div></div><div className="kp-copy-status" role="status">{copyStatus !== 'Copied' ? copyStatus : ''}</div></section>
    </div>
  </div>;
}

const functions = [
  { id: 'GV', title: 'Govern', icon: FileCheck2, color: 'purple', summary: 'Set the direction.', description: 'Establish cybersecurity risk strategy, roles, policies, and oversight.', category: 'GV.PO · Policy', capability: 'Documented response boundaries', evidence: 'The demo identifies simulated actions and keeps a response audit trail.', gap: 'Organization-approved policies, ownership, and risk appetite are required.', state: 'Planning required' },
  { id: 'ID', title: 'Identify', icon: Fingerprint, color: 'blue', summary: 'Know your environment.', description: 'Understand assets, dependencies, and the risks that affect them.', category: 'ID.AM · Asset management', capability: 'Server inventory & risk context', evidence: 'The asset view exposes host identity, addresses, roles, status, and risk.', gap: 'Connect authoritative inventory sources and assign criticality and owners.', state: 'Demo capability' },
  { id: 'PR', title: 'Protect', icon: LockKeyhole, color: 'green', summary: 'Reduce your exposure.', description: 'Apply safeguards that manage cybersecurity risks and preserve resilience.', category: 'PR.PS · Platform security', capability: 'Containment & sanitization workflow', evidence: 'Server controls record proposed block, isolate, and sanitize state changes.', gap: 'Production enforcement, least privilege, and approved change controls are not connected.', state: 'Simulated control' },
  { id: 'DE', title: 'Detect', icon: Crosshair, color: 'yellow', summary: 'Find the signal.', description: 'Monitor assets and analyze anomalies and potentially adverse events.', category: 'DE.CM / DE.AE · Monitoring & analysis', capability: 'Log monitoring & event correlation', evidence: 'Ingested demo logs trigger local detections and correlated incident records.', gap: 'Validate real source coverage, detection precision, retention, and escalation SLAs.', state: 'Demo capability' },
  { id: 'RS', title: 'Respond', icon: Shield, color: 'orange', summary: 'Act with confidence.', description: 'Manage, analyze, communicate, and mitigate detected incidents.', category: 'RS.AN / RS.MI · Analysis & mitigation', capability: 'Triage, investigate & contain', evidence: 'Analysts can investigate logs and incidents and record containment decisions.', gap: 'Define production runbooks, communications, authorization, and evidence handling.', state: 'Demo capability' },
  { id: 'RC', title: 'Recover', icon: RotateCcw, color: 'teal', summary: 'Restore and improve.', description: 'Restore affected operations and communicate recovery activities.', category: 'RC.RP · Recovery plan execution', capability: 'Recovery review & audit history', evidence: 'The audit history supports reviewing response decisions after a simulated incident.', gap: 'Backups, restoration testing, service verification, and recovery communications remain external.', state: 'Planning required' },
];

export function NistFramework() {
  const [activeId, setActiveId] = useState('DE');
  const active = functions.find(item => item.id === activeId)!;
  const Icon = active.icon;
  return <div className="kp-page">
    <div className="kp-page-heading"><div><div className="kp-eyebrow">SECURITY WITH STRUCTURE</div><h1>NIST framework<span className="kp-title-dot">.</span></h1><p>Six functions. One connected approach to cyber resilience.</p></div><div className="kp-heading-tag"><ShieldCheck size={15}/> CSF 2.0</div></div>
    <div className="kp-nist-banner"><div className="kp-nist-orbit"><ShieldCheck size={34}/></div><div><span className="kp-eyebrow">FROM FRAMEWORK TO WORKFLOW</span><h2>Built around the way defenders work.</h2><p>Explore how Shadow Shade’s training capabilities relate to NIST CSF 2.0 and what remains for a real-world implementation.</p></div><span className="kp-outline-tag">Capability mapping</span></div>
    <div className="kp-function-grid">{functions.map(item => { const ItemIcon = item.icon; return <button className={`kp-function kp-tone-${item.color} ${item.id === activeId ? 'kp-function-active' : ''}`} key={item.id} onClick={() => setActiveId(item.id)} aria-pressed={item.id === activeId}><div><span className="kp-function-icon"><ItemIcon size={21}/></span><span className="kp-function-id">{item.id}</span></div><h3>{item.title}</h3><p>{item.summary}</p><span className="kp-function-bottom">Explore function <ArrowRight size={14}/></span></button>; })}</div>
    <section className="kp-panel kp-nist-detail"><div className="kp-nist-detail-top"><div className={`kp-nist-detail-icon kp-tone-${active.color}`}><Icon size={24}/></div><div><span className="kp-eyebrow">{active.category}</span><h2>{active.title}</h2><p>{active.description}</p></div><span className="kp-status-tag">{active.state}</span></div><div className="kp-evidence-grid"><div><span className="kp-evidence-label"><Workflow size={15}/> Shadow Shade capability</span><h3>{active.capability}</h3><p>{active.evidence}</p></div><div><span className="kp-evidence-label"><Target size={15}/> Implementation next step</span><h3>Make it operational</h3><p>{active.gap}</p></div></div></section>
    <div className="kp-callout"><Info size={16}/><span>This is an educational capability mapping, not a compliance assessment or NIST certification. CSF outcomes require organizational evidence and risk-based evaluation.</span></div>
  </div>;
}

const questions = [
  { question: 'A user signs into the VPN from India and Germany within 8 minutes. What should you do first?', options: ['Immediately delete the user account', 'Validate the sign-in context, IP reputation, and geolocation', 'Mark both events safe because the password worked', 'Disable logging to reduce the alert volume'], answer: 1, explanation: 'Investigate context first. Corporate proxies, VPN egress, and geolocation errors can mimic impossible travel. Check MFA, device details, user history, and session activity before following the containment playbook.', skill: 'Identity & VPN analysis' },
  { question: 'One source IP fails to log in to 30 different accounts in 5 minutes. Which pattern is most likely?', options: ['Password spraying', 'A scheduled backup', 'DNS tunneling', 'A normal single-user typo'], answer: 0, explanation: 'Password spraying targets many accounts, often with a small number of common passwords, to avoid per-account lockout thresholds. Correlate the source, time window, distinct usernames, and any subsequent successful sign-in.', skill: 'Event correlation' },
  { question: 'Which evidence should you preserve before isolating a potentially compromised server?', options: ['Only its desktop wallpaper', 'Nothing; isolation guarantees evidence is preserved', 'Relevant logs, process and network context, and investigation timestamps', 'Only the server’s marketing name'], answer: 2, explanation: 'Preserve relevant evidence and chain-of-custody context according to policy. Coordinate volatile data collection with containment urgency; do not delay critical containment when active harm requires immediate action.', skill: 'Incident response' },
  { question: 'Which NIST CSF 2.0 function includes continuous monitoring and analysis of adverse events?', options: ['Govern', 'Recover', 'Protect', 'Detect'], answer: 3, explanation: 'Detect includes Continuous Monitoring (DE.CM) and Adverse Event Analysis (DE.AE). Respond addresses actions taken after detection, while Recover focuses on restoring operations.', skill: 'NIST CSF 2.0' },
  { question: 'A PowerShell encoded-command alert is triggered by approved administration software. What is the best next step?', options: ['Disable every PowerShell rule permanently', 'Document the finding and tune a narrow, verified exception', 'Block all administrators indefinitely', 'Ignore every future alert from that server'], answer: 1, explanation: 'Confirm the approved activity, document your evidence, and tune a narrow exception with an owner and review date. Broad exclusions create detection blind spots and can hide real abuse.', skill: 'Detection engineering' },
];

export function AnalystQuiz() {
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<(number | null)[]>(Array(5).fill(null));
  const [checked, setChecked] = useState<boolean[]>(Array(5).fill(false));
  const [complete, setComplete] = useState(false);
  const question = questions[index];
  const score = answers.filter((answer, i) => answer === questions[i].answer).length;
  function reset() { setIndex(0); setAnswers(Array(5).fill(null)); setChecked(Array(5).fill(false)); setComplete(false); }
  return <div className="kp-page">
    <div className="kp-page-heading"><div><div className="kp-eyebrow">KEEP YOUR INSTINCTS SHARP</div><h1>Analyst academy<span className="kp-title-dot">.</span></h1><p>Five real-world decisions. Put your SOC knowledge to the test.</p></div><div className="kp-heading-tag"><GraduationCap size={16}/> SOC fundamentals</div></div>
    <div className="kp-quiz-layout"><aside className="kp-panel kp-quiz-sidebar"><div className="kp-quiz-emblem"><GraduationCap size={34}/></div><span className="kp-eyebrow">THE ANALYST’S EDGE</span><h2>Think like<br/>a defender.</h2><p>Build confidence in the decisions that matter when an alert becomes an incident.</p><div className="kp-quiz-facts"><span><BookOpen size={15}/>5 scenario questions</span><span><Target size={15}/>Immediate explanations</span><span><ShieldCheck size={15}/>Foundations, reinforced</span></div><div className="kp-quiz-sidebar-bottom">SHADOW SHADE <span>FIELD GUIDE / 001</span></div></aside>
      <section className="kp-panel kp-quiz-main">{complete ? <div className="kp-quiz-result"><div className="kp-result-icon"><Sparkles size={35}/></div><span className="kp-eyebrow">EXERCISE COMPLETE</span><h2>{score === 5 ? 'Sharp instincts.' : score >= 3 ? 'Good progress, analyst.' : 'Every signal is a lesson.'}</h2><p>{score === 5 ? 'You navigated every scenario. Keep practicing and applying context to your detections.' : 'Review the explanations and try again to strengthen your response instincts.'}</p><div className="kp-score"><strong>{score}</strong><span>/ 5</span></div><span className="kp-score-label">questions answered correctly</span><div className="kp-result-breakdown">{questions.map((q, i) => <div key={q.skill}><span>{answers[i] === q.answer ? <CheckCircle2 size={17}/> : <X size={17}/>}</span><span>{q.skill}</span><span>{answers[i] === q.answer ? 'Correct' : 'Review'}</span></div>)}</div><button className="kp-primary" onClick={reset}><RotateCcw size={16}/>Try again</button></div> : <><div className="kp-quiz-progress-heading"><span>QUESTION {String(index + 1).padStart(2, '0')} <span className="kp-muted">/ 05</span></span><span>{question.skill}</span></div><div className="kp-progress-track"><span style={{width: `${((index + 1) / 5) * 100}%`}}/></div><h2 className="kp-question">{question.question}</h2><div className="kp-options" role="radiogroup" aria-label={`Question ${index + 1} answers`}>{question.options.map((option, i) => { const isSelected = answers[index] === i; const isAnswer = checked[index] && i === question.answer; const wrong = checked[index] && isSelected && i !== question.answer; return <button key={option} role="radio" aria-checked={isSelected} disabled={checked[index]} onKeyDown={event => { const directions: Record<string, number> = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }; if (event.key in directions || event.key === 'Home' || event.key === 'End') { event.preventDefault(); const next = event.key === 'Home' ? 0 : event.key === 'End' ? question.options.length - 1 : (i + directions[event.key] + question.options.length) % question.options.length; setAnswers(list => list.map((answer, n) => n === index ? next : answer)); const buttons = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]'); buttons?.[next]?.focus(); } }} className={`kp-option ${isSelected ? 'kp-option-selected' : ''} ${isAnswer ? 'kp-option-correct' : ''} ${wrong ? 'kp-option-wrong' : ''}`} onClick={() => setAnswers(list => list.map((answer, n) => n === index ? i : answer))}><span className="kp-option-letter">{String.fromCharCode(65 + i)}</span><span>{option}</span><span className="kp-option-indicator">{isAnswer ? <Check size={17}/> : wrong ? <X size={17}/> : null}</span></button>; })}</div>{checked[index] && <div className={`kp-explanation ${answers[index] === question.answer ? 'kp-explanation-correct' : ''}`} role="status"><strong>{answers[index] === question.answer ? <><CheckCheck size={17}/>Exactly right.</> : <><Info size={17}/>A learning moment.</>}</strong><p>{question.explanation}</p></div>}<div className="kp-quiz-actions"><span><ShieldCheck size={14}/>Practice makes a prepared analyst.</span>{!checked[index] ? <button className="kp-primary" disabled={answers[index] === null} onClick={() => setChecked(list => list.map((value, n) => n === index ? true : value))}>Check answer<ArrowRight size={16}/></button> : <button className="kp-primary" onClick={() => index === 4 ? setComplete(true) : setIndex(index + 1)}>{index === 4 ? 'View results' : 'Next question'}<ArrowRight size={16}/></button>}</div></> }</section></div>
  </div>;
}
