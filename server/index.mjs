import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isIP } from 'node:net';
import { seedState } from './seed.mjs';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const LOG_ACTIONS = { block: 'blocked', investigate: 'investigating', safe: 'safe' };
const ASSET_ACTIONS = { block: 'blocked', sanitize: 'sanitized', investigate: 'investigating', isolate: 'isolated' };
const INCIDENT_ACTIONS = { investigate: 'investigating', resolve: 'resolved' };
const MAX_BODY_BYTES = 64 * 1024;
const MAX_LOGS = 2000;
const CORRELATION_WINDOW_MS = 15 * 60_000;
const nowIso = () => new Date().toISOString();
const isVpnEvent = (log) => /\bvpn\b/i.test(`${log.category} ${log.source} ${log.message}`);
const isConnectedVpnEvent = (log) => isVpnEvent(log) && !/\bfail(?:ed|ure|ures)?\b|denied|rejected|closed|terminated|disconnected/i.test(log.message);
const normalizedUser = (log) => log.user.trim().toLowerCase();
const isAuthFailure = (log) => {
  const context = `${log.category} ${log.message}`;
  return /auth|login|logon/i.test(context)
    && /\bfail(?:ed|ure|ures)?\b|invalid (?:password|credentials)|incorrect password/i.test(log.message)
    && !/\bno (?:authentication |login |logon )?fail(?:ed|ure|ures)?\b/i.test(log.message);
};

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export function createStore({ dataDir = resolve(dirname(fileURLToPath(import.meta.url)), '../.data'), clock = Date.now } = {}) {
  mkdirSync(dataDir, { recursive: true });
  const file = resolve(dataDir, 'state.json');
  let state;
  if (existsSync(file)) {
    state = JSON.parse(readFileSync(file, 'utf8'));
    if (!state || state.version !== 1 || !['logs', 'assets', 'incidents', 'audit'].every((key) => Array.isArray(state[key]))) {
      throw new Error('Stored workspace has an unsupported format. Preserve the file before repairing it.');
    }
  } else {
    state = seedState(clock());
  }

  function refreshStats() {
    const currentTime = clock();
    const day = new Date(currentTime).toISOString().slice(0, 10);
    state.stats = {
      eventsToday: state.logs.filter((log) => log.time.startsWith(day)).length,
      ingestRate: state.logs.filter((log) => { const age = currentTime - Date.parse(log.time); return age >= 0 && age < 60_000; }).length,
      coverage: 94,
    };
  }

  function save() {
    refreshStats();
    const temporary = `${file}.tmp`;
    writeFileSync(temporary, JSON.stringify(state, null, 2), { mode: 0o600 });
    renameSync(temporary, file);
  }

  function audit(action, target) {
    state.audit.unshift({ id: `AUD-${randomUUID().slice(0, 8)}`, time: new Date(clock()).toISOString(), action, target });
    state.audit = state.audit.slice(0, 500);
  }

  function raiseIncident({ log, title, severity, description, tactics, confidence, ruleId, key, related = [] }) {
    log.severity = severity;
    log.ruleId = ruleId;
    const logIds = [...new Set([...related.map((entry) => entry.id), log.id])];
    const existing = state.incidents.find((incident) => incident.correlationKey === key && incident.status !== 'resolved' && clock() - Date.parse(incident.time) < 3_600_000);
    if (existing) {
      existing.logIds = [...new Set([...existing.logIds, ...logIds])];
      existing.time = log.time;
      existing.confidence = Math.max(existing.confidence, confidence);
    } else {
      state.incidents.unshift({ id: `INC-${randomUUID().slice(0, 6).toUpperCase()}`, title, severity, status: 'open', time: log.time, description, logIds, tactics, confidence, correlationKey: key });
      audit(`Alert raised: ${title}`, log.id);
    }
    const asset = state.assets.find((entry) => entry.id === log.assetId);
    if (asset) asset.risk = Math.max(asset.risk, severity === 'critical' ? 92 : 75);
  }

  function detect(log) {
    const recent = state.logs.filter((entry) => { const age = clock() - Date.parse(entry.time); return age >= 0 && age <= CORRELATION_WINDOW_MS; });
    const vpn = isVpnEvent(log);
    const user = normalizedUser(log);
    const otherCountries = log.country && user !== 'unknown' && isConnectedVpnEvent(log)
      ? recent.filter((entry) => entry.id !== log.id && isConnectedVpnEvent(entry) && normalizedUser(entry) === user && entry.country && entry.country.toLowerCase() !== log.country.toLowerCase())
      : [];
    if (vpn && (log.ip === '185.220.101.42' || /tor exit|impossible travel|concurrent vpn|unusual (?:vpn|location)|suspicious vpn/i.test(log.message) || otherCountries?.length)) {
      raiseIncident({ log, title: 'Suspicious VPN activity', severity: 'critical', description: 'VPN telemetry indicates a known Tor exit node, a suspicious VPN signal, or the same identity connecting from multiple countries within 15 minutes. Country differences alone are a triage signal and require user and location verification.', tactics: ['Initial Access', 'Defense Evasion'], confidence: log.ip === '185.220.101.42' ? 96 : 82, ruleId: 'SS-VPN-001', key: `SS-VPN-001:${user}`, related: otherCountries || [] });
    }
    if (isAuthFailure(log)) {
      const failures = recent.filter((entry) => entry.ip === log.ip && normalizedUser(entry) === user && isAuthFailure(entry));
      if (failures.length >= 5) {
        raiseIncident({ log, title: 'Authentication brute force', severity: 'high', description: `${failures.length} authentication failures from ${log.ip} targeted ${log.user} within 15 minutes. Verify account ownership and review subsequent successful sign-ins.`, tactics: ['Credential Access', 'Initial Access'], confidence: 91, ruleId: 'SS-AUTH-002', key: `SS-AUTH-002:${log.ip}:${user}`, related: failures });
      }
    }
    if (/powershell/i.test(log.message) && /-enc(?:odedcommand)?\b|encoded command|encodedcommand/i.test(log.message)) {
      raiseIncident({ log, title: 'Encoded PowerShell execution', severity: 'critical', description: 'Encoded PowerShell was observed. Review the process tree, preserve telemetry, and decode the command only in an isolated analysis environment. Legitimate administration can also use encoded commands.', tactics: ['Execution', 'Defense Evasion'], confidence: 89, ruleId: 'SS-EXEC-003', key: `SS-EXEC-003:${log.assetId}` });
    }
    if (/exfiltrat|suspicious (?:outbound|egress)|unusual outbound/i.test(log.message)) {
      raiseIncident({ log, title: 'Suspicious outbound transfer', severity: 'high', description: 'Network telemetry indicates an unusual outbound transfer. Compare volume against the normal baseline, inspect the destination, and confirm the business purpose.', tactics: ['Exfiltration', 'Command and Control'], confidence: 78, ruleId: 'SS-NET-004', key: `SS-NET-004:${log.assetId}` });
    }
  }

  function ingest(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new HttpError(400, 'A JSON object is required.');
    if (typeof input.message !== 'string' || !input.message.trim() || input.message.length > 4000) throw new HttpError(400, 'message must contain 1–4000 characters.');
    for (const field of ['source', 'category', 'user', 'assetId', 'country']) {
      if (input[field] !== undefined && (typeof input[field] !== 'string' || input[field].length > 128 || !input[field].trim())) throw new HttpError(400, `${field} must be a nonempty string of at most 128 characters.`);
    }
    if (input.ip !== undefined && (typeof input.ip !== 'string' || !isIP(input.ip))) throw new HttpError(400, 'ip must be a valid IPv4 or IPv6 address.');
    if (input.severity !== undefined && !SEVERITIES.has(input.severity)) throw new HttpError(400, 'severity must be critical, high, medium, low, or info.');
    if (input.assetId && !state.assets.some((asset) => asset.id === input.assetId)) throw new HttpError(400, 'assetId must reference a monitored asset.');
    const log = {
      id: `EVT-${randomUUID().slice(0, 8).toUpperCase()}`, time: new Date(clock()).toISOString(),
      source: input.source?.trim() || 'Manual ingest', category: input.category?.trim() || 'System',
      severity: input.severity || 'info', message: input.message.trim(), ip: input.ip || '127.0.0.1',
      user: input.user?.trim() || 'unknown', assetId: input.assetId || 'srv-01', status: 'open',
      ...(input.country ? { country: input.country.trim() } : {}),
    };
    state.logs.unshift(log);
    detect(log);
    if (log.severity === 'high' || log.severity === 'critical') log.status = 'open';
    state.logs = state.logs.slice(0, MAX_LOGS);
    const retainedIds = new Set(state.logs.map((entry) => entry.id));
    for (const incident of state.incidents) incident.logIds = incident.logIds.filter((id) => retainedIds.has(id));
    const asset = state.assets.find((entry) => entry.id === log.assetId);
    if (asset) asset.lastSeen = log.time;
    audit('Log ingested', log.id);
    save();
    return state;
  }

  function act(collection, id, action) {
    const actions = collection === 'logs' ? LOG_ACTIONS : collection === 'assets' ? ASSET_ACTIONS : INCIDENT_ACTIONS;
    if (!Object.hasOwn(actions, action)) throw new HttpError(400, `Allowed actions: ${Object.keys(actions).join(', ')}.`);
    const item = state[collection].find((entry) => entry.id === id);
    if (!item) throw new HttpError(404, 'The requested item was not found.');
    item.status = actions[action];
    audit(`${collection === 'assets' ? 'Simulated server response' : collection === 'logs' ? 'Log response' : 'Incident response'}: ${action}`, id);
    save();
    return state;
  }

  function simulate() {
    ingest({ message: 'VPN session from known Tor exit node; suspicious VPN access requires triage', source: 'FortiGate', category: 'VPN', ip: '185.220.101.42', user: 'j.rivera', country: 'Netherlands', assetId: 'srv-02' });
    for (let index = 0; index < 5; index++) {
      ingest({ message: `Login failed: invalid password (${index + 1}/5)`, source: 'Windows Security', category: 'Authentication', ip: '203.0.113.77', user: 'svc.deploy', assetId: 'srv-03', severity: 'medium' });
    }
    return state;
  }

  save();
  return { getState: () => { refreshStats(); return state; }, ingest, act, simulate, save };
}

async function readJson(request) {
  const contentType = request.headers['content-type']?.split(';')[0].trim();
  if (contentType !== 'application/json') throw new HttpError(415, 'Content-Type must be application/json.');
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body exceeds 64 KiB.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new HttpError(400, 'The request body must contain valid JSON.'); }
}

export function createApp(options = {}) {
  const store = options.store || createStore(options);
  const staticDir = options.staticDir === false ? null : resolve(options.staticDir || resolve(dirname(fileURLToPath(import.meta.url)), '../dist'));
  const server = http.createServer(async (request, response) => {
    const reply = (status, body) => {
      response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      response.end(JSON.stringify(body));
    };
    try {
      const { pathname } = new URL(request.url, 'http://localhost');
      if (request.method === 'GET' && pathname === '/api/health') return reply(200, { status: 'ok', mode: 'demo', time: nowIso() });
      if (request.method === 'GET' && pathname === '/api/state') return reply(200, store.getState());
      if (request.method === 'POST' && pathname === '/api/logs') return reply(201, store.ingest(await readJson(request)));
      if (request.method === 'POST' && pathname === '/api/demo') return reply(200, store.simulate());
      const actionMatch = /^\/api\/(logs|assets|incidents)\/([^/]+)$/.exec(pathname);
      if (request.method === 'PATCH' && actionMatch) {
        const body = await readJson(request);
        if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.action !== 'string') throw new HttpError(400, 'An action string is required.');
        let id;
        try { id = decodeURIComponent(actionMatch[2]); }
        catch { throw new HttpError(400, 'The item ID is malformed.'); }
        return reply(200, store.act(actionMatch[1], id, body.action));
      }
      if ((request.method === 'GET' || request.method === 'HEAD') && pathname !== '/api' && !pathname.startsWith('/api/') && staticDir && existsSync(resolve(staticDir, 'index.html'))) {
        let decodedPath;
        try { decodedPath = decodeURIComponent(pathname); }
        catch { throw new HttpError(400, 'The URL path is malformed.'); }
        const requestedFile = resolve(staticDir, `.${decodedPath}`);
        if (!requestedFile.startsWith(`${staticDir}${sep}`) && requestedFile !== staticDir) throw new HttpError(403, 'Path is outside the static directory.');
        if (decodedPath.includes('\0')) throw new HttpError(400, 'The URL path is invalid.');
        let file = requestedFile;
        if (!existsSync(file) || !statSync(file).isFile()) {
          if (extname(decodedPath)) return reply(404, { error: 'Static resource not found.' });
          file = resolve(staticDir, 'index.html');
        }
        const realStaticDir = realpathSync(staticDir);
        const realFile = realpathSync(file);
        if (!realFile.startsWith(`${realStaticDir}${sep}`)) throw new HttpError(403, 'Static resource is outside the static directory.');
        const contentTypes = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8', '.woff': 'font/woff', '.woff2': 'font/woff2' };
        response.writeHead(200, { 'content-type': contentTypes[extname(file)] || 'application/octet-stream', 'cache-control': extname(file) === '.html' ? 'no-cache' : 'public, max-age=3600', 'x-content-type-options': 'nosniff' });
        return response.end(request.method === 'HEAD' ? undefined : readFileSync(file));
      }
      reply(404, { error: 'Endpoint not found.' });
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 500) console.error('Shadow Shade request failed:', error.message);
      reply(status, { error: status === 500 ? 'An internal error occurred.' : error.message });
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  return { server, store };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3001);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be an integer from 1 to 65535.');
  const { server } = createApp();
  server.listen(port, '127.0.0.1', () => console.log(`Shadow Shade demo API listening on 127.0.0.1:${port}`));
  const shutdown = () => server.close(() => process.exit(0));
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
