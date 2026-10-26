import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp, createStore } from './index.mjs';
import { seedState } from './seed.mjs';

async function fixture(t) {
  const dataDir = mkdtempSync(join(tmpdir(), 'shadow-shade-test-'));
  const { server, store } = createApp({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dataDir, { recursive: true, force: true });
  });
  const request = async (path, method = 'GET', body) => {
    const response = await fetch(`${base}${path}`, { method, ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  };
  return { request, store, dataDir, base };
}

test('health and initial workspace expose usable telemetry and incident references', async (t) => {
  const { request } = await fixture(t);
  const health = await request('/api/health');
  assert.equal(health.status, 200);
  assert.equal(health.body.mode, 'demo');
  const { status, body } = await request('/api/state');
  assert.equal(status, 200);
  assert.equal(body.logs.length, 30);
  assert.equal(body.assets.length, 5);
  assert.equal(body.incidents.length, 3);
  assert.ok(body.incidents.every((incident) => incident.logIds.every((id) => body.logs.some((log) => log.id === id))));
  const bruteForce = body.incidents.find((incident) => incident.correlationKey.startsWith('SS-AUTH-002:'));
  const failureTimes = bruteForce.logIds.map((id) => Date.parse(body.logs.find((log) => log.id === id).time));
  assert.ok(Math.max(...failureTimes) - Math.min(...failureTimes) <= 15 * 60_000);
});

test('VPN detection raises an alert and correlates repeated events without duplicates', async (t) => {
  const { request } = await fixture(t);
  const input = { message: 'VPN authentication succeeded', source: 'FortiGate', category: 'VPN', ip: '185.220.101.42', user: 'new.user', assetId: 'srv-02', country: 'Netherlands' };
  const first = await request('/api/logs', 'POST', input);
  assert.equal(first.status, 201);
  assert.equal(first.body.logs[0].severity, 'critical');
  assert.equal(first.body.logs[0].ruleId, 'SS-VPN-001');
  const second = await request('/api/logs', 'POST', input);
  const matching = second.body.incidents.filter((incident) => incident.correlationKey === 'SS-VPN-001:new.user');
  assert.equal(matching.length, 1);
  assert.equal(matching[0].logIds.length, 2);
  assert.ok(second.body.audit.some((entry) => entry.action.includes('Alert raised')));
});

test('VPN country change within correlation window raises an impossible-travel triage signal', async (t) => {
  const { request } = await fixture(t);
  const input = { message: 'VPN session opened', category: 'VPN', ip: '192.0.2.24', user: 'travel.user', assetId: 'srv-02' };
  await request('/api/logs', 'POST', { ...input, country: 'India' });
  const result = await request('/api/logs', 'POST', { ...input, country: 'Germany' });
  const incident = result.body.incidents.find((entry) => entry.correlationKey === 'SS-VPN-001:travel.user');
  assert.equal(incident.logIds.length, 2);
  assert.equal(incident.confidence, 82);
});

test('five authentication failures correlate into one brute force incident', async (t) => {
  const { request } = await fixture(t);
  const input = { message: 'Login failed: invalid password', category: 'Authentication', ip: '192.0.2.77', user: 'test.admin', assetId: 'srv-03' };
  let result;
  for (let attempt = 0; attempt < 5; attempt++) result = await request('/api/logs', 'POST', input);
  const incident = result.body.incidents.find((entry) => entry.correlationKey === 'SS-AUTH-002:192.0.2.77:test.admin');
  assert.ok(incident);
  assert.equal(incident.logIds.length, 5);
  assert.equal(result.body.logs[0].severity, 'high');
});

test('encoded PowerShell and unusual outbound events produce specific alerts', async (t) => {
  const { request } = await fixture(t);
  const execution = await request('/api/logs', 'POST', { message: 'powershell.exe -EncodedCommand SQBFAFgA', category: 'Endpoint', assetId: 'srv-01' });
  assert.equal(execution.body.logs[0].ruleId, 'SS-EXEC-003');
  const network = await request('/api/logs', 'POST', { message: 'Unusual outbound transfer of 500MB', category: 'Network', assetId: 'srv-04' });
  assert.equal(network.body.logs[0].ruleId, 'SS-NET-004');
});

test('response actions persist and append an audit record without external enforcement', async (t) => {
  const { request, dataDir } = await fixture(t);
  let result = await request('/api/logs/EVT-1048', 'PATCH', { action: 'block' });
  assert.equal(result.body.logs.find((log) => log.id === 'EVT-1048').status, 'blocked');
  result = await request('/api/assets/srv-02', 'PATCH', { action: 'isolate' });
  assert.equal(result.body.assets.find((asset) => asset.id === 'srv-02').status, 'isolated');
  assert.equal(result.body.audit[0].action, 'Simulated server response: isolate');
  result = await request('/api/incidents/INC-0241', 'PATCH', { action: 'investigate' });
  assert.equal(result.body.incidents.find((incident) => incident.id === 'INC-0241').status, 'investigating');
  const restored = createStore({ dataDir }).getState();
  assert.equal(restored.assets.find((asset) => asset.id === 'srv-02').status, 'isolated');
  assert.equal(restored.logs.find((log) => log.id === 'EVT-1048').status, 'blocked');
});

test('invalid bodies, values, routes, and actions return useful client errors', async (t) => {
  const { request, base } = await fixture(t);
  for (const input of [null, [], {}, { message: ' ' }, { message: 'x'.repeat(4001) }, { message: 'test', ip: 'bad-ip' }, { message: 'test', severity: 'urgent' }, { message: 'test', assetId: 'missing' }, { message: 'test', country: 42 }]) {
    const result = await request('/api/logs', 'POST', input);
    assert.equal(result.status, 400);
    assert.ok(result.body.error);
  }
  assert.equal((await request('/api/assets/srv-01', 'PATCH', { action: 'delete' })).status, 400);
  assert.equal((await request('/api/assets/missing', 'PATCH', { action: 'isolate' })).status, 404);
  assert.equal((await request('/api/unknown')).status, 404);
  const malformed = await fetch(`${base}/api/logs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' });
  assert.equal(malformed.status, 400);
  const unsupported = await fetch(`${base}/api/logs`, { method: 'POST', body: 'anything' });
  assert.equal(unsupported.status, 415);
  const tooLarge = await request('/api/logs', 'POST', { message: 'x'.repeat(70_000) });
  assert.equal(tooLarge.status, 413);
});

test('simulation exercises VPN and authentication ingestion together', async (t) => {
  const { request } = await fixture(t);
  const result = await request('/api/demo', 'POST');
  assert.equal(result.status, 200);
  assert.equal(result.body.logs.length, 36);
  assert.ok(result.body.incidents.some((incident) => incident.correlationKey === 'SS-VPN-001:j.rivera'));
  assert.ok(result.body.incidents.some((incident) => incident.correlationKey === 'SS-AUTH-002:203.0.113.77:svc.deploy'));
});

test('production mode serves assets and SPA routes while keeping API errors distinct', async (t) => {
  const dataDir = mkdtempSync(join(tmpdir(), 'shadow-shade-static-test-'));
  const staticDir = join(dataDir, 'dist');
  mkdirSync(join(staticDir, 'assets'), { recursive: true });
  writeFileSync(join(staticDir, 'index.html'), '<html>Shadow Shade</html>');
  writeFileSync(join(staticDir, 'assets/app.js'), 'console.log("Shadow Shade")');
  symlinkSync(join(dataDir, 'state.json'), join(staticDir, 'escaped.json'));
  const { server } = createApp({ dataDir, staticDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    rmSync(dataDir, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const index = await fetch(`${base}/`);
  assert.equal(index.status, 200);
  assert.match(index.headers.get('content-type'), /text\/html/);
  assert.match(await index.text(), /Shadow Shade/);
  const spa = await fetch(`${base}/investigation/example`);
  assert.equal(spa.status, 200);
  const script = await fetch(`${base}/assets/app.js`);
  assert.match(script.headers.get('content-type'), /javascript/);
  assert.equal((await fetch(`${base}/assets/missing.js`)).status, 404);
  assert.equal((await fetch(`${base}/api/missing`)).status, 404);
  assert.equal((await fetch(`${base}/api`)).status, 404);
  assert.equal((await fetch(`${base}/%2E%2E%2Fstate.json`)).status, 403);
  assert.equal((await fetch(`${base}/escaped.json`)).status, 403);
});

function deterministicStore(t) {
  const dataDir = mkdtempSync(join(tmpdir(), 'shadow-shade-clock-test-'));
  let time = Date.parse('2026-10-26T12:00:00.000Z');
  const store = createStore({ dataDir, clock: () => time });
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  return { store, advance: (milliseconds) => { time += milliseconds; } };
}

test('country-change correlation excludes expired events, unknown identities, failed sessions, and case-only changes', (t) => {
  const { store, advance } = deterministicStore(t);
  const input = { message: 'VPN session opened', category: 'VPN', ip: '192.0.2.24', user: 'window.user', assetId: 'srv-02' };
  store.ingest({ ...input, country: 'India' });
  advance(15 * 60_000 + 1);
  store.ingest({ ...input, country: 'Germany' });
  assert.ok(!store.getState().incidents.some((incident) => incident.correlationKey === 'SS-VPN-001:window.user'));
  const result = store.ingest({ ...input, country: 'France' });
  const incident = result.incidents.find((entry) => entry.correlationKey === 'SS-VPN-001:window.user');
  assert.equal(incident.logIds.length, 2);
  store.ingest({ ...input, user: 'case.user', country: 'India' });
  store.ingest({ ...input, user: 'CASE.USER', country: 'india' });
  store.ingest({ ...input, user: 'failed.user', country: 'India' });
  store.ingest({ ...input, user: 'failed.user', country: 'Germany', message: 'VPN authentication failed' });
  store.ingest({ ...input, user: undefined, country: 'India' });
  store.ingest({ ...input, user: undefined, country: 'Germany' });
  for (const user of ['case.user', 'failed.user', 'unknown']) {
    assert.ok(!store.getState().incidents.some((entry) => entry.correlationKey === `SS-VPN-001:${user}`));
  }
});

test('authentication correlation requires five actual failures within the inclusive 15-minute window', (t) => {
  const { store, advance } = deterministicStore(t);
  const input = { message: 'Login failed: invalid password', category: 'Authentication', ip: '192.0.2.66', user: 'window.admin', assetId: 'srv-03' };
  for (let attempt = 0; attempt < 4; attempt++) store.ingest(input);
  for (let attempt = 0; attempt < 4; attempt++) store.ingest({ ...input, category: 'System', message: 'File integrity check failed' });
  store.ingest({ ...input, message: 'No authentication failures detected' });
  assert.ok(!store.getState().incidents.some((incident) => incident.correlationKey === 'SS-AUTH-002:192.0.2.66:window.admin'));
  advance(15 * 60_000);
  let result = store.ingest({ ...input, user: 'WINDOW.ADMIN' });
  let incident = result.incidents.find((entry) => entry.correlationKey === 'SS-AUTH-002:192.0.2.66:window.admin');
  assert.equal(incident.logIds.length, 5);
  store.act('incidents', incident.id, 'resolve');
  advance(1);
  result = store.ingest(input);
  assert.equal(result.incidents.filter((entry) => entry.correlationKey === incident.correlationKey).length, 1, 'Expired failures cannot create another incident');
  for (let attempt = 0; attempt < 3; attempt++) result = store.ingest(input);
  incident = result.incidents.find((entry) => entry.correlationKey === 'SS-AUTH-002:192.0.2.66:window.admin' && entry.status === 'open');
  assert.ok(incident);
  assert.equal(incident.logIds.length, 5);
});

test('ingestion rate expires on read and all response options are audited', (t) => {
  const { store, advance } = deterministicStore(t);
  assert.ok(store.getState().stats.ingestRate > 0);
  advance(61_000);
  assert.equal(store.getState().stats.ingestRate, 0);
  for (const [action, status] of Object.entries({ block: 'blocked', investigate: 'investigating', safe: 'safe' })) {
    const result = store.act('logs', 'EVT-1048', action);
    assert.equal(result.logs.find((log) => log.id === 'EVT-1048').status, status);
    assert.equal(result.audit[0].action, `Log response: ${action}`);
  }
  for (const [action, status] of Object.entries({ block: 'blocked', sanitize: 'sanitized', investigate: 'investigating', isolate: 'isolated' })) {
    const result = store.act('assets', 'srv-02', action);
    assert.equal(result.assets.find((asset) => asset.id === 'srv-02').status, status);
    assert.equal(result.audit[0].action, `Simulated server response: ${action}`);
  }
});

test('log retention trims missing evidence references and caps the audit trail', (t) => {
  const dataDir = mkdtempSync(join(tmpdir(), 'shadow-shade-retention-test-'));
  t.after(() => rmSync(dataDir, { recursive: true, force: true }));
  const state = seedState();
  const oldest = state.logs.at(-1);
  state.incidents[0].logIds.push(oldest.id);
  state.logs = [...Array.from({ length: 1970 }, (_, index) => ({ ...state.logs[0], id: `FILL-${index}` })), ...state.logs];
  state.audit = Array.from({ length: 500 }, (_, index) => ({ id: `AUD-FILL-${index}`, time: new Date().toISOString(), action: 'Test history', target: 'retention test' }));
  writeFileSync(join(dataDir, 'state.json'), JSON.stringify(state));
  const store = createStore({ dataDir });
  const result = store.ingest({ message: 'Normal application health check' });
  assert.equal(result.logs.length, 2000);
  assert.equal(result.audit.length, 500);
  assert.ok(!result.logs.some((log) => log.id === oldest.id));
  const retainedIds = new Set(result.logs.map((log) => log.id));
  assert.ok(result.incidents.every((incident) => incident.logIds.every((id) => retainedIds.has(id))));
});
