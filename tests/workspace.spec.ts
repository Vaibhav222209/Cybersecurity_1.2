import { test, expect, type Page } from '@playwright/test';
async function navigate(page: Page, label: string) { await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('button', { name: new RegExp('^' + label) }).click(); }
test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Security overview.' })).toBeVisible();
  await expect(page.locator('.metric-card')).toHaveCount(4);
});

test('overview uses telemetry, filters time, pauses polling, and exports a report', async ({ page, request }) => {
  const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
  const state = await (await request.get('/api/state')).json();
  await expect(page.locator('.metric-value-row strong').first()).toHaveText(String(state.logs.length).padStart(2, '0'));
  await page.getByLabel('Dashboard time range').selectOption('1');
  await expect(page.getByText('Across the last 1 hours')).toBeVisible();
  const lastHour = state.logs.filter((l: { time: string }) => Date.parse(l.time) >= Date.now() - 3600000).length;
  await expect(page.locator('.metric-value-row strong').first()).toHaveText(String(lastHour).padStart(2, '0'));
  await page.getByRole('button', { name: 'LIVE', exact: true }).click();
  await expect(page.getByRole('button', { name: 'PAUSED', exact: true })).toBeVisible();
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export report', exact: true }).click();
  const download = await downloadPromise; expect(download.suggestedFilename()).toMatch(/^shadow-shade-report-/);
  const stream = await download.createReadStream(); const chunks: Buffer[] = []; for await (const chunk of stream!) chunks.push(chunk);
  expect(JSON.parse(Buffer.concat(chunks).toString()).author).toBe('Vaibhav Thakur');
  expect(errors).toEqual([]);
});

test('custom VPN telemetry raises an alert and log decisions persist', async ({ page, request }) => {
  const message = 'Browser test VPN session from known Tor exit node';
  await page.getByRole('button', { name: 'Ingest logs', exact: true }).click();
  await page.getByLabel('Event message').fill(message);
  await page.getByLabel('User', { exact: true }).fill('');
  await page.getByRole('button', { name: 'Ingest event', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('row').filter({ hasText: message }).click();
  const dialog = page.getByRole('dialog', { name: 'Signal under the lens.' });
  await expect(dialog.getByText('SS-VPN-001', { exact: true })).toBeVisible();
  for (const [name, status] of [['Investigate', 'investigating'], ['Block event', 'blocked'], ['Mark as safe', 'safe']]) {
    await dialog.getByRole('button', { name, exact: true }).click();
    await expect(dialog.locator('.small-tag')).toHaveText(status);
  }
  await page.keyboard.press('Escape');
  const state = await (await request.get('/api/state')).json();
  expect(state.logs.find((l: { message: string }) => l.message === message).status).toBe('safe');
  expect(state.incidents.some((i: { title: string; logIds: string[] }) => i.title === 'Suspicious VPN activity' && i.logIds.includes(state.logs[0].id))).toBeTruthy();
});

test('log explorer supports search, severity filtering and event responses', async ({ page }) => {
  await navigate(page, 'Log explorer');
  await page.getByRole('textbox', { name: 'Search logs', exact: true }).fill('no-such-event-7291');
  await expect(page.getByRole('heading', { name: 'No matching results' })).toBeVisible();
  await page.getByRole('button', { name: 'Clear search', exact: true }).click();
  await page.getByLabel('Filter log severity').selectOption('critical');
  await expect(page.locator('.op-log-table tbody tr')).not.toHaveCount(0);
  for (const badge of await page.locator('.op-log-table tbody .op-severity').all()) await expect(badge).toHaveText('Critical');
  await page.getByRole('button', { name: /^Actions for/ }).first().click();
  await page.getByRole('button', { name: 'Investigate', exact: true }).click();
  await expect(page.locator('.op-log-table tbody tr').first().locator('.op-status')).toHaveText('Investigating');
});

test('all four server response actions change local state and appear in the audit trail', async ({ page, request }) => {
  await navigate(page, 'Asset inventory');
  const card = page.locator('.op-asset-card').first();
  const state = await (await request.get('/api/state')).json();
  const asset = state.assets[0];
  for (const [name, status] of [['Investigate server','investigating'], ['Sanitize server','sanitized'], ['Isolate server','isolated'], ['Block server','blocked']]) {
    await card.getByRole('button', { name: 'Respond', exact: true }).click();
    await card.getByRole('button', { name, exact: true }).click();
    await expect(card.locator('.op-asset-top .op-status')).toHaveText(new RegExp(status, 'i'));
  }
  const updated = await (await request.get('/api/state')).json();
  expect(updated.assets.find((a: {id:string}) => a.id === asset.id).status).toBe('blocked');
  expect(updated.audit.filter((a: {target:string}) => a.target === asset.id).length).toBeGreaterThanOrEqual(4);
});

test('correlated incidents show evidence and can be investigated and resolved', async ({ page }) => {
  await navigate(page, 'Event correlations');
  await expect(page.locator('.op-timeline-item')).not.toHaveCount(0);
  await page.locator('.op-incident-actions').getByRole('button', { name: 'Investigate', exact: true }).click();
  await expect(page.locator('.op-incident-meta .op-status')).toHaveText('Investigating');
  await page.getByRole('button', { name: 'Resolve incident', exact: true }).click();
  await expect(page.locator('.op-incident-meta .op-status')).toHaveText('Resolved');
  await page.getByLabel('Filter incidents').selectOption('resolved');
  await expect(page.locator('.op-incident-item')).not.toHaveCount(0);
});

test('SPL/KQL rule library has switchable templates and searchable rules', async ({ page }) => {
  await navigate(page, 'Detection rules');
  await expect(page.locator('.kp-rule-item')).toHaveCount(5);
  await expect(page.getByLabel('SPL query')).toContainText('index=vpn');
  await page.getByRole('button', { name: 'Microsoft KQL', exact: true }).click();
  await expect(page.getByLabel('KQL query')).toContainText('VPNLogs_CL');
  await page.getByRole('button', { name: 'Disable reference Impossible travel' }).click();
  await expect(page.getByRole('button', { name: 'Enable reference Impossible travel' })).toHaveAttribute('aria-pressed', 'false');
  await page.getByLabel('Search detection rules').fill('powershell');
  await expect(page.locator('.kp-rule-item')).toHaveCount(1);
  await page.locator('.kp-rule-item').click();
  await expect(page.getByLabel('KQL query')).toContainText('DeviceProcessEvents');
});

test('all six NIST CSF 2.0 functions expose capability evidence and implementation gaps', async ({ page }) => {
  await navigate(page, 'NIST framework');
  await expect(page.locator('.kp-function')).toHaveCount(6);
  for (const name of ['Govern','Identify','Protect','Detect','Respond','Recover']) {
    await page.locator('.kp-function').filter({ has: page.getByRole('heading', { name, exact: true }) }).click();
    await expect(page.locator('.kp-nist-detail').getByRole('heading', { name, exact: true })).toBeVisible();
    await expect(page.getByText('Make it operational', { exact: true })).toBeVisible();
  }
  await expect(page.getByText(/not a compliance assessment/)).toBeVisible();
});

test('five-question SOC quiz scores answers, explains decisions and resets', async ({ page }) => {
  await navigate(page, 'Analyst academy');
  const answers = [1,0,2,3,1];
  for (let i=0;i<5;i++) {
    await expect(page.getByRole('button', { name: 'Check answer', exact: true })).toBeDisabled();
    await page.getByRole('radio').nth(answers[i]).click();
    await page.getByRole('button', { name: 'Check answer', exact: true }).click();
    await expect(page.getByText('Exactly right.')).toBeVisible();
    await page.getByRole('button', { name: i === 4 ? 'View results' : 'Next question', exact: true }).click();
  }
  await expect(page.locator('.kp-score strong')).toHaveText('5');
  await page.getByRole('button', { name: 'Try again', exact: true }).click();
  await expect(page.getByRole('radio')).toHaveCount(4);
  await expect(page.getByRole('button', { name: 'Check answer', exact: true })).toBeDisabled();
});

test('mobile layout supports navigation and keeps every workspace page within the viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const label of ['Overview','Log explorer','Event correlations','Asset inventory','Detection rules','NIST framework','Analyst academy']) {
    await page.getByRole('button', { name: 'Toggle navigation', exact: true }).click();
    await navigate(page, label);
    await expect(page.locator('.sidebar')).not.toHaveClass(/is-open/);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), label).toBeTruthy();
  }
});
