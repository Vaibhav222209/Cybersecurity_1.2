const minutesAgo = (now, minutes) => new Date(now - minutes * 60_000).toISOString();

export function seedState(now = Date.now()) {
  const assets = [
    { id: 'srv-01', name: 'prod-api-01', ip: '10.0.1.12', os: 'Ubuntu 24.04', role: 'Application server', status: 'healthy', risk: 24, lastSeen: minutesAgo(now, 0) },
    { id: 'srv-02', name: 'vpn-gateway', ip: '10.0.0.5', os: 'FortiOS 7.4', role: 'VPN gateway', status: 'healthy', risk: 87, lastSeen: minutesAgo(now, 0) },
    { id: 'srv-03', name: 'win-dc-01', ip: '10.0.2.10', os: 'Windows Server 2022', role: 'Domain controller', status: 'healthy', risk: 72, lastSeen: minutesAgo(now, 1) },
    { id: 'srv-04', name: 'db-primary', ip: '10.0.3.20', os: 'Ubuntu 24.04', role: 'Database server', status: 'healthy', risk: 18, lastSeen: minutesAgo(now, 1) },
    { id: 'srv-05', name: 'edge-proxy-01', ip: '10.0.0.8', os: 'Debian 12', role: 'Reverse proxy', status: 'healthy', risk: 42, lastSeen: minutesAgo(now, 2) },
  ];
  const rows = [
    [0, 'FortiGate', 'VPN', 'critical', 'VPN session from known Tor exit node; impossible travel detected for m.chen', '185.220.101.42', 'm.chen', 'srv-02', 'SS-VPN-001', 'Netherlands'],
    [1, 'Windows Security', 'Authentication', 'high', 'Repeated login failures: 12 attempts against a privileged account', '203.0.113.42', 'svc.admin', 'srv-03', 'SS-AUTH-002'],
    [2, 'Sysmon', 'Endpoint', 'critical', 'PowerShell launched with -EncodedCommand from an unexpected parent process', '10.0.2.10', 'svc.admin', 'srv-03', 'SS-EXEC-003'],
    [4, 'Nginx', 'Network', 'medium', 'Unusual outbound transfer: 284 MB to an external destination', '198.51.100.24', 'www-data', 'srv-05', 'SS-NET-004'],
    [6, 'FortiGate', 'VPN', 'high', 'Concurrent VPN session for m.chen from a second country within 8 minutes', '203.0.113.88', 'm.chen', 'srv-02', 'SS-VPN-001', 'Singapore'],
    [8, 'Linux Audit', 'System', 'info', 'Scheduled security package integrity check completed', '10.0.1.12', 'root', 'srv-01'],
    [10, 'PostgreSQL', 'Database', 'low', 'Read-only reporting session established', '10.0.3.20', 'reporting', 'srv-04'],
    [4, 'Windows Security', 'Authentication', 'high', 'Login failed: invalid password for privileged account', '203.0.113.42', 'svc.admin', 'srv-03', 'SS-AUTH-002'],
    [7, 'Windows Security', 'Authentication', 'high', 'Login failed: invalid password for privileged account', '203.0.113.42', 'svc.admin', 'srv-03', 'SS-AUTH-002'],
    [10, 'Windows Security', 'Authentication', 'medium', 'Login failed: invalid password for privileged account', '203.0.113.42', 'svc.admin', 'srv-03'],
    [13, 'Windows Security', 'Authentication', 'medium', 'Login failed: invalid password for privileged account', '203.0.113.42', 'svc.admin', 'srv-03'],
    [20, 'FortiGate', 'VPN', 'info', 'VPN authentication succeeded with MFA', '192.0.2.18', 'a.patel', 'srv-02', null, 'India'],
    [24, 'Nginx', 'Network', 'low', 'Rate limit applied to repeated requests for /admin', '198.51.100.55', 'anonymous', 'srv-05'],
    [31, 'Linux Audit', 'System', 'info', 'SSH public key authentication successful', '192.0.2.9', 'deploy', 'srv-01'],
    [38, 'PostgreSQL', 'Database', 'info', 'Automated database backup completed successfully', '10.0.3.20', 'backup', 'srv-04'],
    [45, 'Sysmon', 'Endpoint', 'low', 'New signed process observed: Windows Defender scan', '10.0.2.10', 'SYSTEM', 'srv-03'],
    [58, 'FortiGate', 'Network', 'medium', 'Port scan detected across 24 destination ports', '198.51.100.41', 'unknown', 'srv-05'],
    [74, 'Linux Audit', 'System', 'info', 'Configuration baseline matched approved version', '10.0.1.12', 'auditd', 'srv-01'],
    [90, 'Windows Security', 'Authentication', 'info', 'Interactive logon completed with MFA', '10.0.2.10', 'v.thakur', 'srv-03'],
    [110, 'Nginx', 'Network', 'info', 'TLS certificate verification completed', '10.0.0.8', 'nginx', 'srv-05'],
    [145, 'PostgreSQL', 'Database', 'low', 'Database connection pool recovered after threshold warning', '10.0.3.20', 'postgres', 'srv-04'],
    [192, 'FortiGate', 'VPN', 'info', 'Remote employee session closed normally', '192.0.2.18', 'a.patel', 'srv-02', null, 'India'],
    [235, 'Linux Audit', 'System', 'info', 'File integrity scan finished; no unexpected changes', '10.0.1.12', 'auditd', 'srv-01'],
    [282, 'Windows Security', 'Authentication', 'info', 'Service account authentication succeeded', '10.0.2.10', 'svc.backup', 'srv-03'],
    [400, 'Nginx', 'Network', 'info', 'Health probe returned HTTP 200 across all upstream services', '10.0.0.8', 'nginx', 'srv-05'],
    [530, 'Linux Audit', 'System', 'low', 'Approved deployment changed the application configuration', '10.0.1.12', 'deploy', 'srv-01'],
    [710, 'FortiGate', 'VPN', 'info', 'Employee VPN authentication completed with MFA', '192.0.2.26', 's.wilson', 'srv-02', null, 'United Kingdom'],
    [910, 'PostgreSQL', 'Database', 'info', 'Database replication health check passed', '10.0.3.20', 'replication', 'srv-04'],
    [1100, 'Windows Security', 'Authentication', 'low', 'Password reset completed through approved helpdesk workflow', '10.0.2.10', 'a.patel', 'srv-03'],
    [1380, 'Linux Audit', 'System', 'info', 'Daily baseline inventory synchronized with monitoring service', '10.0.1.12', 'auditd', 'srv-01'],
  ];
  const logs = rows.map((row, index) => ({
    id: `EVT-${String(1048 - index).padStart(4, '0')}`,
    time: minutesAgo(now, row[0]), source: row[1], category: row[2], severity: row[3],
    message: row[4], ip: row[5], user: row[6], assetId: row[7],
    ...(row[8] ? { ruleId: row[8] } : {}), ...(row[9] ? { country: row[9] } : {}),
    status: row[3] === 'info' || row[3] === 'low' ? 'safe' : 'open',
  }));
  const incidents = [
    { id: 'INC-0241', title: 'Suspicious VPN activity', severity: 'critical', status: 'open', time: minutesAgo(now, 0), description: 'A VPN session originated from a known Tor exit node. The same user connected from two countries within 8 minutes. Verify the employee through a trusted channel and review identity provider records before containment.', logIds: [logs[0].id, logs[4].id], tactics: ['Initial Access', 'Defense Evasion'], confidence: 96, correlationKey: 'SS-VPN-001:m.chen' },
    { id: 'INC-0240', title: 'Privileged account brute force', severity: 'high', status: 'open', time: minutesAgo(now, 1), description: 'Five authentication failures from one source targeted svc.admin. Review the authentication timeline, confirm account ownership, and check for a subsequent successful login.', logIds: [logs[1].id, logs[7].id, logs[8].id, logs[9].id, logs[10].id], tactics: ['Credential Access', 'Initial Access'], confidence: 91, correlationKey: 'SS-AUTH-002:203.0.113.42:svc.admin' },
    { id: 'INC-0239', title: 'Encoded PowerShell execution', severity: 'critical', status: 'open', time: minutesAgo(now, 2), description: 'An encoded PowerShell command ran on the domain controller with an unexpected parent process. Preserve process telemetry and inspect the decoded command in an isolated analysis environment.', logIds: [logs[2].id], tactics: ['Execution', 'Defense Evasion'], confidence: 89, correlationKey: 'SS-EXEC-003:srv-03' },
  ];
  return {
    version: 1, logs, assets, incidents,
    audit: [{ id: 'AUD-0001', time: minutesAgo(now, 5), action: 'Demo workspace initialized', target: 'Shadow Shade' }],
    stats: { eventsToday: logs.length, ingestRate: 0, coverage: 94 },
  };
}
