export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export interface LogEvent { id: string; time: string; source: string; category: string; severity: Severity; message: string; ip: string; user: string; assetId: string; status: 'open' | 'investigating' | 'safe' | 'blocked'; ruleId?: string; country?: string; }
export interface Asset { id: string; name: string; ip: string; os: string; role: string; status: 'healthy' | 'investigating' | 'isolated' | 'blocked' | 'sanitized'; risk: number; lastSeen: string; }
export interface Incident { id: string; title: string; severity: Severity; status: 'open' | 'investigating' | 'resolved'; time: string; description: string; logIds: string[]; tactics: string[]; confidence: number; }
export interface AuditEvent { id: string; time: string; action: string; target: string; }
export interface WorkspaceState { logs: LogEvent[]; assets: Asset[]; incidents: Incident[]; audit: AuditEvent[]; stats: { eventsToday: number; ingestRate: number; coverage: number }; }
export type ActionFn = (path: string, action: string) => Promise<void>;
