# Shadow Shade

**See beyond the noise.** A security operations workspace made by **Vaibhav Thakur**.

Shadow Shade combines an obsidian SIEM dashboard with a persistent local detection engine and SOC learning tools. It runs entirely on your machine with seeded demo telemetry; no external services, accounts, or API keys are required.

## Run the project

Use Node.js **22.12 or later** (validated with Node 24) and npm.

```sh
cd /workspace/Cybersecurity_1.2
npm ci
npm run dev
```

The development command starts Vite on port **5173** and the local API on **3001**. The frontend forwards `/api` requests to the backend. Stop both with Ctrl+C. Restart `npm run dev` after changing backend files; frontend changes reload automatically.

To run the production build locally:

```sh
npm run build
npm start
```

The Node server serves both the built frontend and API on port **3001**, bound to `127.0.0.1`. `PORT` changes the production port. Development expects the backend on its default port; leave `PORT` unset for `npm run dev`.

## Explore the workspace

- **Overview:** live refresh, event volume by time range, event severities, high-risk alerts, priority incidents, and JSON report export. Counts and charts are calculated from retained telemetry.
- **Log explorer:** search messages, IP addresses, identities, or event IDs; filter by severity, source, and status; inspect event evidence; investigate, block, or mark a signal as safe.
- **Event correlations:** inspect incident timelines, related events, ATT&CK tactic context, and detection confidence; investigate or resolve incidents.
- **Asset inventory:** view five demo servers, their roles and risk context; investigate, block, sanitize, or isolate; review the response audit trail.
- **Detection rules:** five searchable reference detections, each with both Splunk SPL and Microsoft KQL, documented schema assumptions, and copy controls.
- **NIST framework:** capability mapping and implementation gaps for all six NIST CSF 2.0 functions: Govern, Identify, Protect, Detect, Respond, and Recover.
- **Analyst academy:** five SOC scenario questions with explanations, scoring, and retry.

Use **Ingest logs** to submit a custom event. The sample Tor IP `185.220.101.42` triggers a suspicious VPN alert. **Generate events** creates a VPN event and five authentication failures so you can investigate correlated activity. Responses persist across browser refreshes and server restarts.

## Detection and response boundaries

This project is a **local SOC simulator**, not a production monitoring or enforcement service. It starts with 30 representative events, five servers, and three incident records. Seeded event severities and risk values are illustrative. New ingested events pass through a JavaScript heuristic engine:

| Detection | Local behavior |
| --- | --- |
| Suspicious VPN | Flags the sample Tor IP or suspicious VPN message patterns. Also correlates successful VPN activity for a known identity in different reported countries within 15 minutes. |
| Brute force | Correlates at least five authentication failures for the same source IP and identity within 15 minutes. |
| Encoded PowerShell | Flags PowerShell messages containing encoded command arguments. |
| Unusual egress | Flags messages that describe suspicious outbound transfers or exfiltration. |

Messages are analyzed as supplied; there is no IP reputation service, geographic distance calculation, or external log collector. Country differences are a triage signal and can have legitimate explanations. Investigate context before acting.

**Block, sanitize, and isolate record simulated local state changes and audit entries.** They do not change firewalls, terminate sessions, sanitize disks, or touch external servers. Marking a log safe does not automatically resolve its incident; analysts review incident status separately. Risk scores do not reset when an asset is marked sanitized.

SPL/KQL queries are educational templates for external SIEM deployment; Shadow Shade does not interpret or execute those languages. Reference-selection switches affect the current browser session, not backend detections. The external templates and local heuristic engine have different thresholds and schemas. NIST mappings identify relevant capabilities and remaining organizational controls; they are not a compliance assessment or certification.

## Validation

```sh
npm test             # Backend API, detection, correlation, persistence, and validation
npm run build        # Strict TypeScript check and production build
npm run test:ui      # Nine Chromium browser workflow tests
```

Browser tests start an isolated production server on port **3011** and use temporary telemetry storage. They do not alter the main demo workspace. They use `/usr/bin/chromium` when present; otherwise install the browser with `npx playwright install chromium`, or set `CHROMIUM_EXECUTABLE_PATH` to a compatible Chromium executable.

The browser suite covers log ingestion and responses, all four server actions, incident resolution, time filtering and report export, SPL/KQL selection, six NIST functions, all five quiz questions, and navigation across every page on a mobile viewport.

## API and persistence

The backend uses Node's HTTP server and a JSON file; no database installation is needed.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Local API readiness and demo mode |
| GET | `/api/state` | Telemetry, assets, incidents, audit trail, and stats |
| POST | `/api/logs` | Ingest a JSON event; `message` required, optional `source`, `category`, `ip`, `user`, `assetId`, `country`, `severity` |
| POST | `/api/demo` | Generate representative suspicious activity |
| PATCH | `/api/logs/:id` | `{ "action": "block" | "investigate" | "safe" }` |
| PATCH | `/api/assets/:id` | `{ "action": "block" | "sanitize" | "investigate" | "isolate" }` |
| PATCH | `/api/incidents/:id` | `{ "action": "investigate" | "resolve" }` |

Telemetry and decisions are saved to ignored `.data/state.json`. The simulator retains the newest **2,000 logs** and **500 audit entries**; incident evidence references are trimmed to retained events. Preserve or export that file before resetting a workspace. There is no authentication, multi-user permission system, or production evidence chain of custody; keep this local demo API off public networks.

## Project layout

```text
src/App.tsx                       Application shell and overview
src/components/OperationsPages.tsx Logs, assets, and incident investigations
src/components/KnowledgePanels.tsx Detection templates, NIST mapping, and quiz
server/index.mjs                  Local API, persistence, detection, and correlation
server/seed.mjs                   Representative demo dataset
server/index.test.mjs             Backend tests
scripts/dev.mjs                   Development process manager
tests/workspace.spec.ts           Browser workflow tests
```

Each cloud task already has an isolated checkout. Use the existing repository directly; a Git worktree is unnecessary unless explicitly requested.
