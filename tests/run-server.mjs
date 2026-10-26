import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../server/index.mjs';
const dataDir = mkdtempSync(join(tmpdir(), 'shadow-shade-ui-'));
const { server } = createApp({ dataDir });
server.listen(3011, '127.0.0.1');
let stopping = false;
function stop() {
  if (stopping) return;
  stopping = true;
  server.close(() => { rmSync(dataDir, { recursive: true, force: true }); process.exit(0); });
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
