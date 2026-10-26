import { spawn } from 'node:child_process';
const processes = [
  spawn(process.execPath, ['server/index.mjs'], { stdio: 'inherit' }),
  spawn(process.execPath, ['node_modules/vite/bin/vite.js'], { stdio: 'inherit' }),
];
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of processes) child.kill('SIGTERM');
  process.exitCode = code;
}
for (const child of processes) {
  child.on('error', error => { console.error(error.message); stop(1); });
  child.on('exit', (code, signal) => { if (!stopping) stop(code ?? (signal ? 1 : 0)); });
}
process.on('SIGINT', () => stop());
process.on('SIGTERM', () => stop());
