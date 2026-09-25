import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { defineConfig, devices } from '@playwright/test';

const PYTHON_REPO =
  process.env.NK_PYTHON_REPO ?? '/Users/alessiodellasanta/Documents/noknowledge';
const PYTHON_BIN = process.env.NK_PYTHON ?? path.join(PYTHON_REPO, '.venv/bin/python');
const RELAY_PORT = 8231;
const RELAY_URL = `http://127.0.0.1:${RELAY_PORT}`;
const relayDataDir = mkdtempSync(path.join(tmpdir(), 'nk-e2e-relay-'));

export default defineConfig({
  testDir: './e2e',
  timeout: 180_000,
  expect: { timeout: 45_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], channel: 'chrome' } }],
  webServer: [
    {
      command: `${PYTHON_BIN} -m noknowledge.server --host 127.0.0.1 --port ${RELAY_PORT} --data-dir ${relayDataDir} --log-level warning`,
      cwd: PYTHON_REPO,
      url: `${RELAY_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 60_000,
      env: {
        NK_DISABLE_KEYRING: '1',
        PYTHONPATH: PYTHON_REPO,
        // One relay serves the whole run and every provisioning publishes a
        // prekey bundle plus a device list; production limits would throttle it.
        NK_BUNDLES_PER_HOUR: '100000',
        NK_MAILBOXES_PER_HOUR: '100000',
        NK_WRITES_PER_MINUTE: '100000',
      },
    },
    {
      command: 'npm run preview',
      url: 'http://127.0.0.1:4173',
      reuseExistingServer: false,
      timeout: 60_000,
      env: { NK_RELAY: RELAY_URL },
    },
  ],
});
