import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as readline from 'node:readline';
import { fileURLToPath } from 'node:url';

export const PYTHON_REPO =
  process.env.NK_PYTHON_REPO ?? '/Users/alessiodellasanta/Documents/noknowledge';
export const PYTHON_BIN = process.env.NK_PYTHON ?? path.join(PYTHON_REPO, '.venv/bin/python');

const PEER_SCRIPT = fileURLToPath(new URL('../scripts/interop_peer.py', import.meta.url));

async function waitForHealth(url: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${url}/api/health`);
      if (response.ok) return;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`relay did not become healthy: ${String(lastError)}`);
}

export interface RelayHandle {
  url: string;
  stop: () => Promise<void>;
}

/** Start the Python reference relay on a free port with a throwaway data dir. */
export async function startRelay(): Promise<RelayHandle> {
  const port = 8100 + Math.floor(Math.random() * 1500);
  const dataDir = mkdtempSync(path.join(tmpdir(), 'nk-relay-'));
  const child: ChildProcess = spawn(
    PYTHON_BIN,
    [
      '-m',
      'noknowledge.server',
      '--host',
      '127.0.0.1',
      '--port',
      String(port),
      '--data-dir',
      dataDir,
      '--log-level',
      'warning',
    ],
    {
      cwd: PYTHON_REPO,
      // One relay serves a whole test file and every provisioning publishes a
      // prekey bundle plus a device list, so the production per-IP limits would
      // throttle the suite long before it finishes.
      env: {
        ...process.env,
        NK_DISABLE_KEYRING: '1',
        PYTHONPATH: PYTHON_REPO,
        NK_BUNDLES_PER_HOUR: '100000',
        NK_MAILBOXES_PER_HOUR: '100000',
        NK_WRITES_PER_MINUTE: '100000',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  let stderr = '';
  child.stderr?.on('data', (chunk) => {
    stderr += String(chunk);
  });
  const url = `http://127.0.0.1:${port}`;
  try {
    await waitForHealth(url);
  } catch (error) {
    child.kill('SIGKILL');
    throw new Error(`relay failed to start: ${String(error)}\n${stderr}`);
  }
  return {
    url,
    stop: async () => {
      child.kill('SIGTERM');
      await new Promise<void>((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) return resolve();
        child.once('exit', () => resolve());
        setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 3000);
      });
    },
  };
}

/** A line-oriented JSON client wrapping the Python reference implementation. */
export class PythonPeer {
  private readonly child: ChildProcess;
  private readonly pending: Array<{ resolve: (value: any) => void; reject: (error: Error) => void }> = [];
  private readonly queue: any[] = [];
  private stderr = '';

  private constructor(child: ChildProcess) {
    this.child = child;
    const rl = readline.createInterface({ input: child.stdout as NodeJS.ReadableStream });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      let parsed: any;
      try {
        parsed = JSON.parse(line);
      } catch {
        return;
      }
      const waiter = this.pending.shift();
      if (waiter) waiter.resolve(parsed);
      else this.queue.push(parsed);
    });
    child.stderr?.on('data', (chunk) => {
      this.stderr += String(chunk);
    });
  }

  static async start(
    options: { relays: string[]; name: string; dataDir?: string },
  ): Promise<{ peer: PythonPeer; card: string; id: string }> {
    const dataDir = options.dataDir ?? mkdtempSync(path.join(tmpdir(), 'nk-peer-'));
    const child = spawn(PYTHON_BIN, [PEER_SCRIPT], {
      env: {
        ...process.env,
        NK_PYTHON_REPO: PYTHON_REPO,
        NK_DISABLE_KEYRING: '1',
        PYTHONPATH: PYTHON_REPO,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const peer = new PythonPeer(child);
    const result = await peer.send({
      cmd: 'init',
      data_dir: dataDir,
      relays: options.relays,
      name: options.name,
    });
    if (!result?.ok) throw new Error(`python peer init failed: ${JSON.stringify(result)}\n${peer.stderr}`);
    return { peer, card: result.card, id: result.id };
  }

  send(command: Record<string, unknown>): Promise<any> {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift());
    return new Promise((resolve, reject) => {
      this.pending.push({ resolve, reject });
      this.child.stdin?.write(`${JSON.stringify(command)}\n`);
    });
  }

  async stop(): Promise<void> {
    try {
      this.child.stdin?.write(`${JSON.stringify({ cmd: 'quit' })}\n`);
    } catch {
      /* already gone */
    }
    this.child.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      if (this.child.exitCode !== null) return resolve();
      this.child.once('exit', () => resolve());
      setTimeout(() => {
        this.child.kill('SIGKILL');
        resolve();
      }, 3000);
    });
  }
}
