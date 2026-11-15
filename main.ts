// The entry's lifecycle with the make.fun env, and nothing else.
//
// The harness runs this process beside its env service. The env's origin arrives in
// MAKEFUN_ENV_URL; without it there is nobody to register with, so the process exits 1.
// Otherwise: build the forge server, bind an ephemeral port (never 8080 — that is the
// env's own port), POST {"port": N} to $MAKEFUN_ENV_URL/register (the first register
// wins; a 409 simply means ours was not first), then poll GET $MAKEFUN_ENV_URL/done
// until it answers {"done": true}, close the server and exit 0. Failed register or
// poll attempts are retried with a short exponential backoff: the env may still be
// starting, and the process must never exit before the env says it is done.

import { createApp } from './app.ts';

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');

const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_FIRST_MS = 250;
const RETRY_CAP_MS = 2_000;

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoff(attempt: number): number {
  return Math.min(RETRY_CAP_MS, RETRY_FIRST_MS * 2 ** Math.min(attempt, 8));
}

/** Register the bound port; 200 and 409 both end the loop, 400/405 are fatal. */
async function registerWithEnv(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (response.status === 200 || response.status === 409) return;
      if (response.status === 400 || response.status === 405) {
        throw new Error(`register refused with HTTP ${response.status}`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register refused')) throw err;
      // A network failure just means the env is not up yet: wait and try again.
    }
    await wait(backoff(attempt));
  }
}

/** Poll the env's /done until it reports the trial is over. */
async function waitUntilDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const response = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (response.ok) {
        const body = (await response.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // Not answered yet is not done: keep polling.
    }
    await wait(backoff(attempt));
  }
}

async function run(): Promise<void> {
  if (ENV_URL === '') {
    process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
    process.exit(1);
  }
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] forge listening on port ${address.port}\n`);
  await registerWithEnv(address.port);
  process.stdout.write('[entry] registered with the env; waiting for done\n');
  await waitUntilDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await run();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
