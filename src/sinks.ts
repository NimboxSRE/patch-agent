import { execFile } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { promisify } from 'node:util';
import type { Config, SinkName } from './config.js';
import { renderMessage, topSeverity } from './message.js';
import type { PatchEvent } from './watch.js';

const run = promisify(execFile);
const AGENT_TIMEOUT_MS = 30 * 60 * 1000;

export type Sink = (events: PatchEvent[]) => Promise<void>;

function log(msg: string): void {
  process.stderr.write(`[patch-watch] ${msg}\n`);
}

/** Todos los destinos reciben un lote por pasada: un solo turno del agente para todo lo nuevo. */
export function makeSink(name: SinkName, cfg: Config): Sink {
  switch (name) {
    case 'stdout':
      return async (events) => {
        process.stdout.write(`${JSON.stringify({ at: new Date().toISOString(), events })}\n`);
      };

    case 'codex-queue':
      // Encola en una sesión existente de Codex y la reanuda en el daemon local.
      return async (events) => {
        await run(cfg.codexBin, ['queue', '--thread', cfg.codexThread, '--message', renderMessage(events), '--resume', ...cfg.codexArgs], {
          timeout: 60_000,
        });
        log(`encolado en la sesión de Codex «${cfg.codexThread}»`);
      };

    case 'codex-exec':
      return async (events) => {
        const { stdout } = await run(cfg.codexBin, ['exec', '--cd', cfg.workdir, ...cfg.codexArgs, renderMessage(events)], {
          timeout: AGENT_TIMEOUT_MS,
          maxBuffer: 16 * 1024 * 1024,
        });
        log(`codex exec terminó:\n${stdout.slice(-2000)}`);
      };

    case 'claude-exec':
      return async (events) => {
        const { stdout } = await run(cfg.claudeBin, ['-p', ...cfg.claudeArgs, renderMessage(events)], {
          cwd: cfg.workdir,
          timeout: AGENT_TIMEOUT_MS,
          maxBuffer: 16 * 1024 * 1024,
        });
        log(`claude -p terminó:\n${stdout.slice(-2000)}`);
      };

    case 'http':
      // Para una routine de Claude con disparador por API, n8n o cualquier receptor propio.
      return async (events) => {
        if (!cfg.webhookUrl) throw new Error('El destino http necesita PATCH_WATCH_WEBHOOK_URL');
        const body = JSON.stringify({
          source: 'patch-watch',
          severity: topSeverity(events),
          text: renderMessage(events),
          events,
        });
        const ts = Math.floor(Date.now() / 1000).toString();
        const headers: Record<string, string> = { 'content-type': 'application/json', 'x-patch-watch-timestamp': ts };
        if (cfg.webhookToken) headers.authorization = `Bearer ${cfg.webhookToken}`;
        if (cfg.webhookSecret) {
          headers['x-patch-watch-signature'] = `sha256=${createHmac('sha256', cfg.webhookSecret).update(`${ts}.${body}`).digest('hex')}`;
        }
        const res = await fetch(cfg.webhookUrl, { method: 'POST', headers, body, signal: AbortSignal.timeout(30_000) });
        if (!res.ok) throw new Error(`El webhook respondió ${res.status}: ${(await res.text()).slice(0, 300)}`);
      };
  }
}
