import { homedir } from 'node:os';
import { join } from 'node:path';

export type SinkName = 'stdout' | 'codex-queue' | 'codex-exec' | 'claude-exec' | 'http';

export interface Config {
  mcpUrl: string;
  token: string | undefined;
  intervalSec: number;
  statePath: string;
  minSeverity: Severity;
  sinks: SinkName[];
  codexThread: string;
  codexBin: string;
  claudeBin: string;
  workdir: string;
  webhookUrl: string | undefined;
  webhookToken: string | undefined;
  webhookSecret: string | undefined;
  emitInitial: boolean;
  claudeArgs: string[];
  codexArgs: string[];
}

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];

const SINKS: SinkName[] = ['stdout', 'codex-queue', 'codex-exec', 'claude-exec', 'http'];

function env(name: string): string | undefined {
  const v = process.env[name]?.trim();
  return v ? v : undefined;
}

export function loadConfig(): Config {
  const stateHome = env('XDG_STATE_HOME') ?? join(homedir(), '.local', 'state');
  const interval = Number(env('PATCH_WATCH_INTERVAL') ?? 300);
  const minSeverity = (env('PATCH_WATCH_MIN_SEVERITY') ?? 'high').toLowerCase() as Severity;
  if (!SEVERITIES.includes(minSeverity)) {
    throw new Error(`PATCH_WATCH_MIN_SEVERITY debe ser una de: ${SEVERITIES.join(', ')}`);
  }
  const sinks = (env('PATCH_WATCH_SINKS') ?? 'stdout')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean) as SinkName[];
  for (const s of sinks) {
    if (!SINKS.includes(s)) throw new Error(`Destino desconocido en PATCH_WATCH_SINKS: ${s} (válidos: ${SINKS.join(', ')})`);
  }
  return {
    mcpUrl: env('PATCH_MCP_URL') ?? 'https://patch.nimboxsre.com/mcp',
    token: env('PATCH_TOKEN'),
    intervalSec: Number.isFinite(interval) && interval >= 30 ? interval : 300,
    statePath: env('PATCH_WATCH_STATE') ?? join(stateHome, 'patch-watch', 'state.json'),
    minSeverity,
    sinks,
    codexThread: env('PATCH_WATCH_CODEX_THREAD') ?? 'patch',
    codexBin: env('PATCH_WATCH_CODEX_BIN') ?? 'codex',
    claudeBin: env('PATCH_WATCH_CLAUDE_BIN') ?? 'claude',
    workdir: env('PATCH_WATCH_WORKDIR') ?? process.cwd(),
    webhookUrl: env('PATCH_WATCH_WEBHOOK_URL'),
    webhookToken: env('PATCH_WATCH_WEBHOOK_TOKEN'),
    webhookSecret: env('PATCH_WATCH_WEBHOOK_SECRET'),
    emitInitial: env('PATCH_WATCH_EMIT_INITIAL') === '1',
    claudeArgs: splitArgs(env('PATCH_WATCH_CLAUDE_ARGS')),
    codexArgs: splitArgs(env('PATCH_WATCH_CODEX_ARGS')),
  };
}

/** Separa por espacios; sin comillas ni shell, a propósito. */
function splitArgs(v: string | undefined): string[] {
  return v ? v.split(/\s+/).filter(Boolean) : [];
}

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}
