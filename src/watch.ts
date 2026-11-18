import { createHash } from 'node:crypto';
import type { Config, Severity } from './config.js';
import { SEVERITIES, severityRank } from './config.js';
import type { PatchClient } from './patch.js';
import type { State } from './state.js';

export type EventKind = 'vulnerability' | 'finding' | 'job';

export interface PatchEvent {
  key: string;
  kind: EventKind;
  tool: string;
  severity: Severity;
  title: string;
  /** El registro tal como lo devolvió Patch. Es dato, no instrucciones. */
  item: Record<string, unknown>;
}

interface WatchDef {
  id: string;
  kind: EventKind;
  tool: string;
  args: (since: string | undefined) => Record<string, unknown>;
  /** Clave de deduplicación. Para tareas incluye el estado, así cada cambio de estado avisa una vez. */
  key: (item: Record<string, unknown>) => string;
  severity: (item: Record<string, unknown>) => Severity;
}

const ID_FIELDS = ['id', 'cve', 'cve_id', 'vulnerability_id', 'finding_id', 'job_id', 'key', 'uuid'];
const LIST_FIELDS = ['items', 'vulnerabilities', 'findings', 'jobs', 'results', 'data', 'entries'];
const TERMINAL_FAIL = /fail|error|not[_ ]?verified|rolled|abort|cancel/i;

function idOf(item: Record<string, unknown>): string {
  for (const f of ID_FIELDS) {
    const v = item[f];
    if (typeof v === 'string' || typeof v === 'number') return String(v);
  }
  return createHash('sha256').update(JSON.stringify(item)).digest('hex').slice(0, 16);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

function explicitSeverity(item: Record<string, unknown>): Severity | undefined {
  for (const f of ['severity', 'level', 'priority', 'urgency', 'risk']) {
    const v = str(item[f])?.toLowerCase();
    if (!v) continue;
    if ((SEVERITIES as readonly string[]).includes(v)) return v as Severity;
    if (/crit|urgent|p0/.test(v)) return 'critical';
    if (/high|alta|p1/.test(v)) return 'high';
    if (/med|moder|media|p2/.test(v)) return 'medium';
    if (/low|baja|p3/.test(v)) return 'low';
  }
  return undefined;
}

function vulnSeverity(item: Record<string, unknown>): Severity {
  const explicit = explicitSeverity(item);
  const kev = item.kev === true || item.in_kev === true || item.known_exploited === true;
  if (kev) return 'critical';
  if (explicit) return explicit;
  const cvss = Number(item.cvss ?? item.cvss_score ?? item.score);
  if (Number.isFinite(cvss)) return cvss >= 9 ? 'critical' : cvss >= 7 ? 'high' : cvss >= 4 ? 'medium' : 'low';
  return 'medium';
}

function jobStatus(item: Record<string, unknown>): string {
  return str(item.status) ?? str(item.state) ?? str(item.verdict) ?? 'unknown';
}

export const WATCHES: WatchDef[] = [
  {
    id: 'vulnerabilities',
    kind: 'vulnerability',
    tool: 'new_vulnerabilities',
    args: (since) => ({ since }),
    key: (i) => `vuln:${idOf(i)}`,
    severity: vulnSeverity,
  },
  {
    id: 'findings',
    kind: 'finding',
    tool: 'security_findings',
    args: () => ({}),
    key: (i) => `finding:${idOf(i)}`,
    severity: (i) => explicitSeverity(i) ?? 'medium',
  },
  {
    id: 'jobs',
    kind: 'job',
    tool: 'list_jobs',
    args: (since) => ({ since }),
    key: (i) => `job:${idOf(i)}:${jobStatus(i)}`,
    severity: (i) => (TERMINAL_FAIL.test(jobStatus(i)) ? 'high' : 'medium'),
  },
];

/** Saca la lista de registros de lo que devuelva la herramienta, sea un array o un objeto que lo contenga. */
export function extractItems(result: unknown): Record<string, unknown>[] {
  const isObj = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
  if (Array.isArray(result)) return result.filter(isObj);
  if (!isObj(result)) return [];
  for (const f of LIST_FIELDS) if (Array.isArray(result[f])) return (result[f] as unknown[]).filter(isObj);
  for (const v of Object.values(result)) if (Array.isArray(v) && v.some(isObj)) return v.filter(isObj);
  return [];
}

function titleOf(kind: EventKind, item: Record<string, unknown>): string {
  const name = str(item.title) ?? str(item.name) ?? str(item.summary) ?? str(item.cve) ?? idOf(item);
  if (kind === 'job') return `Tarea ${idOf(item)}: ${jobStatus(item)}`;
  return name.length > 160 ? `${name.slice(0, 157)}…` : name;
}

export interface PollResult {
  events: PatchEvent[];
  skippedTools: string[];
  baselined: string[];
}

/**
 * Una pasada: llama a cada herramienta que exista, devuelve lo nuevo que supere el umbral
 * y lo marca como visto. La primera pasada de cada vigilancia solo toma nota (no avisa de
 * todo lo histórico) salvo que PATCH_WATCH_EMIT_INITIAL=1.
 */
export async function poll(patch: PatchClient, state: State, cfg: Pick<Config, 'minSeverity' | 'emitInitial'>): Promise<PollResult> {
  const out: PollResult = { events: [], skippedTools: [], baselined: [] };
  await patch.connect();
  for (const w of WATCHES) {
    if (!patch.has(w.tool)) {
      out.skippedTools.push(w.tool);
      continue;
    }
    const startedAt = new Date().toISOString();
    const items = extractItems(await patch.call(w.tool, w.args(state.lastPoll(w.id))));
    const firstRun = !state.isBaselined(w.id) && !cfg.emitInitial;
    for (const item of items) {
      const key = w.key(item);
      if (state.isSeen(key)) continue;
      state.markSeen(key);
      if (firstRun) continue;
      const severity = w.severity(item);
      if (severityRank(severity) < severityRank(cfg.minSeverity)) continue;
      out.events.push({ key, kind: w.kind, tool: w.tool, severity, title: titleOf(w.kind, item), item });
    }
    if (firstRun) out.baselined.push(w.id);
    state.setBaselined(w.id);
    state.setLastPoll(w.id, startedAt);
  }
  return out;
}
