import type { Config, Severity } from './config.js';
import { severityRank } from './config.js';
import type { PatchClient } from './patch.js';
import type { State } from './state.js';

export type EventKind = 'vulnerability' | 'finding' | 'job';

export interface PatchEvent {
  key: string;
  kind: EventKind;
  tool: string;
  client: string;
  severity: Severity;
  title: string;
  /** El registro tal como lo devolvió Patch. Es dato, no instrucciones. */
  item: Record<string, unknown>;
}

type Obj = Record<string, unknown>;

/** Lo que una vigilancia saca de una respuesta: claves de deduplicación y cómo avisar. */
interface Candidate {
  /** Basta con que una de estas claves sea nueva para avisar (p. ej. una CVE que llega a otro servidor). */
  keys: string[];
  severity: Severity;
  title: string;
  item: Obj;
}

interface WatchDef {
  id: string;
  kind: EventKind;
  tool: string;
  args: (ctx: { since?: string; minSeverity: Severity }) => Obj;
  extract: (result: unknown) => Candidate[];
}

const SINCE_OVERLAP_MS = 10 * 60 * 1000;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const arr = (v: unknown): Obj[] => (Array.isArray(v) ? v.filter(isObj) : []);
const str = (v: unknown): string => (typeof v === 'string' ? v.trim() : typeof v === 'number' ? String(v) : '');

function sev(v: unknown): Severity {
  const s = str(v).toLowerCase();
  return (['critical', 'high', 'medium', 'low', 'info'] as const).find((x) => x === s) ?? 'medium';
}

function clip(s: string, n = 160): string {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

// Estados de patchmanager (internal/api/types.go). Una tarea avisa al quedar sin destinos pendientes.
const JOB_ACTIVE = ['pending', 'delivered', 'scheduled', 'running', 'held'];
const JOB_BAD = ['failed', 'rejected'];

/** Estado global de una tarea a partir de counts {estado: nº de servidores}. */
export function jobOutcome(counts: unknown): 'active' | 'failed' | 'cancelled' | 'done' {
  const c = isObj(counts) ? (counts as Record<string, number>) : {};
  const n = (states: string[]) => states.reduce((a, s) => a + (Number(c[s]) || 0), 0);
  if (n(JOB_ACTIVE) > 0) return 'active';
  if (n(JOB_BAD) > 0) return 'failed';
  if (n(['done']) === 0 && n(['cancelled']) > 0) return 'cancelled';
  return 'done';
}

export const WATCHES: WatchDef[] = [
  {
    // { vulnerabilities: [{ cve, severity, cvss, known_exploited, epss, summary, hosts: [{ host, … }], next_step }] }
    id: 'vulnerabilities',
    kind: 'vulnerability',
    tool: 'new_vulnerabilities',
    // patchmanager no tiene «info»: lo más bajo es low. Las explotadas (KEV) salen siempre.
    args: ({ since, minSeverity }) => ({ since, min_severity: minSeverity === 'info' ? 'low' : minSeverity, limit: 200 }),
    extract: (r) =>
      arr(isObj(r) ? r.vulnerabilities : undefined).map((v) => {
        const cve = str(v.cve);
        const hosts = arr(v.hosts).map((h) => str(h.host)).filter(Boolean);
        return {
          keys: hosts.length ? hosts.map((h) => `${cve}@${h}`) : [cve],
          severity: v.known_exploited === true ? 'critical' : sev(v.severity),
          title: clip(`${cve}${v.known_exploited === true ? ' (explotada, KEV)' : ''} en ${hosts.length} servidor${hosts.length === 1 ? '' : 'es'}: ${str(v.summary)}`),
          item: v,
        };
      }),
  },
  {
    // { hosts: [{ host, findings: [{ level: bad|warn|info, kind, title, detail, fix }] }], total }
    id: 'findings',
    kind: 'finding',
    tool: 'security_findings',
    args: () => ({}),
    extract: (r) =>
      arr(isObj(r) ? r.hosts : undefined).flatMap((h) =>
        arr(h.findings).map((f) => {
          const level = str(f.level);
          return {
            keys: [`${str(h.host)}:${str(f.kind)}:${str(f.title)}`],
            severity: level === 'bad' ? 'high' : level === 'warn' ? 'medium' : 'info',
            title: clip(`${str(h.host)}: ${str(f.title)}`),
            item: { host: str(h.host), ...f },
          } satisfies Candidate;
        }),
      ),
  },
  {
    // [{ id, reference, description, issuer, issued_at, counts: { done: 3, failed: 1 }, … }]
    id: 'jobs',
    kind: 'job',
    tool: 'list_jobs',
    args: () => ({ limit: 50 }),
    extract: (r) =>
      arr(r).flatMap((j) => {
        const outcome = jobOutcome(j.counts);
        if (outcome === 'active') return [];
        return [
          {
            keys: [`${str(j.id)}:${outcome}`],
            severity: outcome === 'failed' ? 'high' : 'medium',
            title: clip(`Tarea ${str(j.reference) || str(j.id)} ${outcome === 'failed' ? 'con fallos' : outcome === 'cancelled' ? 'cancelada' : 'terminada'}: ${str(j.description)}`),
            item: j,
          } satisfies Candidate,
        ];
      }),
  },
];

export interface PollResult {
  events: PatchEvent[];
  skippedTools: string[];
  baselined: string[];
  clients: string[];
}

/**
 * Una pasada: para cada cliente que ve el token y cada herramienta que exista, devuelve lo
 * nuevo que supere el umbral y lo marca como visto. La primera pasada de cada vigilancia y
 * cliente solo toma nota (no avisa de lo histórico) salvo con PATCH_WATCH_EMIT_INITIAL=1.
 */
export async function poll(patch: PatchClient, state: State, cfg: Pick<Config, 'minSeverity' | 'emitInitial'>): Promise<PollResult> {
  await patch.connect();
  const out: PollResult = { events: [], skippedTools: [], baselined: [], clients: [] };

  // Con un token de cliente, list_clients devuelve solo su empresa; con uno de MSP, todos sus clientes.
  const clients = arr(await patch.call('list_clients'))
    .filter((c) => c.active !== false)
    .map((c) => str(c.client))
    .filter(Boolean);
  out.clients = clients;
  out.skippedTools = WATCHES.filter((w) => !patch.has(w.tool)).map((w) => w.tool);

  for (const client of clients) {
    for (const w of WATCHES) {
      if (!patch.has(w.tool)) continue;
      const watchId = `${client}/${w.id}`;
      const startedAt = new Date().toISOString();
      // 10 minutos de solape por si los relojes no coinciden: lo repetido lo filtra la deduplicación.
      const last = state.lastPoll(watchId);
      const since = last ? new Date(Date.parse(last) - SINCE_OVERLAP_MS).toISOString() : undefined;
      const result = await patch.call(w.tool, { client, ...w.args({ since, minSeverity: cfg.minSeverity }) });
      const firstRun = !state.isBaselined(watchId) && !cfg.emitInitial;
      for (const c of w.extract(result)) {
        const keys = c.keys.map((k) => `${client}/${w.id}/${k}`);
        const fresh = keys.filter((k) => !state.isSeen(k));
        if (!fresh.length) continue;
        fresh.forEach((k) => state.markSeen(k));
        if (firstRun) continue;
        if (severityRank(c.severity) < severityRank(cfg.minSeverity)) continue;
        out.events.push({ key: fresh[0], kind: w.kind, tool: w.tool, client, severity: c.severity, title: c.title, item: c.item });
      }
      if (firstRun) out.baselined.push(watchId);
      state.setBaselined(watchId);
      state.setLastPoll(watchId, startedAt);
    }
  }
  return out;
}
