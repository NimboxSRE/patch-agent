// Imita el MCP de patchmanager (internal/server/mcp.go): JSON-RPC por POST, sin sesiones,
// 405 en GET, «client» obligatorio con token de MSP y resultados como JSON en un bloque de texto.
import { createServer, type Server as HttpServer } from 'node:http';

export interface ClientData {
  vulnerabilities: Record<string, unknown>[];
  findingHosts: { host: string; findings: Record<string, unknown>[] }[];
  jobs: Record<string, unknown>[];
}

export interface Mock {
  url: string;
  clients: Record<string, ClientData>;
  calls: { tool: string; args: Record<string, unknown> }[];
  close: () => Promise<void>;
}

const emptyClient = (): ClientData => ({ vulnerabilities: [], findingHosts: [], jobs: [] });
const clientProp = { type: 'string' };

const TOOLS = [
  { name: 'list_clients', inputSchema: { type: 'object', properties: {} } },
  { name: 'new_vulnerabilities', inputSchema: { type: 'object', properties: { client: clientProp, since: { type: 'string' }, min_severity: { type: 'string' }, limit: { type: 'integer' } } } },
  { name: 'security_findings', inputSchema: { type: 'object', properties: { client: clientProp, host: { type: 'string' } } } },
  { name: 'list_jobs', inputSchema: { type: 'object', properties: { client: clientProp, limit: { type: 'integer' } } } },
  { name: 'get_job', inputSchema: { type: 'object', properties: { client: clientProp, id: { type: 'string' } }, required: ['id'] } },
];

/** msp: el token es de MSP (varios clientes y «client» obligatorio). Si no, es de un solo cliente. */
export async function startMockPatch(token: string, opts: { msp?: boolean } = {}): Promise<Mock> {
  const clients: Record<string, ClientData> = opts.msp ? { acme: emptyClient(), globex: emptyClient() } : { solo: emptyClient() };
  const calls: Mock['calls'] = [];

  const callTool = (name: string, args: Record<string, unknown>): unknown => {
    calls.push({ tool: name, args });
    if (name === 'list_clients') return Object.keys(clients).map((c) => ({ client: c, name: c.toUpperCase(), active: true }));
    let slug = Object.keys(clients)[0];
    if (opts.msp) {
      slug = String(args.client ?? '');
      if (!slug) throw new Error('indica el cliente (usa list_clients)');
      if (!clients[slug]) throw new Error('cliente no encontrado entre los de este MSP');
    }
    const d = clients[slug];
    switch (name) {
      case 'new_vulnerabilities': {
        const since = args.since ? Date.parse(String(args.since)) : Date.now() - 24 * 3600 * 1000;
        const vulns = d.vulnerabilities.filter((v) => Date.parse(String(v.first_seen)) >= since);
        return { since: new Date(since).toISOString(), actionable: vulns.length, discarded_not_exploitable: 0, vulnerabilities: vulns };
      }
      case 'security_findings':
        return { hosts: d.findingHosts, total: d.findingHosts.reduce((a, h) => a + h.findings.length, 0) };
      case 'list_jobs':
        return d.jobs;
    }
    throw new Error(`sin implementar: ${name}`);
  };

  const http: HttpServer = createServer(async (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' }).end('este servidor MCP solo responde por POST');
      return;
    }
    if (req.headers.authorization !== `Bearer ${token}`) {
      res.writeHead(401, { 'www-authenticate': 'Bearer realm="patchmanager"', 'content-type': 'application/json' }).end('{"error":"token de API no válido"}');
      return;
    }
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const msg = JSON.parse(Buffer.concat(chunks).toString()) as { id?: unknown; method: string; params?: Record<string, unknown> };
    if (msg.id === undefined) {
      res.writeHead(202).end();
      return;
    }
    let result: unknown;
    let error: unknown;
    switch (msg.method) {
      case 'initialize':
        result = { protocolVersion: msg.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'patch-nimboxsre', version: '1' } };
        break;
      case 'ping':
        result = {};
        break;
      case 'tools/list':
        result = { tools: TOOLS };
        break;
      case 'tools/call': {
        const { name, arguments: args = {} } = msg.params as { name: string; arguments?: Record<string, unknown> };
        try {
          result = { content: [{ type: 'text', text: JSON.stringify(callTool(name, args), null, 1) }] };
        } catch (e) {
          result = { isError: true, content: [{ type: 'text', text: (e as Error).message }] };
        }
        break;
      }
      default:
        error = { code: -32601, message: `método no soportado: ${msg.method}` };
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ jsonrpc: '2.0', id: msg.id, result, error }));
  });
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', r));
  const { port } = http.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    clients,
    calls,
    close: async () => {
      http.closeAllConnections();
      await new Promise<void>((r) => http.close(() => r()));
    },
  };
}

/** Una CVE con el formato de new_vulnerabilities. */
export function vuln(cve: string, opts: { severity?: string; kev?: boolean; hosts?: string[]; summary?: string; ago?: number } = {}): Record<string, unknown> {
  return {
    cve,
    severity: opts.severity ?? 'high',
    cvss: 8.1,
    known_exploited: opts.kev ?? false,
    epss: 0.02,
    summary: opts.summary ?? `resumen de ${cve}`,
    first_seen: new Date(Date.now() - (opts.ago ?? 0)).toISOString(),
    hosts: (opts.hosts ?? ['web-01']).map((h) => ({ host: h, package: 'openssl', installed: '3.0.1', fixed: '3.0.2' })),
    fixable_hosts: opts.hosts ?? ['web-01'],
    next_step: 'parchear (patch_plan → prepare_job)',
  };
}
