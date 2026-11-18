// Servidor MCP que imita a Patch para las pruebas: mismas herramientas, datos controlados.
import { createServer, type Server as HttpServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { z } from 'zod';

export interface MockData {
  vulnerabilities: Record<string, unknown>[];
  findings: Record<string, unknown>[];
  jobs: Record<string, unknown>[];
  calls: { tool: string; args: unknown }[];
}

export async function startMockPatch(token: string): Promise<{ url: string; data: MockData; close: () => Promise<void> }> {
  const data: MockData = { vulnerabilities: [], findings: [], jobs: [], calls: [] };
  const transports = new Map<string, StreamableHTTPServerTransport>();

  const build = () => {
    const s = new McpServer({ name: 'patch-mock', version: '0.0.0' });
    s.registerTool('new_vulnerabilities', { inputSchema: { since: z.string().optional() } }, async (args) => {
      data.calls.push({ tool: 'new_vulnerabilities', args });
      return { content: [{ type: 'text', text: JSON.stringify({ vulnerabilities: data.vulnerabilities }) }] };
    });
    s.registerTool('security_findings', { inputSchema: {} }, async (args) => {
      data.calls.push({ tool: 'security_findings', args });
      return { content: [{ type: 'text', text: JSON.stringify(data.findings) }] };
    });
    s.registerTool('list_jobs', { inputSchema: { since: z.string().optional() } }, async (args) => {
      data.calls.push({ tool: 'list_jobs', args });
      return { content: [{ type: 'text', text: JSON.stringify({ jobs: data.jobs }) }] };
    });
    return s;
  };

  const http: HttpServer = createServer(async (req, res) => {
    if (req.headers.authorization !== `Bearer ${token}`) {
      res.writeHead(401).end('unauthorized');
      return;
    }
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
    const sid = req.headers['mcp-session-id'] as string | undefined;
    let transport = sid ? transports.get(sid) : undefined;
    if (!transport) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        onsessioninitialized: (id) => {
          transports.set(id, transport!);
        },
      });
      await build().connect(transport);
    }
    await transport.handleRequest(req, res, body);
  });
  await new Promise<void>((r) => http.listen(0, '127.0.0.1', r));
  const { port } = http.address() as { port: number };
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    data,
    close: async () => {
      for (const t of transports.values()) await t.close();
      http.closeAllConnections();
      await new Promise<void>((r) => http.close(() => r()));
    },
  };
}
