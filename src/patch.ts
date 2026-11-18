import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

/** Cliente mínimo del servidor MCP de Patch: abre una sesión, lista herramientas y las llama. */
export class PatchClient {
  private client: Client | undefined;
  private tools: Map<string, { inputSchema?: { properties?: Record<string, unknown> } }> = new Map();

  constructor(
    private readonly url: string,
    private readonly token: string,
  ) {}

  async connect(): Promise<void> {
    if (this.client) return;
    const client = new Client({ name: 'patch-watch', version: '0.1.0' });
    const transport = new StreamableHTTPClientTransport(new URL(this.url), {
      requestInit: { headers: { Authorization: `Bearer ${this.token}` } },
    });
    await client.connect(transport);
    const { tools } = await client.listTools();
    this.tools = new Map(tools.map((t) => [t.name, t as never]));
    this.client = client;
  }

  async close(): Promise<void> {
    const c = this.client;
    this.client = undefined;
    await c?.close().catch(() => {});
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  toolNames(): string[] {
    return [...this.tools.keys()];
  }

  /** Solo pasa los argumentos que la herramienta declara, para no romper si el esquema cambia. */
  async call(name: string, args: Record<string, unknown> = {}): Promise<unknown> {
    if (!this.client) await this.connect();
    const props = this.tools.get(name)?.inputSchema?.properties ?? {};
    const accepted = Object.fromEntries(Object.entries(args).filter(([k, v]) => k in props && v !== undefined));
    let res;
    try {
      res = await this.client!.callTool({ name, arguments: accepted });
    } catch (err) {
      // La sesión puede haber caducado en el servidor: reconecta una vez.
      await this.close();
      await this.connect();
      res = await this.client!.callTool({ name, arguments: accepted });
    }
    if (res.isError) {
      throw new Error(`${name} devolvió un error: ${textOf(res.content).slice(0, 500)}`);
    }
    if (res.structuredContent !== undefined) return res.structuredContent;
    const text = textOf(res.content);
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }
}

function textOf(content: unknown): string {
  if (!Array.isArray(content)) return '';
  return content
    .filter((c): c is { type: 'text'; text: string } => c?.type === 'text' && typeof c.text === 'string')
    .map((c) => c.text)
    .join('\n');
}
