import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';

const KEEP_MS = 60 * 24 * 3600 * 1000; // olvida avisos de hace más de 60 días

interface StateFile {
  version: 1;
  seen: Record<string, number>;
  baselined: Record<string, boolean>;
  lastPoll: Record<string, string>;
}

/** Recuerda qué se ha avisado ya, para no despertar al agente dos veces por lo mismo. */
export class State {
  private data: StateFile = { version: 1, seen: {}, baselined: {}, lastPoll: {} };

  constructor(private readonly path: string) {}

  async load(): Promise<void> {
    try {
      const parsed = JSON.parse(await readFile(this.path, 'utf8')) as Partial<StateFile>;
      this.data = {
        version: 1,
        seen: parsed.seen ?? {},
        baselined: parsed.baselined ?? {},
        lastPoll: parsed.lastPoll ?? {},
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
  }

  async save(): Promise<void> {
    const now = Date.now();
    for (const [k, t] of Object.entries(this.data.seen)) if (now - t > KEEP_MS) delete this.data.seen[k];
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(this.data), { mode: 0o600 });
    await rename(tmp, this.path);
  }

  isSeen(key: string): boolean {
    return key in this.data.seen;
  }

  markSeen(key: string): void {
    this.data.seen[key] = Date.now();
  }

  isBaselined(watch: string): boolean {
    return this.data.baselined[watch] === true;
  }

  setBaselined(watch: string): void {
    this.data.baselined[watch] = true;
  }

  lastPoll(watch: string): string | undefined {
    return this.data.lastPoll[watch];
  }

  setLastPoll(watch: string, iso: string): void {
    this.data.lastPoll[watch] = iso;
  }
}
