import type { Config } from './config.js';
import { PatchClient } from './patch.js';
import { makeSink } from './sinks.js';
import { State } from './state.js';
import { poll } from './watch.js';

function log(msg: string): void {
  process.stderr.write(`[patch-watch] ${new Date().toISOString()} ${msg}\n`);
}

/**
 * Una pasada completa. Si algún destino falla no guarda el estado, así lo mismo se
 * vuelve a intentar en la siguiente pasada en lugar de perderse.
 */
export async function runOnce(cfg: Config, patch: PatchClient, state: State, deliver = true): Promise<number> {
  const res = await poll(patch, state, cfg);
  if (res.baselined.length) log(`primera pasada de ${res.baselined.join(', ')}: anotado lo existente sin avisar`);
  if (res.events.length && deliver) {
    const failures: string[] = [];
    for (const name of cfg.sinks) {
      try {
        await makeSink(name, cfg)(res.events);
      } catch (err) {
        failures.push(`${name}: ${(err as Error).message}`);
      }
    }
    if (failures.length) {
      await state.load();
      throw new Error(`no se pudo avisar (${failures.join('; ')}); se reintentará`);
    }
  } else if (res.events.length) {
    process.stdout.write(`${JSON.stringify(res.events, null, 2)}\n`);
  }
  await state.save();
  return res.events.length;
}

export async function runDaemon(cfg: Config): Promise<void> {
  if (!cfg.token) throw new Error('Falta PATCH_TOKEN');
  const patch = new PatchClient(cfg.mcpUrl, cfg.token);
  const state = new State(cfg.statePath);
  await state.load();
  log(`vigilando ${cfg.mcpUrl} cada ${cfg.intervalSec}s, umbral ${cfg.minSeverity}, destinos ${cfg.sinks.join(', ')}`);

  let stopping = false;
  let wake: (() => void) | undefined;
  const stop = () => {
    stopping = true;
    wake?.();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);

  let failures = 0;
  while (!stopping) {
    try {
      const n = await runOnce(cfg, patch, state);
      if (n) log(`${n} novedades enviadas`);
      failures = 0;
    } catch (err) {
      failures++;
      log(`error: ${(err as Error).message}`);
      await patch.close();
    }
    // Espera el intervalo; tras errores seguidos, un poco más (máximo 4×).
    const waitMs = cfg.intervalSec * 1000 * Math.min(2 ** Math.max(failures - 1, 0), 4);
    if (stopping) break;
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, waitMs);
      wake = () => {
        clearTimeout(timer);
        resolve();
      };
    });
  }
  await patch.close();
  log('parado');
}
