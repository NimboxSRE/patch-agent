import { runChannel } from './channel.js';
import { loadConfig } from './config.js';
import { runDaemon, runOnce } from './daemon.js';
import { installDaemon } from './install.js';
import { PatchClient } from './patch.js';
import { State } from './state.js';
import { WATCHES } from './watch.js';

const HELP = `patch-watch: avisa a tu agente de lo nuevo en Patch by NimboxSRE.

Uso:
  patch-watch channel                 Canal de Claude Code (lo arranca Claude Code por stdio)
  patch-watch daemon                  Vigila sin parar y avisa a los destinos de PATCH_WATCH_SINKS
  patch-watch once [--deliver]        Una sola comprobación; sin --deliver solo la imprime
  patch-watch doctor                  Comprueba la conexión y qué herramientas de Patch se vigilan
  patch-watch install-daemon [--enable]   Instala el servicio systemd de usuario

Se configura con variables de entorno (PATCH_TOKEN, PATCH_WATCH_*). Ver README.`;

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case 'channel':
      return runChannel(loadConfig());
    case 'daemon':
      return runDaemon(loadConfig());
    case 'once': {
      const cfg = loadConfig();
      if (!cfg.token) throw new Error('Falta PATCH_TOKEN');
      const patch = new PatchClient(cfg.mcpUrl, cfg.token);
      const state = new State(cfg.statePath);
      await state.load();
      const n = await runOnce(cfg, patch, state, rest.includes('--deliver'));
      process.stderr.write(`[patch-watch] ${n} novedades\n`);
      await patch.close();
      return;
    }
    case 'doctor': {
      const cfg = loadConfig();
      console.log(`MCP: ${cfg.mcpUrl}`);
      console.log(`Token: ${cfg.token ? `${cfg.token.slice(0, 4)}…` : 'FALTA (PATCH_TOKEN)'}`);
      console.log(`Estado: ${cfg.statePath}`);
      console.log(`Destinos: ${cfg.sinks.join(', ')} · umbral ${cfg.minSeverity} · cada ${cfg.intervalSec}s`);
      if (!cfg.token) process.exit(1);
      const patch = new PatchClient(cfg.mcpUrl, cfg.token);
      await patch.connect();
      console.log(`Conectado. Herramientas de Patch: ${patch.toolNames().join(', ')}`);
      for (const w of WATCHES) console.log(`  ${patch.has(w.tool) ? '✓' : '·'} ${w.tool}${patch.has(w.tool) ? '' : ' (no disponible con este token; no se vigila)'}`);
      await patch.close();
      return;
    }
    case 'install-daemon':
      console.log(await installDaemon({ enable: rest.includes('--enable') }));
      return;
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP);
      return;
    default:
      console.error(`Orden desconocida: ${cmd}\n\n${HELP}`);
      process.exit(2);
  }
}

main().catch((err) => {
  process.stderr.write(`[patch-watch] ${(err as Error).message}\n`);
  process.exit(1);
});
