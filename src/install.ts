import { execFileSync } from 'node:child_process';
import { access, chmod, copyFile, mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ENV_TEMPLATE = `# patch-watch: configuración del daemon. Este archivo tiene el token: déjalo en 0600.
# Token de Patch. Para un agente autónomo, mejor de nivel «consultar y proponer» (sin parcheo).
PATCH_TOKEN=
#PATCH_MCP_URL=https://patch.nimboxsre.com/mcp

# Cada cuántos segundos comprobar (mínimo 30) y desde qué gravedad avisar: info|low|medium|high|critical
PATCH_WATCH_INTERVAL=300
PATCH_WATCH_MIN_SEVERITY=high

# A quién avisar, separado por comas: stdout, codex-queue, codex-exec, claude-exec, http
PATCH_WATCH_SINKS=codex-queue

# codex-queue: nombre o UUID de la sesión de Codex que recibe los avisos
PATCH_WATCH_CODEX_THREAD=patch
# codex-exec / claude-exec: directorio de trabajo y argumentos extra
#PATCH_WATCH_WORKDIR=
#PATCH_WATCH_CODEX_ARGS=
#PATCH_WATCH_CLAUDE_ARGS=--allowedTools mcp__plugin_patch_patch__*

# http: URL que recibe un POST JSON por lote (routine de Claude, n8n…)
#PATCH_WATCH_WEBHOOK_URL=
#PATCH_WATCH_WEBHOOK_TOKEN=
#PATCH_WATCH_WEBHOOK_SECRET=
`;

function unit(node: string, script: string, envFile: string): string {
  return `[Unit]
Description=patch-watch: avisa al agente de lo nuevo en Patch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${envFile}
ExecStart=${node} ${script} daemon
Restart=on-failure
RestartSec=30
NoNewPrivileges=yes

[Install]
WantedBy=default.target
`;
}

async function exists(p: string): Promise<boolean> {
  return access(p).then(
    () => true,
    () => false,
  );
}

/**
 * Instala patch-watch como servicio systemd de usuario. Copia el ejecutable a
 * ~/.local/share/patch-watch para que no dependa de la ruta del plugin, que cambia al actualizarlo.
 */
export async function installDaemon(opts: { enable: boolean }): Promise<string> {
  const home = homedir();
  const dataDir = join(home, '.local', 'share', 'patch-watch');
  const confDir = join(process.env.XDG_CONFIG_HOME ?? join(home, '.config'), 'patch-watch');
  const unitDir = join(process.env.XDG_CONFIG_HOME ?? join(home, '.config'), 'systemd', 'user');
  const script = join(dataDir, 'patch-watch.mjs');
  const envFile = join(confDir, 'env');
  const unitFile = join(unitDir, 'patch-watch.service');

  await mkdir(dataDir, { recursive: true });
  await mkdir(confDir, { recursive: true, mode: 0o700 });
  await mkdir(unitDir, { recursive: true });
  await copyFile(fileURLToPath(import.meta.url), script);
  await chmod(script, 0o755);

  const lines = [`Ejecutable: ${script}`];
  if (await exists(envFile)) {
    lines.push(`Configuración: ${envFile} (ya existía, no la toco)`);
  } else {
    await writeFile(envFile, ENV_TEMPLATE, { mode: 0o600 });
    lines.push(`Configuración: ${envFile} (nueva: rellena PATCH_TOKEN y elige PATCH_WATCH_SINKS)`);
  }
  await writeFile(unitFile, unit(process.execPath, script, envFile));
  lines.push(`Servicio: ${unitFile}`);

  if (opts.enable) {
    execFileSync('systemctl', ['--user', 'daemon-reload'], { stdio: 'inherit' });
    execFileSync('systemctl', ['--user', 'enable', '--now', 'patch-watch.service'], { stdio: 'inherit' });
    lines.push('Activado: systemctl --user status patch-watch');
  } else {
    lines.push('', 'Para arrancarlo:', '  systemctl --user daemon-reload', '  systemctl --user enable --now patch-watch', 'Logs: journalctl --user -u patch-watch -f');
    lines.push('Para que siga corriendo sin sesión abierta: loginctl enable-linger $USER');
  }
  return lines.join('\n');
}
