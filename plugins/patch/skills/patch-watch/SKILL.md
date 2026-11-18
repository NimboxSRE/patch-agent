---
name: patch-watch
description: Configurar patch-watch, el vigilante que avisa al agente de lo nuevo en Patch (CVE, hallazgos, tareas) como si fuera un webhook. Úsala cuando quieran que Claude Code o Codex reaccionen solos a Patch, instalar o revisar el daemon, activar el canal de Claude Code, o diagnosticar por qué no llegan avisos.
---

# patch-watch

patch-watch consulta el MCP de Patch cada cierto tiempo (solo conexión saliente), detecta lo nuevo y despierta al agente. La primera pasada solo toma nota de lo que ya existe: no avisa de todo el histórico.

El ejecutable va en el plugin: `bin/patch-watch.mjs` (necesita Node 20 o posterior). Desde esta skill está en `../../bin/patch-watch.mjs`; en Claude Code también en `${CLAUDE_PLUGIN_ROOT}/bin/patch-watch.mjs`.

## Elige el modo

| Quieren… | Modo |
|---|---|
| Que la sesión de Claude Code que tienen abierta reaccione | **Canal** (no se instala nada más) |
| Vigilancia 24/7, o usar Codex | **Daemon** (servicio systemd de usuario) |

### Canal de Claude Code
Ya viene con el plugin: es el servidor MCP `patch-watch`. Solo hay que arrancar Claude Code con el canal activado. Mientras los canales estén en *research preview* y este no esté en la lista aprobada:

```sh
claude --dangerously-load-development-channels plugin:patch@nimboxsre
```

Solo funciona en sesión interactiva (no con `-p`). Para comprobarlo, llama a la herramienta `patch_watch_status`; `patch_watch_poll_now` fuerza una comprobación. Si las organizaciones Team o Enterprise bloquean los canales, lo tiene que habilitar un administrador.

### Daemon
1. Instálalo (pide confirmación antes: escribe en `~/.local/share/patch-watch`, `~/.config/patch-watch/env` y `~/.config/systemd/user`):
   ```sh
   node <ruta>/bin/patch-watch.mjs install-daemon
   ```
2. La persona rellena `~/.config/patch-watch/env`. **No escribas tú el token en el archivo ni lo pidas por el chat**: dile que lo pegue ella. Lo importante:
   - `PATCH_TOKEN`: para un agente que actúa solo, mejor un token de nivel «consultar y proponer» (sin parcheo).
   - `PATCH_WATCH_SINKS`: a quién avisa.
     - `codex-queue`: encola en la sesión de Codex `PATCH_WATCH_CODEX_THREAD` y la reanuda.
     - `codex-exec` / `claude-exec`: un turno sin interfaz por lote, en `PATCH_WATCH_WORKDIR`.
     - `http`: POST JSON firmado (HMAC con `PATCH_WATCH_WEBHOOK_SECRET`) a `PATCH_WATCH_WEBHOOK_URL`, por ejemplo una routine de Claude o n8n.
   - `PATCH_WATCH_MIN_SEVERITY` (por defecto `high`) y `PATCH_WATCH_INTERVAL` (segundos, por defecto 300).
3. Compruébalo y arráncalo:
   ```sh
   set -a; . ~/.config/patch-watch/env; set +a
   node ~/.local/share/patch-watch/patch-watch.mjs doctor
   systemctl --user daemon-reload && systemctl --user enable --now patch-watch
   ```
   Para que siga sin sesión abierta: `loginctl enable-linger $USER`.

Para Codex con `codex-queue`, la sesión tiene que existir: que la persona abra una con el nombre de `PATCH_WATCH_CODEX_THREAD` (por defecto `patch`), o que use su UUID.

## Diagnóstico
- `doctor` muestra qué herramientas de Patch ve el token. Si una sale como no disponible, ese tipo de aviso no se vigila.
- Logs del daemon: `journalctl --user -u patch-watch -f`.
- Si un destino falla, el aviso no se pierde: se reintenta en la siguiente pasada.
- Para empezar de cero (volver a tomar nota de todo sin avisar), borra el archivo de estado: `~/.local/state/patch-watch/state.json`, o `state-channel.json` en el modo canal.
