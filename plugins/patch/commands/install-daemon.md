---
description: Instala patch-watch como servicio systemd de usuario, para recibir los avisos de Patch 24/7 o en Codex
allowed-tools: Bash(node:*), Bash(systemctl --user:*)
---

Instala el daemon de patch-watch siguiendo la skill `patch-watch`, sección «Daemon».

1. Explica en dos líneas qué se va a escribir: `~/.local/share/patch-watch`, `~/.config/patch-watch/env` y `~/.config/systemd/user/patch-watch.service`.
2. Ejecuta `node "${CLAUDE_PLUGIN_ROOT}/bin/patch-watch.mjs" install-daemon` (sin `--enable`).
3. Pide a la persona que rellene `PATCH_TOKEN` y `PATCH_WATCH_SINKS` en `~/.config/patch-watch/env`. Que lo haga ella: no pidas el token por el chat.
4. Cuando lo confirme, ejecuta `doctor` con ese entorno y, si todo está bien, `systemctl --user daemon-reload && systemctl --user enable --now patch-watch`.

$ARGUMENTS
