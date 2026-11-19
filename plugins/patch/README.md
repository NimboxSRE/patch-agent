# Patch para Claude Code y Codex

Conecta tu agente con [Patch by NimboxSRE](https://patchsre.com) para parchear Linux con firma: el agente investiga y prepara, una persona decide.

Incluye:

- **El servidor MCP de Patch**, autenticado con tu token `pmk_…`.
- **La skill `patch-triage`**, con el flujo: novedades → exposición real → plan → propuesta o tarea firmada → verificación → nota.
- **La skill `patch-watch`** y el comando `/patch:install-daemon`.
- **patch-watch**, que avisa al agente de lo nuevo en Patch como si fuera un webhook: CVE que afectan a tus servidores, hallazgos de seguridad y tareas que terminan o fallan.

## Instalación

### Claude Code

```sh
claude plugin marketplace add NimboxSRE/patch-agent   # o la ruta local del repo
claude plugin install patch@nimboxsre
```

Al activarlo, Claude Code te pide el token de Patch y lo guarda en el almacén seguro del sistema, no en `settings.json`.

Para que la sesión reciba los avisos de patch-watch, arranca con el canal activado. Mientras los canales estén en *research preview*:

```sh
claude --dangerously-load-development-channels plugin:patch@nimboxsre
```

Los avisos llegan como `<channel source="patch-watch" severity="critical">…` y Claude los trata con la skill `patch-triage`. Sin ese flag, el plugin funciona igual pero sin avisos: el MCP de Patch y las skills siguen disponibles.

### Codex

```sh
codex plugin marketplace add NimboxSRE/patch-agent   # o la ruta local del repo
codex plugin add patch@nimboxsre
export PATCH_TOKEN=pmk_…   # el MCP de Patch lo lee de aquí
```

Codex no tiene canales. Para recibir avisos, instala el daemon y usa el destino `codex-queue`: encola cada lote en una sesión de Codex y la reanuda.

## patch-watch en modo daemon (24/7, Codex o sin interfaz)

```sh
node bin/patch-watch.mjs install-daemon    # o /patch:install-daemon en Claude Code
$EDITOR ~/.config/patch-watch/env          # PATCH_TOKEN y PATCH_WATCH_SINKS
systemctl --user enable --now patch-watch
```

| Destino (`PATCH_WATCH_SINKS`) | Qué hace |
|---|---|
| `codex-queue` | `codex queue --thread $PATCH_WATCH_CODEX_THREAD --message … --resume` |
| `codex-exec` | Un `codex exec` por lote en `PATCH_WATCH_WORKDIR` |
| `claude-exec` | Un `claude -p` por lote en `PATCH_WATCH_WORKDIR` (`PATCH_WATCH_CLAUDE_ARGS` para `--allowedTools`) |
| `http` | POST JSON a `PATCH_WATCH_WEBHOOK_URL`, con `Authorization: Bearer $PATCH_WATCH_WEBHOOK_TOKEN` y firma `x-patch-watch-signature: sha256=HMAC(secret, "<timestamp>.<body>")` |
| `stdout` | Una línea JSON por lote (para encadenar con otra herramienta) |

Otras variables:

| Variable | Por defecto |
|---|---|
| `PATCH_MCP_URL` | `https://patch.nimboxsre.com/mcp` |
| `PATCH_WATCH_INTERVAL` | `300` segundos (mínimo 30) |
| `PATCH_WATCH_MIN_SEVERITY` | `high` |
| `PATCH_WATCH_STATE` | `~/.local/state/patch-watch/state.json` |

Para k3s hay un `Dockerfile` y `deploy/k8s/patch-watch.yaml` en el repositorio, con el destino `http`.

## Cómo funciona

- **Solo sale, nunca escucha.** patch-watch llama al MCP de Patch con tu token; no abre puertos.
- **Qué vigila.** Para cada cliente de `list_clients` (uno con token de cliente, todos los del MSP con token de MSP), consulta `new_vulnerabilities` y `list_jobs` (las dos con `since`) y `security_findings`. Avisa de cada par CVE+servidor nuevo, también cuando una CVE conocida llega a otro servidor; de cada hallazgo nuevo; y de cada tarea cuando ya no le quedan servidores pendientes. `patch-watch doctor` dice qué herramientas y clientes ve tu token.
- **Sin avalanchas.** La primera pasada solo toma nota de lo que ya existe; después avisa una vez de cada cosa nueva, o de cada cambio de estado de una tarea. Todo lo de una pasada va en un único aviso, así que es un solo turno del agente.
- **Sin pérdidas.** Si un destino falla, no guarda el estado y lo reintenta en la siguiente pasada.
- **Gravedad.** Una CVE explotada (KEV) es `critical`; si no, la gravedad que da Patch. Hallazgos: `bad` es `high`, `warn` es `medium`, `info` es `info`. Una tarea con algún servidor `failed` o `rejected` es `high`; terminada sin fallos, `medium`.

## Seguridad

- **Lo que devuelve Patch es contenido no fiable** (las descripciones de CVE las escribe cualquiera). El aviso lo separa en un bloque `<patch-data>` del que no se puede salir, y tanto la skill como las instrucciones del canal dicen al agente que es dato, no orden.
- **Para un agente que actúa solo, usa un token de nivel «consultar y proponer».** Así lo más que puede hacer es dejar una propuesta para que la firme una persona.
- **Nada se ejecuta sin firma.** Ni el agente ni patch-watch cambian eso; cada servidor verifica la firma.

## Desarrollo

```sh
npm install
npm test        # empaqueta bin/patch-watch.mjs y prueba contra un Patch simulado
```
