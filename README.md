# patch-agent

Plugin de [Patch by NimboxSRE](https://patchsre.com) para Claude Code y Codex, y **patch-watch**, el vigilante que avisa al agente de lo nuevo en Patch.

- Plugin: [`plugins/patch/`](plugins/patch/README.md)
- Código de patch-watch: `src/` (se empaqueta en `plugins/patch/bin/patch-watch.mjs` con `npm run build`)
- Pruebas: `npm test`, contra un MCP de Patch simulado (`test/mock-patch.ts`)
- Despliegue: `Dockerfile` y `deploy/k8s/`
- Marketplaces: `.claude-plugin/marketplace.json` (Claude Code) y `.agents/plugins/marketplace.json` (Codex)

`plugins/patch/bin/patch-watch.mjs` se versiona a propósito: así el plugin funciona sin `npm install`. Recompílalo tras cambiar `src/`.
