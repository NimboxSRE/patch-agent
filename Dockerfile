# patch-watch en modo daemon, para k3s u otro orquestador. Destino típico: http.
FROM node:22.22-alpine
RUN addgroup -S app && adduser -S -G app app && mkdir -p /state && chown app:app /state
COPY plugins/patch/bin/patch-watch.mjs /app/patch-watch.mjs
USER app
ENV PATCH_WATCH_STATE=/state/state.json PATCH_WATCH_SINKS=http
ENTRYPOINT ["node", "/app/patch-watch.mjs"]
CMD ["daemon"]
