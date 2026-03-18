FROM node:20-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=21891
ENV DATA_DIR=/app/runtime/data
ENV SHARED_DIR=/app/runtime/shared

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY public ./public
COPY server.js pin.js share.js start.sh LICENSE README.md OPEN_SOURCE_AUDIT.md ROADMAP.md ./
COPY shared/sync_download.py ./shared/sync_download.py

RUN mkdir -p /app/runtime/data /app/runtime/shared

EXPOSE 21891

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 21891) + '/healthz').then((res) => process.exit(res.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]
