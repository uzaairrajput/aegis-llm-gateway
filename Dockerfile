FROM node:24-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY mock ./mock
COPY eval ./eval
RUN npm run build && npm prune --omit=dev

FROM node:24-slim
ENV NODE_ENV=production PORT=8080 DB_PATH=/data/aegis.db POLICIES_DIR=/app/policies
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY policies ./policies
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD node -e "fetch('http://localhost:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/src/index.js"]
