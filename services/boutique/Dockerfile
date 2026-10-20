# OSTRAL — boutique (Z1). Image officielle Node.js 22, tag fixé (E12).
# Étape 1 : installation des dépendances de production uniquement, depuis le lockfile (SS3 :
# versions figées, analysables par Trivy).
FROM node:22.23.3-alpine3.24 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && npm cache clean --force

# Étape 2 : image d'exécution minimale
FROM node:22.23.3-alpine3.24
ENV NODE_ENV=production
WORKDIR /app
# npm/npx/corepack inutiles à l'exécution : retirés pour réduire la surface d'attaque
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
 && mkdir -p /var/log/boutique \
 && chown node:node /var/log/boutique
COPY --from=deps --chown=root:root /app/node_modules ./node_modules
COPY --chown=root:root package.json ./
COPY --chown=root:root src ./src
COPY --chown=root:root migrations ./migrations
# Code en lecture seule pour l'utilisateur d'exécution ; seul le répertoire de journaux est inscriptible
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "src/server.js"]
