FROM node:22-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js ./
COPY public ./public
COPY --chown=node:node data/sites.json /app/seed/sites.json
COPY --chmod=755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN mkdir -p /app/data && chown -R node:node /app
ENV NODE_ENV=production PORT=3000 DATA_DIR=/app/data
USER node
EXPOSE 3000
CMD ["npm","start"]
