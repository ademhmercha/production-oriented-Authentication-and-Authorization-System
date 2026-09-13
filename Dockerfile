# syntax=docker/dockerfile:1

# ---------- Build stage ----------
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json tsconfig.client.json ./
COPY src ./src
RUN npm run build

# ---------- Runtime stage ----------
FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

# Install production dependencies only (locked).
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist
COPY docs ./docs
COPY src/infrastructure/database/migrations ./migrations

# Signing keys live on a mounted volume; never bake them into the image.
RUN mkdir -p /app/keys && chown -R node:node /app
VOLUME ["/app/keys"]

USER node
EXPOSE 3000 3001 3002 8080

CMD ["node", "dist/apps/auth-server/main.js"]
