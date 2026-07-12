# syntax=docker/dockerfile:1
#
# Production image for aaliyah-core.
#
# aaliyah-core depends on aaliyah-contracts via a file: link, so the BUILD
# CONTEXT is the PARENT directory that holds both repos side by side. Build with:
#
#   cd ~/IdeaProjects        # (the dir containing aaliyah-core + aaliyah-contracts)
#   docker build -f aaliyah-core/Dockerfile -t aaliyah-core:local .
#
# The runtime filesystem is disposable: all durable state lives in Postgres
# (AALIYAH_DATABASE_URL) and secrets are injected at runtime (never baked in).

# ---- base: pinned Node 20 + pnpm via Corepack ----
FROM node:20-bookworm-slim AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
WORKDIR /app

# ---- build: install all deps, build contracts then core ----
FROM base AS build
# Contracts is the dependency — install + build it first so core can link it.
COPY aaliyah-contracts/package.json aaliyah-contracts/
RUN cd aaliyah-contracts && pnpm install --no-frozen-lockfile
COPY aaliyah-contracts/ aaliyah-contracts/
RUN cd aaliyah-contracts && pnpm run build

# Core: install against the sibling contracts, then build.
COPY aaliyah-core/package.json aaliyah-core/pnpm-lock.yaml aaliyah-core/
RUN cd aaliyah-core && pnpm install --frozen-lockfile
COPY aaliyah-core/ aaliyah-core/
RUN cd aaliyah-core && pnpm run build

# Drop dev dependencies from core's tree for the runtime layer. CI=true lets
# pnpm remove the modules dir non-interactively (no TTY in a build).
RUN cd aaliyah-core && CI=true pnpm prune --prod

# ---- runtime: slim, non-root, production-only ----
FROM node:20-bookworm-slim AS runtime
ENV NODE_ENV=production
ENV PORT=8080
WORKDIR /app

# Preserve the sibling layout so the file: link and its relative symlink resolve.
COPY --from=build --chown=node:node /app/aaliyah-contracts/package.json /app/aaliyah-contracts/package.json
COPY --from=build --chown=node:node /app/aaliyah-contracts/dist /app/aaliyah-contracts/dist
COPY --from=build --chown=node:node /app/aaliyah-core/package.json /app/aaliyah-core/package.json
COPY --from=build --chown=node:node /app/aaliyah-core/node_modules /app/aaliyah-core/node_modules
COPY --from=build --chown=node:node /app/aaliyah-core/dist /app/aaliyah-core/dist

WORKDIR /app/aaliyah-core
USER node
EXPOSE 8080

# Liveness for the container runtime. Cloud Run uses its own probes (see deploy/),
# but this keeps `docker run` and other orchestrators honest.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/src/server.js"]
