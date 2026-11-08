# ots-explain: Podman/Docker image.   podman build -t ots-explain .
#   run:   podman run --rm -v "$PWD":/work -w /work ots-explain verify report.txt report.txt.ots
#   page:  podman run --rm -p 8080:8080 ots-explain serve        (then open http://localhost:8080/)
#   cron:  podman run --rm -v /srv/proofs:/work -w /work ots-explain watch /work --ledger
#   tests: podman build --target test -t ots-explain-test . && podman run --rm ots-explain-test test
#   demo:  podman run --rm ots-explain-test demo                 (offline: mock calendar + synthetic chain)
# The runtime image has no network use of its own; nothing is sent anywhere unless a command you run asks to.

FROM docker.io/library/node:22-bookworm-slim AS web
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY web ./web
COPY spec ./spec
RUN npm run build

# Everything for development and CI in one image: node, python, Chromium (for the browser smoke test), the npm packages.
# Used by ./podman.sh so that nothing is installed on the host.   podman build --target ci -t ots-explain-ci .
FROM mcr.microsoft.com/playwright:v1.63.0-noble AS ci
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-pip git ca-certificates \
 && pip install --no-cache-dir --break-system-packages coverage && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
ENV no_proxy=127.0.0.1,localhost NO_PROXY=127.0.0.1,localhost
CMD ["npm", "run", "test:all"]

FROM docker.io/library/node:22-bookworm AS test
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=web /src/node_modules ./node_modules
COPY . .
COPY --from=web /src/web/build ./web/build
COPY --from=web /src/dist ./dist
COPY contrib/entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["test"]

FROM docker.io/library/python:3.13-slim AS runtime
LABEL org.opencontainers.image.title="ots-explain" org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY python/ /app/python/
COPY spec/openapi.json /app/spec/openapi.json
COPY tools/demo.py /app/tools/demo.py
COPY test/mock_calendar.py test/mock_esplora.py /app/test/
COPY vectors/explorer /app/vectors/explorer
COPY --from=web /src/dist/index.html /app/dist/index.html
COPY contrib/entrypoint.sh /app/entrypoint.sh
RUN useradd --uid 10001 --no-create-home ots && mkdir /work && chown ots /work
USER 10001
WORKDIR /work
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["help"]
