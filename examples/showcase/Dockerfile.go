# syntax=docker/dockerfile:1
#
# Multi-stage Go build for the showcase's mesh peers + the bundled roles it runs against.
#
# BUILD CONTEXT IS THE MONOREPO ROOT. docker-compose.yml sets
#   build: { context: ../../.. , dockerfile: examples/showcase/Dockerfile.go }
# so the builder can see every Go module the services need: jip, agentkit, kernel, vault, console,
# signal-bridge, room-view, monitor, and the showcase services. The companion .dockerignore is an
# ALLOWLIST that strips the context to just those dirs. A fresh go.work ties them together (the showcase
# modules' own `replace` directives are harmless — the workspace wins).
#
# Output: one small static image carrying every binary; compose runs each via `command:`.

FROM golang:1.25-bookworm AS build
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
WORKDIR /src
COPY . .

RUN go work init \
 && go work use ./j3nna-mesh/jip \
        ./j3nna-mesh/agentkit \
        ./j3nna-mesh/kernel \
        ./j3nna-mesh/vault \
        ./j3nna-mesh/console \
        ./j3nna-mesh/signal-bridge \
        ./j3nna-mesh/room-view \
        ./j3nna-mesh/monitor \
        ./j3nna-mesh/examples/showcase/inventory-svc \
        ./j3nna-mesh/examples/showcase/quote-svc \
        ./j3nna-mesh/examples/showcase/dispatch-svc \
        ./j3nna-mesh/examples/showcase/desk \
        ./j3nna-mesh/examples/showcase/carrier \
        ./j3nna-mesh/examples/showcase/registrar \
        ./j3nna-mesh/examples/showcase/operator

RUN B=./j3nna-mesh; S=$B/examples/showcase; \
    go build -o /out/console        $B/console        && \
    go build -o /out/signal-bridge  $B/signal-bridge  && \
    go build -o /out/room-view      $B/room-view      && \
    go build -o /out/monitor        $B/monitor        && \
    go build -o /out/inventory-svc  $S/inventory-svc  && \
    go build -o /out/quote-svc      $S/quote-svc      && \
    go build -o /out/dispatch-svc   $S/dispatch-svc   && \
    go build -o /out/desk           $S/desk           && \
    go build -o /out/carrier        $S/carrier        && \
    go build -o /out/registrar      $S/registrar      && \
    go build -o /out/operator       $S/operator

# Writable state dirs owned by the distroless nonroot uid (65532): identities, vaults, and the shared
# webhook secret are written at runtime. A fresh named volume mounted here inherits this ownership, so the
# nonroot process can write — without it, the identity file write fails and a peer's grant subject (from
# enrollment) no longer matches the id it opens with.
RUN install -d -o 65532 -g 65532 /data /shared

# ── final: tiny static runtime with every binary + writable state dirs ──
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /app/
COPY --from=build --chown=65532:65532 /data /data
COPY --from=build --chown=65532:65532 /shared /shared
WORKDIR /data
USER nonroot:nonroot
# No ENTRYPOINT — docker-compose.yml selects the binary per service via `command:`.
