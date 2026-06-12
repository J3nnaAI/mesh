# syntax=docker/dockerfile:1
#
# Multi-stage Go build for the order-fulfillment example's mesh peers.
#
# BUILD CONTEXT IS THE MONOREPO ROOT (/home/j3nna/web-stt-tts). docker-compose.yml sets
#   build: { context: ../../.. , dockerfile: examples/order-fulfillment/Dockerfile.go }
# so the builder can see every Go module the services replace into: jip, agentkit, kernel,
# {vault,console,room-agent,monitor} and the two example services. The companion
# Dockerfile.go.dockerignore is an ALLOWLIST that strips the context to just those dirs.
#
# A fresh go.work is generated here (NOT the repo's go.work, whose relative `use`
# paths and extra modules don't match this flattened context). The example go.mod `replace`
# directives are harmless — the workspace wins.
#
# Output: one small static image carrying all five binaries; compose runs each via `command:`.

FROM golang:1.25-bookworm AS build

# The modules pin `go 1.26.4`; GOTOOLCHAIN=auto lets the 1.25 toolchain fetch + run 1.26.4.
# (No GOFLAGS=-mod=mod — it's incompatible with the go.work workspace mode used below.)
ENV GOTOOLCHAIN=auto CGO_ENABLED=0

WORKDIR /src

# Bring in the whole (allowlisted) monorepo subset. Layout under /src:
#   {jip,agentkit,kernel,vault,console,room-agent,monitor,examples/order-fulfillment/...}
COPY . .

# A workspace tying the exact module dirs this example needs together. Listing them in go.work
# overrides each module's v0.0.0 requires with the local source — no network module fetch for
# our own modules (the toolchain itself is still auto-downloaded by GOTOOLCHAIN=auto).
RUN go work init \
 && go work use ./jip \
        ./agentkit \
        ./kernel \
        ./vault \
        ./console \
        ./room-agent \
        ./monitor \
        ./examples/order-fulfillment/kernel-service \
        ./examples/order-fulfillment/vault-service

# Build the five binaries. Static (CGO off) so they drop into distroless/static.
RUN go build -o /out/console        ./console \
 && go build -o /out/room-agent     ./room-agent \
 && go build -o /out/monitor        ./monitor \
 && go build -o /out/kernel-service ./examples/order-fulfillment/kernel-service \
 && go build -o /out/vault-service  ./examples/order-fulfillment/vault-service

# ── final: tiny static runtime with all five binaries + the seed master data ──
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=build /out/console        /app/console
COPY --from=build /out/room-agent     /app/room-agent
COPY --from=build /out/monitor        /app/monitor
COPY --from=build /out/kernel-service /app/kernel-service
COPY --from=build /out/vault-service  /app/vault-service
# Master data the kernel-service preloads (KSVC_SEED=/app/inventory.jsonl).
COPY --from=build /src/examples/order-fulfillment/inventory.jsonl /app/inventory.jsonl

# No ENTRYPOINT — docker-compose.yml selects the binary per service via `command:`.
