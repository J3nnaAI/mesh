# Multi-stage build for any J3nna Mesh binary. The repo is a Go multi-module workspace, so the build needs
# the whole tree + go.work; pick the module with --build-arg MODULE=<console|room-agent|room-view|
# signal-bridge|samples/joiner>. Produces a static (CGO-free, stdlib-only) binary on a distroless base
# (distroless/static ships ca-certificates, so HTTPS peer/console URLs work if you use them).
#
#   docker build -f deploy/docker/Dockerfile --build-arg MODULE=console -t j3nna-mesh/console .
#
# GO_VERSION tracks the latest stable Go (the project's standing policy + a govulncheck-clean stdlib).
ARG GO_VERSION=1.26.4

FROM golang:${GO_VERSION} AS build
ARG MODULE
WORKDIR /src
COPY . .
# Build the selected module against the committed workspace. Static + trimmed + stripped.
RUN test -n "${MODULE}" && cd "${MODULE}" \
 && CGO_ENABLED=0 GOFLAGS=-trimpath go build -ldflags="-s -w" -o /out/app .
# A writable state dir owned by the distroless nonroot uid (65532): identity files, the vault, and the CRL
# are written at runtime relative to the working directory. Mount a volume here in production.
RUN install -d -o 65532 -g 65532 /data

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/app /usr/local/bin/app
COPY --from=build --chown=65532:65532 /data /data
WORKDIR /data
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/app"]
