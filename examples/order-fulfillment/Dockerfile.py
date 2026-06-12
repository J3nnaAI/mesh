# syntax=docker/dockerfile:1
#
# The Python agents image (intake / pricing / fulfillment / verifier). BUILD CONTEXT IS THE MONOREPO ROOT
# (see docker-compose.yml); the companion Dockerfile.py.dockerignore allowlists just the SDK + the agents.
FROM python:3.12-slim

RUN pip install --no-cache-dir cryptography

WORKDIR /app
COPY sdks/python/                                 /app/sdk/
COPY examples/order-fulfillment/agents/           /app/agents/
COPY examples/order-fulfillment/inventory.jsonl   /app/inventory.jsonl

# The agents locate the SDK via J3NNA_SDK (see agents/common.py).
ENV J3NNA_SDK=/app/sdk/src PYTHONUNBUFFERED=1

# No ENTRYPOINT — docker-compose.yml selects the agent per service via `command:`.
