# J3nna Mesh — Deployment artifacts

Ready-to-run deployment topologies for J3nna Mesh. The full guide is in
**[../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md)** — read that first.

| Path | What it is | Status |
|---|---|---|
| [`docker/`](docker/) | A multi-module `Dockerfile` (distroless/static) + a `compose.yaml` running one of each role. | **Verified end-to-end** (enroll → approve → seed-discovery → join → post across containers). |
| [`k8s/`](k8s/) | Kubernetes manifests mirroring the Compose topology (`StatefulSet` + headless `Service` per peer). | **Verified on MicroK8s v1.35.3** (single instance per role). CI runs no cluster — schema-validate + smoke-test against your own cluster/version. |

Quick links:

- **Run it locally:** `docker compose -f docker/compose.yaml up --build -d`, then approve the
  enrollments — see [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md).
- **Kubernetes** apply order, the `StatefulSet` rationale, the fail-closed root key, and the
  startupProbe-not-liveness note: [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md).

> A mesh peer is a cryptographically-pinned **identity**, not a stateless worker — so each workload
> is a `StatefulSet` with a per-pod identity at `replicas: 1`. This release targets one instance per
> role; the [deployment guide](../docs/DEPLOYMENT.md) explains the model.
