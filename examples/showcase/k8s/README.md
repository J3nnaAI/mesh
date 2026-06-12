# showcase on Kubernetes (microk8s)

A **demo-grade** deployment of the showcase — one StatefulSet per mesh peer (a peer is a pinned identity,
not a stateless replica), gossip-seed discovery, Service DNS advertises. Mirrors the topology that is
verified end-to-end in `docker-compose.yml` and follows the same pattern as the production manifests in
[../../../deploy/k8s/](../../../deploy/k8s/) (verified on MicroK8s).

## Deploy (microk8s)

```sh
# 1. build the image (from the monorepo root) and import it into the cluster
docker build -f examples/showcase/Dockerfile.go -t mesh-showcase:dev .
docker save mesh-showcase:dev | microk8s ctr image import -

# 2. apply
kubectl apply -k examples/showcase/k8s/

# 3. watch it come up, then reach the chat UI
kubectl -n j3nna-showcase get pods -w
kubectl -n j3nna-showcase port-forward svc/room-view 8487:8487
#   open http://localhost:8487  →  type 1 or 2
```

Tear down: `kubectl delete -k examples/showcase/k8s/` (and `kubectl delete ns j3nna-showcase`).

## Notes

- **Demo posture.** The console generates its root key on first run, passphrases are inline, and an
  `operator` Deployment auto-approves enrollments so the stack comes up hands-free. For production, harden
  per [../../../docs/DEPLOYMENT.md](../../../docs/DEPLOYMENT.md): a Secret-mounted root key with
  `CONSOLE_ROOT_KEY_REQUIRED=1`, passphrases/tokens from Secrets, and a real operator approving who joins.
- **carrier + registrar are co-located in the signal-bridge pod.** signal-bridge's webhook management is
  loopback-only, so the registrar shares the pod's network to register the carrier webhook, and writes the
  HMAC secret to a pod-local `emptyDir` the carrier reads — no ReadWriteMany volume required.
- **One image, many commands.** Every container runs the same `mesh-showcase:dev` image and selects its
  binary via `command:` — the same multi-binary image the compose file uses.
