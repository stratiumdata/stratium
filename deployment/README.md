# Deployment Resources

This directory contains everything needed to deploy Stratium in different environments. The content is now organized by deployment method to make it easier to find the correct assets.

## Docker
All Dockerfiles, Compose stacks, and local demo documentation live under [`docker/`](docker/).
- `Dockerfile`, `Dockerfile.pap`, `Dockerfile.postgres`
- `docker-compose*.yml` bundles for RSA, ECC, KEM, and demo scenarios
- Guides such as `README.demo.md` and `ALGORITHMS.md`

Follow the instructions in `docker/README.md` for building images and running the Compose stacks.

## Helm
Helm charts, scripts, and environment-specific guides remain under [`helm/`](helm/). Refer to that directory for deploying to EKS or other Kubernetes clusters using Helm.

## Additional Assets
The deployment root still contains shared infrastructure resources:
- `kubernetes/` manifests and `KUBERNETES.md`
- `dns/`, `certs/`, and other infrastructure helpers
- `postgres/` initialization SQL used by both Docker and Helm scenarios

This layout keeps Docker- and Helm-specific files scoped to their directories while preserving common assets at the root.
