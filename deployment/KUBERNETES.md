# Kubernetes & Helm Deployment Summary

This document provides a complete overview of the production-ready Kubernetes and Helm deployment for Stratium.

## Directory Structure

```
deployment/
├── helm/                          # Helm chart directory
│   ├── stratium/                 # Main Helm chart
│   │   ├── Chart.yaml            # Chart metadata
│   │   ├── values.yaml           # Default values
│   │   ├── values-production.yaml # Production values template
│   │   ├── .helmignore           # Files to ignore in chart
│   │   └── templates/            # Kubernetes templates
│   │       ├── _helpers.tpl      # Template helper functions
│   │       ├── NOTES.txt         # Post-install notes
│   │       ├── postgresql-*.yaml # PostgreSQL resources
│   │       ├── redis-*.yaml      # Redis resources
│   │       ├── keycloak-*.yaml   # Keycloak resources
│   │       ├── platform-*.yaml   # Platform service resources
│   │       ├── key-manager-*.yaml # Key Manager resources
│   │       ├── key-access-*.yaml # Key Access resources
│   │       ├── pap-*.yaml        # PAP service resources
│   │       ├── pap-ui-*.yaml     # PAP UI resources
│   │       ├── envoy-*.yaml      # Envoy proxy resources
│   │       ├── stratium-secret.yaml # Secrets
│   │       ├── ingress.yaml      # Ingress resources
│   │       ├── hpa.yaml          # Horizontal Pod Autoscalers
│   │       ├── pdb.yaml          # Pod Disruption Budgets
│   │       └── networkpolicy.yaml # Network Policies
│   ├── quick-start.sh            # Quick deployment script
│   └── README.md                 # Helm chart documentation
├── kubernetes/                    # Raw Kubernetes manifests
│   └── README.md                 # Kubernetes deployment guide
├── docker-compose.yml            # Docker Compose for local dev
└── README.md                     # Main deployment documentation

```

## Components Deployed

### Infrastructure Services

1. **PostgreSQL StatefulSet**
   - High-availability database
   - Persistent volume claims for data
   - Init scripts for schema creation
   - Databases: keycloak, stratium_pap, stratium_keymanager

2. **Redis Deployment**
   - Cache layer for PAP and Platform services
   - Optional persistence
   - Optional authentication

3. **Keycloak Deployment**
   - OpenID Connect identity provider
   - Realm import from ConfigMap
   - PostgreSQL backend
   - Optional ingress for external access

### Stratium Services

4. **Platform Service**
   - Authorization and entitlement decisions (gRPC)
   - Horizontal Pod Autoscaling (2-10 replicas)
   - Pod Disruption Budget
   - Health checks and resource limits

5. **Key Manager Service**
   - Cryptographic key management (gRPC)
   - Persistent volume for admin keys
   - OIDC authentication
   - Horizontal Pod Autoscaling (2-10 replicas)

6. **Key Access Service**
   - Key wrapping/unwrapping operations (gRPC)
   - Depends on Key Manager
   - OIDC authentication
   - Horizontal Pod Autoscaling (2-10 replicas)

7. **PAP Service**
   - Policy Administration Point REST API
   - PostgreSQL and Redis integration
   - Optional ingress
   - Horizontal Pod Autoscaling (2-10 replicas)

8. **PAP UI**
   - React-based web interface
   - Nginx serving
   - Optional ingress
   - Horizontal Pod Autoscaling (2-5 replicas)

9. **Envoy Proxy**
   - gRPC-Web gateway
   - Routes to Platform, Key Manager, Key Access
   - CORS configuration
   - Optional ingress

## Features

### High Availability

- **Multiple Replicas**: All services run with 2+ replicas by default
- **Pod Disruption Budgets**: Ensures minimum availability during updates
- **Anti-Affinity**: Spreads pods across nodes (configurable)
- **Health Checks**: Liveness and readiness probes for all services

### Auto-Scaling

- **Horizontal Pod Autoscaling**: Scales based on CPU and memory utilization
- **Configurable Targets**: 70% CPU, 80% memory by default
- **Min/Max Replicas**: Prevents under/over-provisioning

### Security

- **Network Policies**: Restricts pod-to-pod communication
- **Pod Security Contexts**: Non-root users, read-only root filesystem
- **Container Security**: Dropped capabilities, no privilege escalation
- **Secrets Management**: Kubernetes secrets for sensitive data
- **RBAC**: Service accounts with minimal permissions

### Production Ready

- **Resource Limits**: CPU and memory limits for all pods
- **Persistent Storage**: StatefulSets for databases
- **Init Containers**: Wait for dependencies before starting
- **Config Management**: ConfigMaps for configuration
- **Ingress Support**: Built-in ingress configuration
- **TLS Support**: Certificate management ready

### Monitoring & Observability

- **ServiceMonitor**: Prometheus integration (optional)
- **Health Endpoints**: All services expose health checks
- **Structured Logging**: JSON-formatted logs
- **Metrics Export**: Ready for Prometheus scraping

## Quick Start

### Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- kubectl configured
- Sufficient cluster resources (8 CPU, 16GB RAM minimum)

### Deploy with Script

```bash
cd deployment/helm
./quick-start.sh
```

### Deploy Manually

```bash
# Install with default values
helm install stratium ./stratium -n stratium --create-namespace

# Or with custom values
helm install stratium ./stratium -n stratium --create-namespace -f custom-values.yaml
```

### Access Services

```bash
# Port forward to PAP UI
kubectl port-forward -n stratium svc/stratium-pap-ui 3000:80

# Port forward to Keycloak
kubectl port-forward -n stratium svc/stratium-keycloak 8080:8080

# Port forward to PAP API
kubectl port-forward -n stratium svc/stratium-pap 8090:8090
```

## Production Deployment Checklist

### 1. Pre-Deployment

- [ ] Review and customize `values-production.yaml`
- [ ] Set strong passwords for all services
- [ ] Configure external secret management
- [ ] Build and push Docker images to registry
- [ ] Create image pull secrets if using private registry
- [ ] Configure DNS for ingress hosts
- [ ] Obtain TLS certificates (or setup cert-manager)

### 2. Infrastructure

- [ ] Provision Kubernetes cluster (AKS, EKS, GKE)
- [ ] Configure storage classes for persistent volumes
- [ ] Install ingress controller (nginx, traefik)
- [ ] Install cert-manager for TLS (optional)
- [ ] Configure backup solution (Velero)

### 3. Security

- [ ] Enable network policies
- [ ] Configure pod security standards
- [ ] Set up RBAC policies
- [ ] Enable audit logging
- [ ] Configure security scanning (Falco, Twistlock)

### 4. Monitoring

- [ ] Install Prometheus Operator
- [ ] Configure ServiceMonitors
- [ ] Set up Grafana dashboards
- [ ] Configure alerting rules
- [ ] Set up log aggregation (ELK, Loki)

### 5. Deployment

- [ ] Deploy Stratium using Helm
- [ ] Verify all pods are running
- [ ] Test service connectivity
- [ ] Verify ingress configuration
- [ ] Test authentication with Keycloak
- [ ] Run smoke tests

### 6. Post-Deployment

- [ ] Configure automated backups
- [ ] Set up disaster recovery procedures
- [ ] Document access procedures
- [ ] Train operations team
- [ ] Set up on-call rotation

## Configuration Examples

### Minimal Development

```yaml
# minimal-values.yaml
postgresql:
  persistence:
    enabled: false

redis:
  persistence:
    enabled: false

platform:
  replicaCount: 1
  autoscaling:
    enabled: false

keyManager:
  replicaCount: 1
  autoscaling:
    enabled: false

security:
  networkPolicy:
    enabled: false
```

### Production with TLS

```yaml
# production-tls-values.yaml
keycloak:
  ingress:
    enabled: true
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: auth.example.com
    tls:
      - secretName: keycloak-tls
        hosts:
          - auth.example.com

papUI:
  ingress:
    enabled: true
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: stratium.example.com
    tls:
      - secretName: stratium-tls
        hosts:
          - stratium.example.com
```

### High Availability

```yaml
# ha-values.yaml
postgresql:
  replicaCount: 1  # Use PostgreSQL Operator for HA

platform:
  replicaCount: 3
  autoscaling:
    minReplicas: 3
    maxReplicas: 20
  podDisruptionBudget:
    enabled: true
    minAvailable: 2

keyManager:
  replicaCount: 3
  autoscaling:
    minReplicas: 3
    maxReplicas: 15
  podDisruptionBudget:
    enabled: true
    minAvailable: 2

affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchLabels:
            app.kubernetes.io/name: stratium
        topologyKey: kubernetes.io/hostname
```

## Upgrade Procedures

### Upgrade Helm Release

```bash
# Update values
helm upgrade stratium ./stratium -n stratium -f production-values.yaml

# Rollback if needed
helm rollback stratium -n stratium
```

### Rolling Updates

```bash
# Update image tag
helm upgrade stratium ./stratium -n stratium \
  --set platform.image.tag=v1.1.0 \
  --set keyManager.image.tag=v1.1.0

# Watch rollout
kubectl rollout status deployment/stratium-platform -n stratium
```

## Troubleshooting

### Common Issues

1. **Pods in CrashLoopBackOff**
   - Check logs: `kubectl logs -n stratium <pod-name>`
   - Check events: `kubectl describe pod -n stratium <pod-name>`
   - Verify dependencies are ready

2. **Service Not Accessible**
   - Check service: `kubectl get svc -n stratium`
   - Check endpoints: `kubectl get endpoints -n stratium`
   - Verify network policies

3. **Database Connection Issues**
   - Check PostgreSQL logs
   - Verify credentials in secrets
   - Test connectivity from pod

4. **Ingress Not Working**
   - Check ingress controller
   - Verify DNS configuration
   - Check TLS certificates

## Maintenance

### Backup Procedures

```bash
# Backup PostgreSQL
kubectl exec -n stratium stratium-postgresql-0 -- \
  pg_dumpall -U keycloak > backup-$(date +%Y%m%d).sql

# Backup Helm values
helm get values stratium -n stratium > stratium-values-backup.yaml
```

### Update Procedures

1. Review release notes
2. Test in staging environment
3. Backup current state
4. Perform upgrade
5. Verify functionality
6. Monitor for issues

## Additional Resources

- [Helm Chart README](helm/README.md) - Detailed configuration guide
- [Kubernetes Guide](kubernetes/README.md) - Raw manifests and GitOps
- [Docker Compose](README.md) - Local development setup
- [Values Reference](helm/stratium/values.yaml) - All configuration options

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/stratium/issues
- Documentation: https://docs.stratium.io
- Slack: https://stratium.slack.com