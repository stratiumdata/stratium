# AWS EKS Deployment (demo-arm64)

This guide captures the settings we use to deploy Stratium to the existing **demo-arm64** cluster in **us-east-2**. It assumes the cluster already runs the AWS Load Balancer Controller and that you have `kubectl`/`helm` access.

## 1. Prerequisites

- AWS CLI with credentials that can read Secrets Manager and ECR
- `kubectl` pointed at the `demo-arm64` cluster
- Helm 3.8+
- [Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/) or another mechanism to pull secrets from AWS Secrets Manager (see below)
- ALB Ingress Controller installed in the cluster

## 2. Build & Push Images to ECR

```bash
cd deployment/helm
./build-images.sh
./push-to-ecr.sh           # pushes to 536176198371.dkr.ecr.us-east-2.amazonaws.com
./create-ecr-secret.sh stratium   # creates ecr-registry-secret in the stratium namespace
```

## 3. Prepare Secrets in AWS Secrets Manager

Create three secrets in AWS Secrets Manager (names can be changed, but the keys must match). Using the AWS CLI:

```bash
# Stratium application secret
aws secretsmanager create-secret \
  --region us-east-2 \
  --name stratium-aws-sm \
  --secret-string '{
    "database-password": "stratium",
    "key-manager-oidc-secret": "stratium-key-manager-secret",
    "key-access-oidc-secret": "stratium-key-access-secret",
    "pap-oidc-secret": "stratium-pap-secret"
  }'

# Keycloak admin secret
aws secretsmanager create-secret \
  --region us-east-2 \
  --name keycloak-aws-sm \
  --secret-string '{
    "admin-user": "admin",
    "admin-password": "super-secure-password"
  }'

# PostgreSQL secret
aws secretsmanager create-secret \
  --region us-east-2 \
  --name postgresql-aws-sm \
  --secret-string '{
    "postgres-password": "keycloak_password",
    "username": "keycloak",
    "password": "keycloak_password",
    "stratium-user": "stratium",
    "stratium-password": "stratium"
  }'
```

If the secrets already exist, use `aws secretsmanager put-secret-value --secret-id … --secret-string file://secret.json`.

Schema reference:

1. **Stratium application secret** – `stratium-aws-sm`
   ```json
   {
     "database-password": "stratium",
     "key-manager-oidc-secret": "stratium-key-manager-secret",
     "key-access-oidc-secret": "stratium-key-access-secret",
     "pap-oidc-secret": "stratium-pap-secret"
   }
   ```
2. **Keycloak admin secret** – `keycloak-aws-sm`
   ```json
   {
     "admin-user": "admin",
     "admin-password": "super-secure-password"
   }
   ```
3. **PostgreSQL secret** – `postgresql-aws-sm`
   ```json
   {
     "postgres-password": "keycloak_password",
     "username": "keycloak",
     "password": "keycloak_password",
     "stratium-user": "stratium",
     "stratium-password": "stratium"
   }
   ```

Sync them into Kubernetes secrets (run whenever you rotate secrets):

```bash
cd deployment/helm
STRATIUM_SECRET_ID=stratium-aws-sm \
KEYCLOAK_SECRET_ID=keycloak-aws-sm \
POSTGRESQL_SECRET_ID=postgresql-aws-sm \
./sync-aws-secrets.sh
```

> The script fetches each secret from AWS Secrets Manager and applies them as Kubernetes Secrets (`stratium-aws-sm`, `keycloak-aws-sm`, and `postgresql-aws-sm`). The Helm chart is configured to reuse those names.

## 4. Deploy with Helm

1. Update the placeholder hostnames inside `stratium/values-eks-demo-arm64.yaml` once you know the ALB DNS name or Route53 records you plan to use.
2. Deploy using the layered values files:

```bash
cd deployment/helm
helm upgrade --install stratium ./stratium \
  -n stratium \
  --create-namespace \
  -f stratium/values-ecr.yaml \
  -f stratium/values-free-tier.yaml \
  -f stratium/values-eks-demo-arm64.yaml
```

This enables ALB ingress (HTTP only for now), reuses the externally managed secrets, and keeps resource requests aligned with the Free Tier.

## 5. Post-Deployment Checklist

- `kubectl get pods -n stratium` – ensure all pods are `Running 1/1`.
- `kubectl get ingress -n stratium` – note the ALB hostname; update your DNS/Route53 records if you want friendly names.
- `kubectl logs deployment/stratium-keycloak -n stratium` – confirm Keycloak imported the realm.
- Update `values-eks-demo-arm64.yaml` with final hostnames and re-run `helm upgrade` once DNS is in place.

## 6. Next Steps

- **AWS Load Balancer Controller IAM policy**: AWS does not ship a managed policy by default. Create and attach it once per account:

  ```bash
  curl -o iam-policy.json \
    https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/v2.7.1/docs/install/iam_policy.json

  aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://iam-policy.json

  aws iam attach-role-policy \
    --role-name eksctl-demo-arm64-addon-iamserviceaccount-kub-Role1-lmrYR7KYd8ni \
    --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AWSLoadBalancerControllerIAMPolicy

  kubectl rollout restart deployment/aws-load-balancer-controller -n kube-system
  ```

  Replace `<ACCOUNT_ID>` with your AWS account number.

- Add ACM certificates and update the ingress annotations (`alb.ingress.kubernetes.io/listen-ports` & `alb.ingress.kubernetes.io/certificate-arn`) for TLS.
- Consider enabling AWS IRSA for image pulls instead of static ECR secrets.
- Tune `values-free-tier.yaml` or create `values-eks-prod.yaml` if you increase node sizes or replicas.
