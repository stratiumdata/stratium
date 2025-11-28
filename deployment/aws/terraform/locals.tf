locals {
  cluster_tags = merge(
    var.tags,
    {
      "eks_cluster" = var.cluster_name
    }
  )

  node_group_desired_effective = max(var.node_group_min, var.node_group_desired)
  node_group_max_effective     = max(local.node_group_desired_effective, var.node_group_max)

  oidc_provider_host = replace(module.eks.cluster_oidc_issuer_url, "https://", "")

  external_secrets_secret_prefixes = [
    "stratium-aws-sm",
    "keycloak-aws-sm",
    "postgresql-aws-sm",
    "stratium-admin-key"
  ]

  external_secrets_secret_arns = [
    for prefix in local.external_secrets_secret_prefixes :
    "arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:${prefix}-*"
  ]

  external_secret_store_name = "stratium-aws-sm"
  stratium_namespace         = "stratium"
  stratium_chart_path        = "${path.module}/../../helm/stratium"

  stratium_helm_value_files = [
    "${path.module}/../../helm/stratium/values.yaml",
    "${path.module}/../../helm/stratium/values-ecr.yaml",
    "${path.module}/../../helm/stratium/values-free-tier.yaml",
    "${path.module}/../../helm/stratium/values-eks-demo-arm64.yaml"
  ]
}
