module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.32"
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets

  enable_irsa = true

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = local.cluster_tags

  eks_managed_node_groups = {
    default = {
      instance_types = ["c6g.xlarge"]
      ami_type       = "AL2_ARM_64"

      min_size     = var.node_group_min
      max_size     = local.node_group_max_effective
      desired_size = local.node_group_desired_effective

      capacity_type         = "ON_DEMAND"
      disk_size             = 10
      subnet_ids            = module.vpc.private_subnets
      create_security_group = false
      additional_tags = {
        Name = "${var.cluster_name}-node"
      }
    }
  }

  cluster_addons = {
    coredns = {
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {}
    vpc-cni = {
      resolve_conflicts = "OVERWRITE"
    }
  }

  create_aws_auth_configmap = false
  manage_aws_auth_configmap = false
}

# IAM role for AWS Load Balancer Controller (IRSA)
module "alb_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.20"

  role_name_prefix                       = "${var.cluster_name}-alb-"
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = [
        "kube-system:aws-load-balancer-controller",
        "kube-system:aws-load-balancer-controller-sa"
      ]
    }
  }

  tags = local.cluster_tags
}

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  providers = {
    kubernetes = kubernetes.eks
    helm       = helm.eks
  }

  depends_on = [module.eks]

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  enable_aws_load_balancer_controller = true

  aws_load_balancer_controller = {
    create_role = false
    set = [
      {
        name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
        value = module.alb_irsa.iam_role_arn
      }
    ]
  }

  eks_addons = {
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_driver_irsa.iam_role_arn
    }
  }

  tags = local.cluster_tags
}

module "ebs_csi_driver_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.20"

  role_name_prefix      = "${var.cluster_name}-ebs-csi-"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }

  tags = local.cluster_tags
}

data "aws_iam_policy_document" "external_secrets_irsa" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:sub"
      values   = ["system:serviceaccount:external-secrets:external-secrets"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_provider_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }
  }
}

data "aws_iam_policy_document" "external_secrets_access" {
  statement {
    sid    = "SecretsManagerRead"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret"
    ]
    resources = local.external_secrets_secret_arns
  }
}

resource "aws_iam_policy" "external_secrets_access" {
  name        = "${var.cluster_name}-external-secrets-access"
  description = "Allow External Secrets controller to read Stratium secrets"
  policy      = data.aws_iam_policy_document.external_secrets_access.json
}

resource "aws_iam_role" "external_secrets" {
  name               = "${var.cluster_name}-external-secrets-irsa"
  assume_role_policy = data.aws_iam_policy_document.external_secrets_irsa.json
  tags               = local.cluster_tags
}

resource "aws_iam_role_policy_attachment" "external_secrets_access" {
  role       = aws_iam_role.external_secrets.name
  policy_arn = aws_iam_policy.external_secrets_access.arn
}

resource "helm_release" "external_secrets" {
  provider = helm.eks

  name             = "external-secrets"
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  namespace        = "external-secrets"
  create_namespace = true

  set {
    name  = "installCRDs"
    value = "true"
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.external_secrets.arn
  }

  depends_on = [
    module.eks,
    aws_iam_role_policy_attachment.external_secrets_access
  ]
}

resource "kubectl_manifest" "cluster_secret_store" {
  provider = kubectl.eks

  yaml_body = yamlencode({
    apiVersion = "external-secrets.io/v1"
    kind       = "ClusterSecretStore"
    metadata = {
      name = local.external_secret_store_name
    }
    spec = {
      provider = {
        aws = {
          service = "SecretsManager"
          region  = var.aws_region
          auth = {
            jwt = {
              serviceAccountRef = {
                name      = "external-secrets"
                namespace = "external-secrets"
              }
            }
          }
        }
      }
    }
  })

  depends_on = [helm_release.external_secrets]
}

resource "kubernetes_storage_class_v1" "gp3_auto" {
  provider = kubernetes.eks

  metadata {
    name = "gp3-auto"
  }

  storage_provisioner = "ebs.csi.aws.com"
  parameters = {
    type      = "gp3"
    encrypted = "true"
  }

  reclaim_policy         = "Delete"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  depends_on = [module.eks_blueprints_addons]
}

resource "kubectl_manifest" "stratium_namespace" {
  provider = kubectl.eks

  yaml_body = yamlencode({
    apiVersion = "v1"
    kind       = "Namespace"
    metadata = {
      name = local.stratium_namespace
      labels = {
        "managed-by" = "terraform"
      }
    }
  })

  wait             = false
  wait_for_rollout = false
}

data "helm_template" "stratium" {
  provider = helm.eks

  name              = "stratium"
  chart             = local.stratium_chart_path
  namespace         = local.stratium_namespace
  dependency_update = true
  wait              = false

  values = [
    for value_file in local.stratium_helm_value_files : file(value_file)
  ]
}

data "kubectl_file_documents" "stratium" {
  content = data.helm_template.stratium.manifest
}

resource "kubectl_manifest" "stratium" {
  for_each = {
    for idx, doc in data.kubectl_file_documents.stratium.documents :
    format("%04d", idx) => doc
    if trimspace(doc) != ""
  }

  provider = kubectl.eks

  yaml_body          = each.value
  wait               = false
  wait_for_rollout   = false
  override_namespace = local.stratium_namespace

  depends_on = [
    kubectl_manifest.stratium_namespace,
    helm_release.external_secrets,
    kubectl_manifest.cluster_secret_store,
    kubernetes_storage_class_v1.gp3_auto
  ]
}
