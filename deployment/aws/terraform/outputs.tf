output "cluster_name" {
  value = module.eks.cluster_name
}

output "region" {
  value = var.aws_region
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "node_group_role_arn" {
  value = module.eks.eks_managed_node_groups["default"].iam_role_arn
}

output "alb_controller_role_arn" {
  value = module.eks_blueprints_addons.aws_load_balancer_controller.iam_role_arn
}

output "ebs_csi_role_arn" {
  value = module.ebs_csi_driver_irsa.iam_role_arn
}

output "external_secrets_role_arn" {
  value = aws_iam_role.external_secrets.arn
}

output "stratium_namespace" {
  value = local.stratium_namespace
}
