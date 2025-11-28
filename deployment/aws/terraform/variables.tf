variable "aws_region" {
  description = "AWS region to deploy the demo cluster"
  type        = string
  default     = "us-east-2"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
  default     = "stratium-demo"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.60.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "List of CIDRs for public subnets"
  type        = list(string)
  default     = ["10.60.0.0/24", "10.60.1.0/24"]
}

variable "private_subnet_cidrs" {
  description = "List of CIDRs for private subnets"
  type        = list(string)
  default     = ["10.60.10.0/24", "10.60.11.0/24"]
}

variable "availability_zones" {
  description = "AZs to use (must match number of subnets)"
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b"]
}

variable "node_group_desired" {
  description = "Desired number of worker nodes"
  type        = number
  default     = 4
}

variable "node_group_min" {
  description = "Minimum number of worker nodes"
  type        = number
  default     = 4
}

variable "node_group_max" {
  description = "Maximum number of worker nodes"
  type        = number
  default     = 6
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "Stratium"
    Environment = "demo"
    ManagedBy   = "terraform"
  }
}
