# The demo's host: one instance in its own VPC, reachable on 80 and 443 only,
# administered through Session Manager (no SSH, no key pair). ../README.md
# covers bringing the stack up once this exists.
#
#   terraform init && terraform plan
#
# State is local and git-ignored. It holds resource identifiers, not secrets:
# the stack's passwords are generated on the instance by ../setup.sh.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-2"
}

variable "profile" {
  type    = string
  default = "default"
}

variable "instance_type" {
  description = "arm64, to match the Ubuntu image below. About 4 GB: Keycloak alone wants 1 GB."
  type        = string
  default     = "t4g.medium"
}

variable "alert_email" {
  description = "Where the monthly cost alert goes. Empty creates no budget."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  type    = number
  default = 50
}

provider "aws" {
  region  = var.region
  profile = var.profile
  default_tags {
    tags = { Project = "stratium-demo" }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
}

# --- Network: a VPC with nothing else in it -------------------------------

resource "aws_vpc" "demo" {
  cidr_block           = "10.42.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "stratium-demo" }
}

resource "aws_internet_gateway" "demo" {
  vpc_id = aws_vpc.demo.id
}

resource "aws_subnet" "demo" {
  vpc_id            = aws_vpc.demo.id
  cidr_block        = aws_vpc.demo.cidr_block
  availability_zone = data.aws_availability_zones.available.names[0]
  tags              = { Name = "stratium-demo" }
}

resource "aws_route_table" "demo" {
  vpc_id = aws_vpc.demo.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo.id
  }
}

resource "aws_route_table_association" "demo" {
  subnet_id      = aws_subnet.demo.id
  route_table_id = aws_route_table.demo.id
}

resource "aws_security_group" "demo" {
  name        = "stratium-demo"
  description = "Stratium demo: web in, web out"
  vpc_id      = aws_vpc.demo.id

  ingress {
    description = "HTTPS: the admin plane, sign-in and the PDP"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP: redirect to HTTPS and the certificate challenge"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound is image pulls, certificate issuance, Session Manager (443) and
  # Ubuntu's package mirrors (80). DNS and time use the VPC's own services,
  # which security groups do not filter.
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Identity: Session Manager and nothing else ----------------------------

resource "aws_iam_role" "demo" {
  name = "stratium-demo"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.demo.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "demo" {
  name = "stratium-demo"
  role = aws_iam_role.demo.name
}

# --- The host --------------------------------------------------------------

resource "aws_instance" "demo" {
  ami                    = data.aws_ssm_parameter.ubuntu.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.demo.id
  vpc_security_group_ids = [aws_security_group.demo.id]
  iam_instance_profile   = aws_iam_instance_profile.demo.name
  # A public address from first boot, so user_data can install packages
  # before the Elastic IP below is attached.
  associate_public_ip_address = true
  user_data                   = file("${path.module}/user-data.sh")

  # IMDSv2 only, and a hop limit of 1: a container is one hop further than
  # the host, so it cannot read the instance role's credentials.
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Standard, not unlimited: sustained load slows the demo down instead of
  # adding to the bill.
  credit_specification {
    cpu_credits = "standard"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  tags = { Name = "stratium-demo" }

  lifecycle {
    # A newer Ubuntu image, or an edit to user-data.sh, must not replace a
    # running host on the next apply. Taint the instance to rebuild it.
    ignore_changes = [ami, user_data]
  }
}

resource "aws_eip" "demo" {
  domain   = "vpc"
  instance = aws_instance.demo.id
  tags     = { Name = "stratium-demo" }
}

# --- Cost alert ------------------------------------------------------------

resource "aws_budgets_budget" "demo" {
  count        = var.alert_email == "" ? 0 : 1
  name         = "stratium-demo"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["user:Project$stratium-demo"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
}

output "public_ip" {
  description = "Point the demo hostname's A record here."
  value       = aws_eip.demo.public_ip
}

output "connect" {
  description = "A shell on the host, through Session Manager."
  value       = "aws ssm start-session --profile ${var.profile} --region ${var.region} --target ${aws_instance.demo.id}"
}
