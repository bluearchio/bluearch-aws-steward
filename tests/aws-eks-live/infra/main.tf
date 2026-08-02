data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name_prefix = "bluearch-steward-eks-${var.run_id}"
  create_vpc  = var.existing_vpc_id == null
  common_tags = {
    "bluearch.io/run-id"     = var.run_id
    "bluearch.io/purpose"    = "steward-eks-live-validation"
    "bluearch.io/owner"      = var.owner
    "bluearch.io/expires-at" = var.expires_at
  }
  public_subnets = {
    a = { cidr = "10.73.0.0/20", az = data.aws_availability_zones.available.names[0] }
    b = { cidr = "10.73.16.0/20", az = data.aws_availability_zones.available.names[1] }
  }
  vpc_id = local.create_vpc ? aws_vpc.lab[0].id : var.existing_vpc_id
  public_subnet_ids = local.create_vpc ? [
    for key in sort(keys(aws_subnet.public)) : aws_subnet.public[key].id
  ] : var.existing_public_subnet_ids
  broken_subnet_az = coalesce(var.broken_subnet_az, data.aws_availability_zones.available.names[0])
}

resource "aws_vpc" "lab" {
  count = local.create_vpc ? 1 : 0

  cidr_block           = "10.73.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = local.name_prefix }
}

resource "aws_internet_gateway" "lab" {
  count = local.create_vpc ? 1 : 0

  vpc_id = aws_vpc.lab[0].id
  tags   = { Name = local.name_prefix }
}

resource "aws_subnet" "public" {
  for_each = local.create_vpc ? local.public_subnets : {}

  vpc_id                  = aws_vpc.lab[0].id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = true

  tags = {
    Name                     = "${local.name_prefix}-public-${each.key}"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "broken" {
  vpc_id                  = local.vpc_id
  cidr_block              = var.broken_subnet_cidr
  availability_zone       = local.broken_subnet_az
  map_public_ip_on_launch = false

  tags = { Name = "${local.name_prefix}-broken-no-egress" }
}

resource "aws_route_table" "public" {
  count = local.create_vpc ? 1 : 0

  vpc_id = aws_vpc.lab[0].id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab[0].id
  }
  tags = { Name = "${local.name_prefix}-public" }
}

resource "aws_route_table_association" "public" {
  for_each = aws_subnet.public

  subnet_id      = each.value.id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "broken" {
  vpc_id = local.vpc_id
  tags   = { Name = "${local.name_prefix}-broken-no-egress" }
}

resource "aws_route_table_association" "broken" {
  subnet_id      = aws_subnet.broken.id
  route_table_id = aws_route_table.broken.id
}

resource "aws_iam_role" "cluster" {
  name = "${local.name_prefix}-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "node" {
  name = "${local.name_prefix}-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "AmazonEKSWorkerNodePolicy",
    "AmazonEC2ContainerRegistryPullOnly",
    "AmazonEKS_CNI_Policy",
  ])

  role       = aws_iam_role.node.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/${each.value}"
}

resource "aws_cloudwatch_log_group" "healthy" {
  name              = "/aws/eks/${local.name_prefix}-healthy/cluster"
  retention_in_days = 1
}

resource "aws_cloudwatch_log_group" "vulnerable" {
  name              = "/aws/eks/${local.name_prefix}-vulnerable/cluster"
  retention_in_days = 1
}

resource "aws_eks_cluster" "healthy" {
  name     = "${local.name_prefix}-healthy"
  role_arn = aws_iam_role.cluster.arn
  version  = var.healthy_cluster_version

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  vpc_config {
    subnet_ids              = local.public_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = [var.admin_cidr]
  }

  depends_on = [
    aws_cloudwatch_log_group.healthy,
    aws_iam_role_policy_attachment.cluster,
  ]
}

resource "aws_eks_cluster" "vulnerable" {
  name     = "${local.name_prefix}-vulnerable"
  role_arn = aws_iam_role.cluster.arn
  version  = var.vulnerable_cluster_version

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  vpc_config {
    subnet_ids              = local.public_subnet_ids
    endpoint_private_access = false
    endpoint_public_access  = true
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  depends_on = [
    aws_cloudwatch_log_group.vulnerable,
    aws_iam_role_policy_attachment.cluster,
  ]
}

resource "aws_iam_role" "mcp_read" {
  name = "${local.name_prefix}-mcp-read"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.operator_principal_arn }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "sts:RoleSessionName" = "bluearch-steward-eks-validation" }
      }
    }]
  })
}

resource "aws_iam_role_policy" "mcp_read" {
  name   = "steward-read-allowlist"
  role   = aws_iam_role.mcp_read.id
  policy = file("${path.module}/mcp-read-policy.json")
}

resource "aws_eks_access_entry" "healthy_mcp" {
  cluster_name      = aws_eks_cluster.healthy.name
  principal_arn     = aws_iam_role.mcp_read.arn
  kubernetes_groups = ["bluearch-steward-readers"]
  type              = "STANDARD"
}

resource "aws_eks_access_entry" "vulnerable_mcp" {
  cluster_name      = aws_eks_cluster.vulnerable.name
  principal_arn     = aws_iam_role.mcp_read.arn
  kubernetes_groups = ["bluearch-steward-readers"]
  type              = "STANDARD"
}

resource "aws_eks_node_group" "healthy" {
  cluster_name    = aws_eks_cluster.healthy.name
  node_group_name = "healthy-ng"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.public_subnet_ids
  version         = var.healthy_cluster_version
  release_version = var.healthy_ami_release_version
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }

  update_config { max_unavailable = 1 }
  depends_on = [aws_iam_role_policy_attachment.node]
}

resource "aws_eks_node_group" "vulnerable_primary" {
  cluster_name    = aws_eks_cluster.vulnerable.name
  node_group_name = "primary-ng"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.public_subnet_ids
  version         = var.vulnerable_cluster_version
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }

  update_config { max_unavailable = 1 }
  depends_on = [aws_iam_role_policy_attachment.node]
}

resource "aws_eks_node_group" "skew" {
  cluster_name    = aws_eks_cluster.vulnerable.name
  node_group_name = "skew-ng"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.public_subnet_ids
  version         = var.skew_nodegroup_version
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }

  update_config { max_unavailable = 1 }
  depends_on = [aws_iam_role_policy_attachment.node]
}

resource "aws_eks_node_group" "old_ami" {
  cluster_name    = aws_eks_cluster.vulnerable.name
  node_group_name = "old-ami-ng"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = local.public_subnet_ids
  version         = var.vulnerable_cluster_version
  release_version = var.old_ami_release_version
  ami_type        = "AL2023_x86_64_STANDARD"
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }

  update_config { max_unavailable = 1 }
  depends_on = [aws_iam_role_policy_attachment.node]
}

resource "aws_eks_addon" "healthy_coredns" {
  cluster_name                = aws_eks_cluster.healthy.name
  addon_name                  = "coredns"
  addon_version               = var.healthy_coredns_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.healthy]
}

resource "aws_eks_addon" "vulnerable_coredns" {
  cluster_name                = aws_eks_cluster.vulnerable.name
  addon_name                  = "coredns"
  addon_version               = var.vulnerable_coredns_version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.vulnerable_primary]
}

resource "aws_iam_role" "cloudwatch_observability" {
  name = "${local.name_prefix}-cloudwatch"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_observability" {
  role       = aws_iam_role.cloudwatch_observability.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_eks_addon" "vulnerable_pod_identity" {
  cluster_name                = aws_eks_cluster.vulnerable.name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.vulnerable_primary]
}

resource "aws_eks_addon" "healthy_pod_identity" {
  cluster_name                = aws_eks_cluster.healthy.name
  addon_name                  = "eks-pod-identity-agent"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  depends_on                  = [aws_eks_node_group.healthy]
}

resource "aws_eks_addon" "vulnerable_observability" {
  cluster_name                = aws_eks_cluster.vulnerable.name
  addon_name                  = "amazon-cloudwatch-observability"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  pod_identity_association {
    role_arn        = aws_iam_role.cloudwatch_observability.arn
    service_account = "cloudwatch-agent"
  }

  depends_on = [
    aws_eks_addon.vulnerable_pod_identity,
    aws_iam_role_policy_attachment.cloudwatch_observability,
  ]
}

resource "aws_eks_addon" "healthy_observability" {
  cluster_name                = aws_eks_cluster.healthy.name
  addon_name                  = "amazon-cloudwatch-observability"
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  pod_identity_association {
    role_arn        = aws_iam_role.cloudwatch_observability.arn
    service_account = "cloudwatch-agent"
  }

  depends_on = [
    aws_eks_addon.healthy_pod_identity,
    aws_iam_role_policy_attachment.cloudwatch_observability,
  ]
}

resource "aws_budgets_budget" "lab" {
  name         = "${local.name_prefix}-max"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = [format("user:bluearch.io/run-id$%s", var.run_id)]
  }
}
