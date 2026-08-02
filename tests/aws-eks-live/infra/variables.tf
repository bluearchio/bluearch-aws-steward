variable "aws_profile" {
  description = "Explicit sandbox AWS profile validated by preflight."
  type        = string
  default     = null
  nullable    = true
}

variable "region" {
  description = "Disposable lab region."
  type        = string
  default     = "us-east-1"
}

variable "run_id" {
  description = "Short unique identifier used in every resource name and tag."
  type        = string
}

variable "owner" {
  description = "Non-sensitive owner label used for cleanup."
  type        = string
  default     = "bluearch-steward-validation"
}

variable "expires_at" {
  description = "RFC3339 hard expiry no more than eight hours after preflight."
  type        = string
}

variable "admin_cidr" {
  description = "Explicit operator CIDR allowed to reach the healthy cluster endpoint."
  type        = string
}

variable "existing_vpc_id" {
  description = "Optional existing sandbox VPC used when the account cannot create another VPC."
  type        = string
  default     = null
  nullable    = true
}

variable "existing_public_subnet_ids" {
  description = "Two or more public subnets in distinct AZs belonging to existing_vpc_id."
  type        = list(string)
  default     = []
}

variable "broken_subnet_cidr" {
  description = "Dedicated temporary subnet CIDR with no default route for the degraded node group."
  type        = string
  default     = "10.73.32.0/24"
}

variable "broken_subnet_az" {
  description = "Availability Zone for the temporary isolated subnet."
  type        = string
  default     = null
  nullable    = true
}

variable "operator_principal_arn" {
  description = "Current sandbox principal allowed to assume the MCP read role."
  type        = string
}

variable "healthy_cluster_version" {
  type = string
}

variable "vulnerable_cluster_version" {
  type = string
}

variable "skew_nodegroup_version" {
  type = string
}

variable "vulnerable_coredns_version" {
  type = string
}

variable "healthy_coredns_version" {
  type = string
}

variable "healthy_ami_release_version" {
  type = string
}

variable "old_ami_release_version" {
  type = string
}

variable "node_instance_type" {
  type    = string
  default = "t3.medium"
}

variable "budget_limit_usd" {
  type    = number
  default = 30
}
