# #######
# EKS IAM
# #######

variable "create_eks_cluster_role" {
  description = "whether to Create EKS Cluster Role"
  type        = string
  default     = true
}

variable "cluster_role_name" {
  description = "EKS Cluster Role Name if you want to create "
  type        = string
  default     = null
}

variable "create_eks_node_group_role" {
  description = "whether to Create EKS Cluster Role"
  type        = string
  default     = true
}

variable "nodes_role_name" {
  description = "EKS Cluster Role Name if you want to create "
  type        = string
  default     = null
}

# ########
# Key Pair
# ########

variable "create_key_pair" {
  description = "whether to create key pair"
  type        = bool
  default     = true
}

variable "key_name" {
  description = "Key Name Which Need to Node Group if 'create_key_pair' = true "
  type        = string
  default     = null
}

# ###########
# EKS Cluster
# ###########

variable "cluster_name" {
  description = "EKS Cluster Name"
  type        = string
}

variable "role_arn" {
  description = "Role arn which need to EKS Cluster"
  type        = string
  default     = null
}

variable "cluster_version" {
  description = "EKS Cluster version (version of kubernetes)"
  type        = string
  default     = null
}

variable "enabled_cluster_log_type" {
  description = "List of the desired control plane logging to enable"
  type        = list(string)
  default     = null
}

variable "kubernetes_service_ipv4_cidr" {
  description = "The CIDR block to assign Kubernetes service IP addresses from. If you don't specify a block, Kubernetes assigns addresses from either the 10.100.0.0/16 or 172.20.0.0/16 CIDR blocks. We recommend that you specify a block that does not overlap with resources in other networks that are peered or connected to your VPC"
  type        = string
  default     = null
}
variable "kubernetes_ip_family" {
  description = "The IP family used to assign Kubernetes pod and service addresses. Valid values are ipv4 (default) and ipv6"
  type        = string
  default     = "ipv4"
  validation {
    condition     = contains(["ipv4", "ipv6"], var.kubernetes_ip_family)
    error_message = "Kubernetes IP family must be one of the following (ipv4 | ipv6)."
  }
}

variable "cluster_additional_security_group_ids" {
  description = "List of additional, externally created security group IDs to attach to the cluster control plane"
  type        = list(string)
  default     = []
}

variable "subnet_ids" {
  description = "A list of subnet IDs where the EKS cluster (ENIs) will be provisioned along with the nodes/node groups. Node groups can be deployed within a different set of subnet IDs from within the node group configuration"
  type        = list(string)
}

variable "cluster_endpoint_private_access" {
  description = "Indicates whether or not the Amazon EKS private API server endpoint is enabled"
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access" {
  description = "Indicates whether or not the Amazon EKS public API server endpoint is enabled"
  type        = bool
  default     = true
}

variable "cluster_endpoint_public_access_cidrs" {
  description = "List of CIDR blocks which can access the Amazon EKS public API server endpoint"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# ##############
# EKS Node Group
# ##############

variable "node_group_name" {
  description = "EKS Node Group Name"
  type        = string
  default     = ""
}

variable "node_instance_type" {
  description = "EKS Node Group Instance Type"
  type        = list(string)
  default     = ["t3.medium"]
}

variable "node_role_arn" {
  description = "Role arn which need to EKS Cluster Node Group"
  type        = string
  default     = null
}

variable "scaling_config" {
  description = "EKS Node Group Scaling Config"
  type        = map(any)
}

variable "update_config" {
  description = "EKS Node Group Update Strategy"
  type        = map(any)
  default     = {}
}

variable "remote_access" {
  description = "EKS Node Group Remote Access"
  type = object({
    ec2_ssh_key               = string
    source_security_group_ids = list(string)
  })
  default = { "ec2_ssh_key" : "", "source_security_group_ids" : [""] }
}
variable "node_disk_size" {
  description = "Node Group Disk Size"
  type        = number
  default     = 20
}

variable "node_group_number" {
  description = "Number of Node Group"
  type        = number
  default     = 1
}

variable "node_ami_type" {
  description = "Type of Amazon Machine Image (AMI) associated with the EKS Node Group"
  type        = string
  default     = "AL2_x86_64"
  validation {
    condition     = contains(["AL2_x86_64", "AL2_x86_64_GPU", "AL2_ARM_64", "CUSTOM", "BOTTLEROCKET_ARM_64", "BOTTLEROCKET_x86_64"], var.node_ami_type)
    error_message = "Node Group ami type must be one of the following (AL2_x86_64 | AL2_x86_64_GPU | AL2_ARM_64 | CUSTOM | BOTTLEROCKET_ARM_64 | BOTTLEROCKET_x86_64)."
  }
}

variable "node_capacity_type" {
  description = " Type of capacity associated with the EKS Node Group. Valid values: ON_DEMAND, SPOT"
  type        = string
  default     = "ON_DEMAND"
  validation {
    condition     = contains(["ON_DEMAND", "SPOT"], var.node_capacity_type)
    error_message = "Node Group capacity type must be one of the following (ON_DEMAND | SPOT)."
  }
}


# ##########
# EKS Addon
# ##########

variable "create_addon" {
  description = "Whether to Create AWS OpenId Connect"
  type        = bool
  default     = false
}

variable "addon_name" {
  description = "Addon Name 'create_addon' true"
  type        = string
  default     = null
}

variable "addon_version" {
  description = "Addon Version 'create_addon' true "
  type        = string
  default     = null
}
variable "addon_resolve_conflicts" {
  description = "how to resolve parameter value conflicts when migrating an existing add-on to an Amazon EKS add-on or when applying version updates to the add-on"
  type        = string
  default     = null
}

variable "addon_preserve" {
  description = "indicates if you want to preserve the created resources when deleting the EKS add-on"
  type        = bool
  default     = null
}

variable "addon_service_account_role_arn" {
  description = " Amazon Resource Name (ARN) of an existing IAM role to bind to the add-on's service account. The role must be assigned the IAM permissions required by the add-on. If you don't specify an existing IAM role, then the add-on uses the permissions assigned to the node IAM role"
  type        = string
  default     = null
}

# ####
# Tags
# ####

variable "tags" {
  description = "Maps of tags to assign to Resources"
  type        = map(string)
  default     = {}
}