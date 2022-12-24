module "vpc" {
  source             = "../modules/vpc"
  availability_zones = ["ca-central-1a", "ca-central-1b"]
  cidr_block         = "10.0.0.0/16"
  database_subnets   = ["10.0.4.0/24", "10.0.5.0/24"]
  env                = local.environment
  nat_gateway_count  = 1
  private_subnets    = ["10.0.2.0/24", "10.0.3.0/24"]
  public_subnets     = ["10.0.0.0/24", "10.0.1.0/24"]
  tags               = local.common_tags
}


module "eks_cluster" {
  source            = "../modules/eks"
  cluster_role_name = "eks-cluster-role"
  nodes_role_name   = "eks-node-role-name"

  # EKS cluster
  key_name        = "eks-node-group-key"
  cluster_name    = "eks-cluster"
  cluster_version = "1.24"
  subnet_ids      = module.vpc.private_subnets

  # EKS node group
  node_group_number  = 1
  node_group_name    = "eks-node-group"
  node_instance_type = ["t3.medium"]
  scaling_config = {
    desired_size = 2
    max_size     = 3
    min_size     = 2
  }
  update_config = {
    max_unavailable_percentage = 50 # Or Max_unavailable  ( only one of the two options)
  }
  remote_access = {
    ec2_ssh_key               = ""
    source_security_group_ids = [module.bastion.sg_id] # usually bastion security group will use

  }
}

module "bastion" {
  source              = "../modules/ec2"
  associate_public_ip = true
  desired_capacity    = 1
  enable_monitoring   = false
  env                 = "Dev"
  health_check_type   = "EC2"
  instance_type       = "t2.micro"
  max_size            = 1
  min_size            = 1
  name                = "${local.environment}-Bastion-host"
  subnets             = module.vpc.public_subnets
  tags                = local.common_tags
  vpc_id              = module.vpc.vpc_id
}

locals {
  common_tags = {
    created_by     = "SRE"
    Environment    = "Dev"
    CreationMethod = "Terraform"
    Project        = "PascalWealth"
  }
}

locals {
  environment = "Dev"
}
