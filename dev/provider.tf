#terraform {
#  required_version = ">= 1.0"
#
#  required_providers {
#    aws = "~>4.0"
#  }
#}

provider "aws" {
  region  = "ca-central-1"
  profile = "dev"
}

data "aws_eks_cluster_auth" "cluster_auth" {
  name = module.eks_cluster.cluster_name
}

provider "kubernetes" {
  host                   = module.eks_cluster.eks_cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_cluster.certificate_authority)
  token                  = data.aws_eks_cluster_auth.cluster_auth.token
}


//provider "helm" {
//  kubernetes {
//    host                   = module.eks_cluster.eks_cluster_endpoint
//    cluster_ca_certificate = base64decode(module.eks_cluster.certificate_authority)
//    token                  = data.aws_eks_cluster_auth.cluster_auth.token
//  }
//}