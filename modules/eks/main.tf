# ########
# EKS IAM
# ########

resource "aws_iam_role" "eks_role" {
  count = var.create_eks_cluster_role ? 1 : 0
  name  = var.cluster_role_name

  tags = var.tags

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  count      = var.create_eks_cluster_role ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_role[count.index].name
}

//resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
//  count      = var.create_eks_cluster_role ? 1 : 0
//  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
//  role       = aws_iam_role.eks_role[count.index].name
//}

# ##################
# EKS Node Group IAM
# ##################

resource "aws_iam_role" "eks_nodes_role" {
  count = var.create_eks_node_group_role ? 1 : 0
  name  = var.nodes_role_name

  tags               = var.tags
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
  count      = var.create_eks_node_group_role ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eks_nodes_role[count.index].name
}

resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
  count      = var.create_eks_node_group_role ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eks_nodes_role[count.index].name
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
  count      = var.create_eks_node_group_role ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eks_nodes_role[count.index].name
}

resource "aws_iam_role_policy_attachment" "CloudWatchAgentServerPolicy" {
  count      = var.create_eks_node_group_role ? 1 : 0
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.eks_nodes_role[count.index].name
}



######
# OIDC
######

data "tls_certificate" "tls_certificate" {
  url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}
resource "aws_iam_openid_connect_provider" "oidc" {
  url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer

  client_id_list = ["sts.amazonaws.com"]

  thumbprint_list = [data.tls_certificate.tls_certificate.certificates.0.sha1_fingerprint]

  tags = var.tags
}

data "aws_caller_identity" "current" {}




# ###########################################################
# Key pair generation (store it as SSM parameter and locally)
# ###########################################################

resource "tls_private_key" "generated" {
  count     = var.create_key_pair ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}
resource "aws_key_pair" "generated" {
  count      = var.create_key_pair ? 1 : 0
  key_name   = var.key_name
  depends_on = [tls_private_key.generated]
  public_key = tls_private_key.generated[count.index].public_key_openssh
}
resource "aws_ssm_parameter" "key_pair" {
  count     = var.create_key_pair ? 1 : 0
  name      = var.key_name
  value     = tls_private_key.generated[count.index].private_key_pem
  type      = "SecureString"
  overwrite = true
}

# ############
#  EKS Cluster
# ############

resource "aws_eks_cluster" "eks_cluster" {
  name                      = var.cluster_name
  role_arn                  = try(aws_iam_role.eks_role[0].arn, var.role_arn)
  enabled_cluster_log_types = var.enabled_cluster_log_type
  version                   = var.cluster_version


  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_private_access = var.cluster_endpoint_private_access
    endpoint_public_access  = var.cluster_endpoint_public_access
    public_access_cidrs     = var.cluster_endpoint_public_access_cidrs
    security_group_ids      = var.cluster_additional_security_group_ids
  }

  kubernetes_network_config {
    service_ipv4_cidr = var.kubernetes_service_ipv4_cidr
    ip_family         = var.kubernetes_ip_family
  }

  tags = merge(
    var.tags,
    tomap({
      "Name" = var.cluster_name
    })
  )
}


# ##############
# EKS Node Group
# ##############

resource "aws_eks_node_group" "node" {
  count           = var.node_group_number
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = var.node_group_name
  node_role_arn   = try(aws_iam_role.eks_nodes_role[0].arn, var.node_role_arn)
  subnet_ids      = var.subnet_ids
  instance_types  = var.node_instance_type
  version         = var.cluster_version
  ami_type        = var.node_ami_type
  capacity_type   = var.node_capacity_type
  disk_size       = var.node_disk_size


  scaling_config {
    desired_size = var.scaling_config.desired_size
    max_size     = var.scaling_config.max_size
    min_size     = var.scaling_config.min_size
  }


  update_config {
    max_unavailable            = lookup(var.update_config, "max_unavailable", null)
    max_unavailable_percentage = lookup(var.update_config, "max_unavailable_percentage", null)
  }

  remote_access {
    ec2_ssh_key               = try(aws_key_pair.generated[0].key_name, var.remote_access.ec2_ssh_key)
    source_security_group_ids = var.remote_access.source_security_group_ids
  }

  tags = merge(
    var.tags,
    tomap({
      "Name"                = var.node_group_name,
      "propagate_at_launch" = true
    })
  )

}


##################
# Cloudwatch Agent
##################

resource "aws_iam_role" "sa_role" {
  count = var.create_eks_node_group_role ? 1 : 0
  name  = "role-service-account"

  tags               = var.tags
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/${trim(aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer, "htpps://")}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${trim(aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer, "htpps://")}:sub": "sts.amazonaws.com",
          "${trim(aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer, "htpps://")}:aud": "system:serviceaccount:${kubernetes_namespace.ns.metadata[0].name}:${kubernetes_service_account.sa.metadata[0].name}"
        }
      }
    }
  ]
}
POLICY
}


resource "kubernetes_namespace" "ns" {
  metadata {
    labels = {
      name = "amazon-cloudwatch"
    }
    name = "amazon-cloudwatch"
  }
  //    depends_on = [aws_eks_node_group.node]
}

resource "kubernetes_service_account" "sa" {
  metadata {
    name      = "cloudwatch-agent"
    namespace = kubernetes_namespace.ns.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/role-service-account"
    }
  }

}

resource "kubernetes_cluster_role" "cr" {
  metadata {
    name = "cloudwatch-agent-role"
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "nodes", "endpoints"]
    verbs      = ["list", "watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["replicasets"]
    verbs      = ["list", "watch"]
  }
  rule {
    api_groups = ["batch"]
    resources  = ["jobs"]
    verbs      = ["list", "watch"]
  }
  rule {
    api_groups = [""]
    resources  = ["nodes/proxy"]
    verbs      = ["get"]
  }
  rule {
    api_groups = [""]
    resources  = ["nodes/stats", "configmaps", "events"]
    verbs      = ["create"]
  }
  rule {
    api_groups     = [""]
    resources      = ["configmaps"]
    resource_names = ["cwagent-clusterleader"]
    verbs          = ["get", "update"]
  }
}

resource "kubernetes_cluster_role_binding" "crb" {
  metadata {
    name = "cloudwatch-agent-role-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.cr.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.sa.metadata[0].name
    namespace = kubernetes_namespace.ns.metadata[0].name
  }
}
data "aws_region" "current" {}

data "template_file" "this" {
  template = file("${path.module}/templates/config.tpl")
  vars = {
    region_name  = data.aws_region.current.name
    cluster_name = aws_eks_cluster.eks_cluster.name
  }
}

resource "kubernetes_config_map" "cm" {
  metadata {
    name      = "cwagentconfig"
    namespace = kubernetes_namespace.ns.metadata[0].name
  }
  data = {
    "cwagentconfig.json" = data.template_file.this.rendered
  }

}

resource "kubernetes_daemonset" "this" {
  metadata {
    name      = "cloudwatch-agent"
    namespace = kubernetes_namespace.ns.metadata[0].name
  }

  spec {
    selector {
      match_labels = {
        name = "cloudwatch-agent"
      }
    }

    template {
      metadata {
        labels = {
          name = "cloudwatch-agent"
        }
      }
      spec {
        container {
          name  = "cloudwatch-agent"
          image = "amazon/cloudwatch-agent:1.247354.0b251981"
          port {
            container_port = 8125
            host_port      = 8125
            protocol       = "UDP"
          }
          resources {
            limits = {
              cpu    = "200m"
              memory = "200Mi"
            }
            requests = {
              cpu    = "200m"
              memory = "200Mi"
            }
          }
          env {
            name = "HOST_IP"
            value_from {
              field_ref {
                field_path = "status.hostIP"
              }
            }
          }
          env {
            name = "HOST_NAME"
            value_from {
              field_ref {
                field_path = "spec.nodeName"
              }
            }
          }
          env {
            name = "K8S_NAMESPACE"
            value_from {
              field_ref {
                field_path = "metadata.namespace"
              }
            }
          }
          env {
            name  = "CI_VERSION"
            value = "k8s/1.3.11"
          }
          volume_mount {
            mount_path = "/etc/cwagentconfig"
            name       = "cwagentconfig"
          }
          volume_mount {
            mount_path = "/rootfs"
            name       = "rootfs"
            read_only  = true
          }
          volume_mount {
            mount_path = "/var/run/docker.sock"
            name       = "dockersock"
            read_only  = true
          }
          volume_mount {
            mount_path = "/var/lib/docker"
            name       = "varlibdocker"
            read_only  = true
          }
          volume_mount {
            mount_path = "/run/containerd/containerd.sock"
            name       = "containerdsock"
            read_only  = true
          }
          volume_mount {
            mount_path = "/sys"
            name       = "sys"
            read_only  = true
          }
          volume_mount {
            mount_path = "/dev/disk"
            name       = "devdisk"
            read_only  = true
          }
        }
        volume {
          name = "cwagentconfig"
          config_map {
            name = kubernetes_config_map.cm.metadata[0].name
          }
        }
        volume {
          name = "rootfs"
          host_path {
            path = "/"
          }
        }
        volume {
          name = "dockersock"
          host_path {
            path = "/var/run/docker.sock"
          }
        }
        volume {
          name = "varlibdocker"
          host_path {
            path = "/var/lib/docker"
          }
        }
        volume {
          name = "containerdsock"
          host_path {
            path = "/run/containerd/containerd.sock"
          }
        }
        volume {
          name = "sys"
          host_path {
            path = "/sys"
          }
        }
        volume {
          name = "devdisk"
          host_path {
            path = "/dev/disk"
          }
        }
        termination_grace_period_seconds = 60
        service_account_name             = kubernetes_service_account.sa.metadata[0].name
      }
    }
  }
}

# #########
# EKS Addon
# #########

//resource "aws_eks_addon" "addon" {
//  count                    = var.create_addon ? 1 : 0
//  cluster_name             = aws_eks_cluster.eks_cluster.name
//  addon_name               = var.addon_name
//  addon_version            = var.addon_version
//  resolve_conflicts        = upper(var.addon_resolve_conflicts)
//  preserve                 = var.addon_preserve
//  service_account_role_arn = var.addon_service_account_role_arn
//
//  tags = merge(
//    var.tags,
//    tomap({
//      "Name" = var.addon_name
//    })
//  )
//}

//data "tls_certificate" "tls_cert" {
//  count = var.create_addon ? 1 : 0
//  url   = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
//}
//
//resource "aws_iam_openid_connect_provider" "oicp" {
//  count           = var.create_addon ? 1 : 0
//  client_id_list  = ["sts.amazonaws.com"]
//  thumbprint_list = [data.tls_certificate.tls_cert[count.index].certificates[0].sha1_fingerprint]
//  url             = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
//}
//
//data "aws_iam_policy_document" "assume_role_policy" {
//  count = var.create_addon ? 1 : 0
//  statement {
//    actions = ["sts:AssumeRoleWithWebIdentity"]
//    effect  = "Allow"
//
//    condition {
//      test     = "StringEquals"
//      variable = "${replace(aws_iam_openid_connect_provider.oicp[count.index].url, "https://", "")}:sub"
//      values   = ["system:serviceaccount:kube-system:aws-node"]
//    }
//
//    principals {
//      identifiers = [aws_iam_openid_connect_provider.oicp[count.index].arn]
//      type        = "Federated"
//    }
//  }
//}
//
//resource "aws_iam_role" "addon_role" {
//  count              = var.create_addon ? 1 : 0
//  assume_role_policy = data.aws_iam_policy_document.assume_role_policy[count.index].json
//  name               = "${var.addon_name}-addon-role"
//}
//
//resource "aws_iam_role_policy_attachment" "addon_policy" {
//  count      = var.create_addon ? 1 : 0
//  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
//  role       = aws_iam_role.addon_role[count.index].name
//}