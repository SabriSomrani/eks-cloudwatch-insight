

# eks with Prometheus & Grafana Using Terraform

- this repository allows deploying amazon Cloudwatch Agent in EKS using Terraform     

# Technology

- [Amazon Elastic Kubernetes Service (Amazon EKS)](https://aws.amazon.com/eks/) is a managed container service to run and scale Kubernetes applications in the cloud or on-premises.
- [Terraform ](https://kubernetes.io/docs/tasks/tools/) is an infrastructure as code tool that lets you define both cloud and on-prem resources in human-readable configuration files that you can version, reuse, and share. You can then use a consistent workflow to provision and manage all of your infrastructure throughout its lifecycle

# Getting Started

Ensure that you have installed the following tools in your Mac or Linux or Windows Laptop before start working with this module and run Terraform Plan and Apply

1. [aws cli](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
2. [terraform](https://learn.hashicorp.com/tutorials/terraform/install-cli)
3. [kubectl](https://kubernetes.io/docs/tasks/tools/)

### Create AWS Profile 

Add the block below to your .aws/credentials file and change the profile_name, aws_access_key_id and aws_secret_access_key with yours.

```shell script
[you-profile-name]
aws_access_key_id = XXXXXXX
aws_secret_access_key = XXXXXXXXXXXXXXXXX
```

### Clone the repo

```shell script
git clone git@github.com:AWSAFT/cloudwatch-eks.git
```
 
### Go To example

```shell script
$ cd dev
```

### Run Terraform INIT
```shell script
$ terraform init
```

### Run Terraform PLAN

Verify the resources that will be created by this execution.

```shell script
$ terraform plan
```

### Finally, Terraform APPLY

Deploy your environment.

```shell script
$ terraform apply
```
