variable "vpc_id" {}
variable "env" {}
variable "instance_type" {}
variable "associate_public_ip" {}
variable "enable_monitoring" {}
variable "user_data" {
  default = ""
}
variable "name" {}
variable "min_size" {}
variable "desired_capacity" {}
variable "max_size" {}
variable "health_check_type" {}
variable "subnets" {}
variable "iam_instance_profile" {
  default = ""
}
variable "tags" { type = map(string) }