# ---------------------------------------------------------------------------------------------------------------------
# Key pair generation (store it as SSM parameter and locally)
# ---------------------------------------------------------------------------------------------------------------------
resource "tls_private_key" "generated" {
  algorithm = "RSA"
  rsa_bits  = 4096

}
resource "aws_key_pair" "generated" {
  key_name   = var.name
  depends_on = [tls_private_key.generated]
  public_key = tls_private_key.generated.public_key_openssh
}
resource "aws_ssm_parameter" "key_pair" {
  name      = "${var.name}_key_pair"
  value     = tls_private_key.generated.private_key_pem
  type      = "SecureString"
  overwrite = true
}

data "aws_ami" "instance_ami" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-2.*-x86_64-ebs"]
  }
}
# ---------------------------------------------------------------------------------------------------------------------
# Launch Template
# ---------------------------------------------------------------------------------------------------------------------

resource "aws_launch_template" "launch_template" {
  name_prefix   = var.name
  image_id      = data.aws_ami.instance_ami.id
  instance_type = var.instance_type
  key_name      = aws_key_pair.generated.key_name
  user_data     = base64encode(var.user_data)
  network_interfaces {
    associate_public_ip_address = var.associate_public_ip
    security_groups             = [aws_security_group.sg.id]
  }
  iam_instance_profile {
    name = var.iam_instance_profile
  }
  monitoring {
    enabled = var.enable_monitoring
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "asg" {
  name                = "${aws_launch_template.launch_template.name}-asg"
  min_size            = var.min_size
  desired_capacity    = var.desired_capacity
  max_size            = var.max_size
  health_check_type   = var.health_check_type
  vpc_zone_identifier = var.subnets
  launch_template {
    id      = aws_launch_template.launch_template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = var.name
    propagate_at_launch = true
  }
  # Required to redeploy without an outage.
  lifecycle {
    create_before_destroy = true
  }
}



resource "aws_security_group" "sg" {
  name_prefix = var.name
  description = "ecs instance security group"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
  tags = merge(
    var.tags,
    tomap({
      Name = "${var.name}_sg"
    })
  )
}

resource "aws_security_group_rule" "allow_all_outbound" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.sg.id
}