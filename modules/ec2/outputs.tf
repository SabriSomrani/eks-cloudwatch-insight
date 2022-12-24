output "sg_id" {
  value = aws_security_group.sg.id
}
output "asg_name" {
  value = aws_autoscaling_group.asg.name
}