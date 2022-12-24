output "vpc_id" {
  value = aws_vpc.main.id
}

output "vpc_cidr" {
  value = aws_vpc.main.cidr_block
}

output "public_subnets" {
  value = aws_subnet.public_subnets.*.id
}

output "public_cidrs" {
  value = aws_subnet.public_subnets.*.cidr_block
}

output "private_subnets" {
  value = aws_subnet.private_subnets.*.id
}

output "private_db_subnets" {
  value = aws_subnet.database_subnets.*.id
}

output "private_subnets_cidrs" {
  value = aws_subnet.private_subnets.*.cidr_block
}

output "private_db_cidrs" {
  value = aws_subnet.database_subnets.*.cidr_block
}