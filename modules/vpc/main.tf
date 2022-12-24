resource "aws_vpc" "main" {
  cidr_block = var.cidr_block
  tags = merge(
    var.tags,
    tomap({
      "Name"         = "${var.env}- Main VPC",
      "IsMutualized" = "True"
    })
  )

  enable_dns_support   = true
  enable_dns_hostnames = true
}

#Enable Internet acess for instances in public subnets.tf

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = merge(
    var.tags,
    tomap({
      "Name"         = "${var.env}- Main IGW",
      "IsMutualized" = "True"
    })
  )
}
# Elastic IP for the Nat Gateway
resource "aws_eip" "nat" {
  count = var.nat_gateway_count
  vpc   = true
  tags = merge(
    var.tags,
    tomap({
      "Name"         = "eip for ${var.env}- Main NGW",
      "IsMutualized" = "True"
    })
  )
}
# NAT Gateways
resource "aws_nat_gateway" "main" {
  allocation_id = element(aws_eip.nat.*.id, count.index)
  subnet_id     = element(aws_subnet.public_subnets.*.id, count.index)
  count         = var.nat_gateway_count

  tags = merge(
    var.tags,
    tomap({
      "Name"         = "${var.env}- NAT - ${element(var.availability_zones, count.index)}",
      "IsMutualized" = "True"
    })
  )
}
