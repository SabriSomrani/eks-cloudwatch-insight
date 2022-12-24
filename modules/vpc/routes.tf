# Route the public subnet traffic through the internet gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    tomap({
      "Name"         = "Public route table for ${var.env}- Main VPC",
      "IsMutualized" = "True"
    })
  )
}

resource "aws_route" "public_internet_gateway" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_route_table_association" "public" {
  count = length(var.availability_zones)

  subnet_id      = element(aws_subnet.public_subnets.*.id, count.index)
  route_table_id = aws_route_table.public.id
}

# Route the private subnets no local traffic to the internet through the NAT Gateway
resource "aws_route_table" "private" {
  count = length(var.availability_zones)

  vpc_id = aws_vpc.main.id

  tags = merge(
    var.tags,
    tomap({
      "Name"         = "Private route table - ${element(var.availability_zones, count.index)} for ${var.env}- Main VPC",
      "IsMutualized" = "True"
    })
  )
}
resource "aws_route" "nat_gateway" {
  count = length(var.availability_zones)

  route_table_id         = element(aws_route_table.private.*.id, count.index)
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = element(aws_nat_gateway.main.*.id, count.index)
}
resource "aws_route_table_association" "private" {
  count = length(var.availability_zones)

  route_table_id = element(aws_route_table.private.*.id, count.index)
  subnet_id      = element(aws_subnet.private_subnets.*.id, count.index)
}