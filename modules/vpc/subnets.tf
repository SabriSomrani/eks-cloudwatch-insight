resource "aws_subnet" "public_subnets" {
  count                   = length(var.availability_zones)
  cidr_block              = element(concat(var.public_subnets, [""]), count.index)
  vpc_id                  = aws_vpc.main.id
  availability_zone       = element(var.availability_zones, count.index)
  map_public_ip_on_launch = true

  tags = merge(
    var.tags,
    tomap({
      "Tier" = "Public",
      "Name" = "Public subnet - ${element(var.availability_zones, count.index)} for ${var.env}- Main VPC"
    })
  )
}

#Private subnets

resource "aws_subnet" "private_subnets" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnets[count.index]
  availability_zone       = element(var.availability_zones, count.index)
  map_public_ip_on_launch = false

  tags = merge(
    var.tags,
    tomap({
      "Tier" = "Private",
      "Name" = "Private subnet - ${element(var.availability_zones, count.index)} for ${var.env}- Main VPC"
    })
  )
}

resource "aws_subnet" "database_subnets" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.database_subnets[count.index]
  availability_zone       = element(var.availability_zones, count.index)
  map_public_ip_on_launch = false

  tags = merge(
    var.tags,
    tomap({
      "Tier" = "Internal",
      "Name" = "DB subnet - ${element(var.availability_zones, count.index)} for ${var.env}- Main VPC"
    })
  )
}