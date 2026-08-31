resource "aws_vpc" "soc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

resource "aws_internet_gateway" "soc" {
  vpc_id = aws_vpc.soc.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_subnet" "public_vpn" {
  vpc_id                  = aws_vpc.soc.id
  cidr_block              = var.public_vpn_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-public-vpn"
    Tier = "public-vpn"
  }
}

resource "aws_subnet" "private_app" {
  vpc_id                  = aws_vpc.soc.id
  cidr_block              = var.private_app_subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-private-app"
    Tier = "private-app"
  }
}

resource "aws_route_table" "public_vpn" {
  vpc_id = aws_vpc.soc.id

  tags = {
    Name = "${local.name_prefix}-public-vpn-rt"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public_vpn.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.soc.id
}

resource "aws_route_table_association" "public_vpn" {
  subnet_id      = aws_subnet.public_vpn.id
  route_table_id = aws_route_table.public_vpn.id
}

resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.soc.id

  tags = {
    Name = "${local.name_prefix}-private-app-rt"
  }
}

resource "aws_route_table_association" "private_app" {
  subnet_id      = aws_subnet.private_app.id
  route_table_id = aws_route_table.private_app.id
}

resource "aws_security_group" "wireguard_gateway" {
  name        = "${local.name_prefix}-wireguard-gateway"
  description = "WireGuard gateway; public ingress is restricted to the known local peer"
  vpc_id      = aws_vpc.soc.id

  ingress = []
  egress  = []

  tags = {
    Name = "${local.name_prefix}-wireguard-gateway-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "wireguard_from_local_peer" {
  security_group_id = aws_security_group.wireguard_gateway.id
  description       = "WireGuard transport from the current local public address"
  cidr_ipv4         = var.local_public_ip_cidr
  from_port         = 51820
  to_port           = 51820
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_egress_rule" "wireguard_egress" {
  security_group_id = aws_security_group.wireguard_gateway.id
  description       = "Temporary gateway egress; host nftables will enforce forwarded inner flows"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "private_app" {
  name        = "${local.name_prefix}-private-app"
  description = "Private application access from approved routed local VLANs only"
  vpc_id      = aws_vpc.soc.id

  ingress = []
  egress  = []

  tags = {
    Name = "${local.name_prefix}-private-app-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_https_from_users" {
  security_group_id = aws_security_group.private_app.id
  description       = "Approved User VLAN HTTPS"
  cidr_ipv4         = var.local_user_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_https_from_management" {
  security_group_id = aws_security_group.private_app.id
  description       = "Approved Management VLAN HTTPS"
  cidr_ipv4         = var.local_management_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_ssh_from_management" {
  security_group_id = aws_security_group.private_app.id
  description       = "Private SSH administration from the Management VLAN"
  cidr_ipv4         = var.local_management_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "app_icmp_from_management" {
  security_group_id = aws_security_group.private_app.id
  description       = "Private diagnostics from the Management VLAN"
  cidr_ipv4         = var.local_management_cidr
  from_port         = -1
  to_port           = -1
  ip_protocol       = "icmp"
}
