data "aws_ssm_parameter" "amazon_linux_2023_x86_64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_key_pair" "soc_admin" {
  key_name   = "${local.name_prefix}-admin"
  public_key = trimspace(file(pathexpand(var.admin_ssh_public_key_path)))

  tags = {
    Name = "${local.name_prefix}-admin-key"
  }
}

resource "aws_iam_role" "wireguard_ssm" {
  name = "${local.name_prefix}-wireguard-ssm"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-wireguard-ssm-role"
  }
}

resource "aws_iam_role_policy_attachment" "wireguard_ssm" {
  role       = aws_iam_role.wireguard_ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "wireguard" {
  name = "${local.name_prefix}-wireguard"
  role = aws_iam_role.wireguard_ssm.name
}

resource "aws_vpc_security_group_ingress_rule" "wireguard_ssh_from_management" {
  security_group_id = aws_security_group.wireguard_gateway.id
  description       = "Private SSH administration from the Management VLAN over WireGuard"
  cidr_ipv4         = var.local_management_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "wireguard_icmp_from_management" {
  security_group_id = aws_security_group.wireguard_gateway.id
  description       = "Private diagnostics from the Management VLAN over WireGuard"
  cidr_ipv4         = var.local_management_cidr
  from_port         = -1
  to_port           = -1
  ip_protocol       = "icmp"
}

resource "aws_instance" "wireguard_gateway" {
  ami                         = data.aws_ssm_parameter.amazon_linux_2023_x86_64.value
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.public_vpn.id
  private_ip                  = "10.50.10.10"
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.wireguard_gateway.id]
  source_dest_check           = false
  key_name                    = aws_key_pair.soc_admin.key_name
  iam_instance_profile        = aws_iam_instance_profile.wireguard.name
  user_data                   = file("${path.module}/templates/wireguard-bootstrap.sh")
  user_data_replace_on_change = true

  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted             = true
    delete_on_termination = true
    volume_type           = "gp3"
    volume_size           = 8
  }

  tags = {
    Name = "${local.name_prefix}-wireguard"
    Role = "wireguard-gateway"
  }

  depends_on = [
    aws_route.public_internet,
    aws_route_table_association.public_vpn,
    aws_iam_role_policy_attachment.wireguard_ssm,
  ]
}

resource "aws_eip" "wireguard" {
  domain = "vpc"

  tags = {
    Name = "${local.name_prefix}-wireguard-eip"
  }
}

resource "aws_eip_association" "wireguard" {
  allocation_id = aws_eip.wireguard.id
  instance_id   = aws_instance.wireguard_gateway.id
}

resource "aws_route" "private_app_to_local" {
  route_table_id         = aws_route_table.private_app.id
  destination_cidr_block = var.local_enterprise_cidr
  network_interface_id   = aws_instance.wireguard_gateway.primary_network_interface_id
}

resource "aws_instance" "private_app" {
  ami                         = data.aws_ssm_parameter.amazon_linux_2023_x86_64.value
  instance_type               = var.ec2_instance_type
  subnet_id                   = aws_subnet.private_app.id
  private_ip                  = "10.50.20.10"
  associate_public_ip_address = false
  vpc_security_group_ids      = [aws_security_group.private_app.id]
  key_name                    = aws_key_pair.soc_admin.key_name
  user_data                   = file("${path.module}/templates/private-app-bootstrap.sh")
  user_data_replace_on_change = true

  credit_specification {
    cpu_credits = "standard"
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted             = true
    delete_on_termination = true
    volume_type           = "gp3"
    volume_size           = 8
  }

  tags = {
    Name = "${local.name_prefix}-private-app"
    Role = "private-application"
  }
}
