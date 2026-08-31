output "aws_region" {
  description = "AWS Region containing the lab."
  value       = var.aws_region
}

output "vpc_id" {
  description = "ID of the hybrid SOC lab VPC."
  value       = aws_vpc.soc.id
}

output "public_vpn_subnet_id" {
  description = "ID of the public subnet reserved for WireGuard."
  value       = aws_subnet.public_vpn.id
}

output "private_app_subnet_id" {
  description = "ID of the private application subnet."
  value       = aws_subnet.private_app.id
}

output "public_vpn_route_table_id" {
  description = "Route table ID for the public VPN subnet."
  value       = aws_route_table.public_vpn.id
}

output "private_app_route_table_id" {
  description = "Route table ID for the private application subnet."
  value       = aws_route_table.private_app.id
}

output "wireguard_security_group_id" {
  description = "Security group reserved for the future WireGuard gateway."
  value       = aws_security_group.wireguard_gateway.id
}

output "private_app_security_group_id" {
  description = "Security group reserved for the future private application."
  value       = aws_security_group.private_app.id
}
