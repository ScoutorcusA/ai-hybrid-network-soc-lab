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

output "wireguard_instance_id" {
  description = "EC2 instance ID of the AWS WireGuard gateway."
  value       = aws_instance.wireguard_gateway.id
}

output "wireguard_public_ip" {
  description = "Stable public IPv4 endpoint used by the local WireGuard peer."
  value       = aws_eip.wireguard.public_ip
}

output "wireguard_private_ip" {
  description = "Private VPC address of the AWS WireGuard gateway."
  value       = aws_instance.wireguard_gateway.private_ip
}

output "private_app_instance_id" {
  description = "EC2 instance ID of the private demo application."
  value       = aws_instance.private_app.id
}

output "private_app_private_ip" {
  description = "Private VPC address of the demo application."
  value       = aws_instance.private_app.private_ip
}
