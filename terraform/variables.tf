variable "aws_region" {
  description = "AWS Region used for the temporary hybrid lab."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "Single Availability Zone used to keep the MVP understandable and inexpensive."
  type        = string
  default     = "us-east-1a"
}

variable "project_name" {
  description = "Project identifier used in resource names and tags."
  type        = string
  default     = "ai-hybrid-network-soc-lab"
}

variable "environment" {
  description = "Environment identifier used in resource names and tags."
  type        = string
  default     = "lab"
}

variable "vpc_cidr" {
  description = "Non-overlapping AWS VPC address range."
  type        = string
  default     = "10.50.0.0/16"
}

variable "public_vpn_subnet_cidr" {
  description = "Public subnet reserved for the future WireGuard gateway."
  type        = string
  default     = "10.50.10.0/24"
}

variable "private_app_subnet_cidr" {
  description = "Private subnet reserved for the demo application."
  type        = string
  default     = "10.50.20.0/24"
}

variable "local_enterprise_cidr" {
  description = "Summary route for the local enterprise VLANs."
  type        = string
  default     = "10.10.0.0/16"
}

variable "local_user_cidr" {
  description = "Local User VLAN allowed to reach the future private application on HTTPS."
  type        = string
  default     = "10.10.10.0/24"
}

variable "local_management_cidr" {
  description = "Local Management VLAN allowed to administer approved AWS resources."
  type        = string
  default     = "10.10.30.0/24"
}

variable "local_public_ip_cidr" {
  description = "Current public IPv4 address of the local WireGuard peer in /32 notation."
  type        = string

  validation {
    condition = (
      can(cidrnetmask(var.local_public_ip_cidr)) &&
      try(tonumber(split("/", var.local_public_ip_cidr)[1]) == 32, false)
    )
    error_message = "local_public_ip_cidr must be one valid IPv4 host in /32 notation, for example 198.51.100.25/32."
  }
}

variable "ec2_instance_type" {
  description = "Free Tier-eligible EC2 instance type used by both lab hosts."
  type        = string
  default     = "t3.micro"

  validation {
    condition     = var.ec2_instance_type == "t3.micro"
    error_message = "This cost-controlled lab currently permits only t3.micro instances."
  }
}

variable "admin_ssh_public_key_path" {
  description = "Path on the Terraform runner to the administrator's SSH public key."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"

  validation {
    condition     = fileexists(pathexpand(var.admin_ssh_public_key_path))
    error_message = "admin_ssh_public_key_path must point to an existing SSH public key file."
  }
}
