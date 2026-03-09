terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

#####################################
# Provider
#####################################

provider "aws" {
  region = var.region
}

#####################################
# 공통 리소스 (ID)
#####################################

resource "random_id" "id" {
  byte_length = 4
}

#####################################
# SSH KeyPair (외부에서 받은 public key로 생성)
#####################################

resource "aws_key_pair" "experiment_key" {
  key_name   = var.ssh_key_name
  public_key = var.ssh_public_key
}

#####################################
# 기본 VPC
#####################################

data "aws_vpc" "default" {
  default = true
}

#####################################
# Security Group (Firewall 역할)
#####################################

resource "aws_security_group" "hotstuff" {
  name        = "hotstuff-${random_id.id.hex}"
  description = "Hotstuff benchmark security group"
  vpc_id      = data.aws_vpc.default.id

  # SSH
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"          # -1 = all protocols
    cidr_blocks = ["0.0.0.0/0"] # 모든 IPv4
  }

  # outbound 모두 허용
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name      = "hotstuff-${random_id.id.hex}"
    Benchmark = "hotstuff"
  }
}

#####################################
# zone_allocations 전개
# [{zone="us-east-1a", count=2}] -> ["us-east-1a","us-east-1a"]
#####################################

locals {
  zones = flatten([
    for alloc in var.zone_allocations : [
      for i in range(alloc.count) : alloc.zone
    ]
  ])
}

#####################################
# EC2 인스턴스 생성
#####################################

resource "aws_instance" "replica_nodes" {
  count = length(local.zones)

  ami               = var.ami
  instance_type     = var.instance_type
  availability_zone = local.zones[count.index]

  associate_public_ip_address = true
  key_name                    = aws_key_pair.experiment_key.key_name
  vpc_security_group_ids      = [aws_security_group.hotstuff.id]

  # Spot 인스턴스 설정 (옵션)
  dynamic "instance_market_options" {
    for_each = var.use_spot_instances ? [1] : []
    content {
      market_type = "spot"

      spot_options {
        instance_interruption_behavior = var.spot_termination_action
      }
    }
  }

  root_block_device {
    volume_size = var.disk_size_gb
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y curl wget git
  EOF

  tags = {
    Name      = "hotstuff-replica-${count.index}-${random_id.id.hex}"
    Benchmark = "hotstuff"
  }
}
