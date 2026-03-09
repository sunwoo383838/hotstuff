variable "region" {
  description = "AWS 리전 (예: us-east-1, ap-northeast-2)"
  type        = string
}

variable "zone_allocations" {
  description = <<EOT
각 AZ별 인스턴스 개수 설정.
예: [
  { zone = "us-east-1a", count = 2 },
  { zone = "us-east-1b", count = 2 },
  { zone = "us-east-1c", count = 2 },
  { zone = "us-east-1d", count = 2 },
  { zone = "us-east-1f", count = 2 },
]
EOT
  type = list(object({
    zone  = string
    count = number
  }))
}

variable "ami" {
  description = "EC2 인스턴스에 사용할 AMI ID (예: Ubuntu 22.04 ARM64 등)"
  type        = string
}

variable "instance_type" {
  description = "EC2 인스턴스 타입 (예: c7g.large, c7g.xlarge 등)"
  type        = string
  default     = "c7g.large"
}

variable "disk_size_gb" {
  description = "루트 디스크 크기 (GB)"
  type        = number
  default     = 100
}

variable "use_spot_instances" {
  description = "Spot 인스턴스를 사용할지 여부"
  type        = bool
  default     = true
}

variable "spot_termination_action" {
  description = <<EOT
Spot 인스턴스 중단 시 동작:
- terminate
- stop
- hibernate
EOT
  type    = string
  default = "terminate"
}

variable "ssh_public_key" {
  description = <<EOT
EC2에 등록할 SSH public key 값.
예: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
EOT
  type = string
}

variable "ssh_key_name" {
  description = "AWS에 등록할 KeyPair 이름 (여러 리전에서 동일 이름 사용 가능)"
  type        = string
  default     = "hotstuff-benchmark"
}
