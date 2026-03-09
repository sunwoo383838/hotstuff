output "instance_details" {
  description = "생성된 인스턴스 상세 정보 (Go 구조체 매핑용)"
  value = [
    for idx, instance in aws_instance.replica_nodes : {
      index       = idx
      name        = instance.tags["Name"]
      zone        = instance.availability_zone
      public_ip   = instance.public_ip
      internal_ip = instance.private_ip
    }
  ]
}

output "instance_public_ips" {
  description = "모든 인스턴스의 퍼블릭 IP 목록"
  value       = aws_instance.replica_nodes[*].public_ip
}

output "instance_internal_ips" {
  description = "모든 인스턴스의 프라이빗 IP 목록"
  value       = aws_instance.replica_nodes[*].private_ip
}

output "instance_zones" {
  description = "각 인스턴스가 위치한 AZ 목록"
  value       = aws_instance.replica_nodes[*].availability_zone
}

output "zone_distribution" {
  description = "zone_allocations 기반 AZ별 인스턴스 개수"
  value       = { for alloc in var.zone_allocations : alloc.zone => alloc.count }
}

output "total_instances" {
  description = "생성된 인스턴스 총 개수"
  value       = length(aws_instance.replica_nodes)
}
