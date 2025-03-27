output "tgw_id" {
  value = aws_ec2_transit_gateway.this.id
}

output "flow_log_bucket_name" {
  value = aws_s3_bucket.tgw_flow_logs.bucket
}