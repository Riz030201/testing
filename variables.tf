variable "tgw_flow_log_bucket_name" {
  description = "S3 bucket name for TGW flow logs"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "example"
}