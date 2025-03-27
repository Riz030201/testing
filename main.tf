resource "aws_s3_bucket" "tgw_flow_logs" {
  bucket = var.tgw_flow_log_bucket_name
  force_destroy = true
}

resource "aws_iam_role" "tgw_flow_log_role" {
  name = "${var.name_prefix}-tgw-flow-log-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "tgw_flow_log_policy" {
  name = "tgw-flow-log-policy"
  role = aws_iam_role.tgw_flow_log_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "s3:PutObject"
      Resource = "${aws_s3_bucket.tgw_flow_logs.arn}/*"
    }]
  })
}

resource "aws_ec2_transit_gateway" "this" {
  description = "Example TGW with Flow Logs"
  amazon_side_asn = 64512
  auto_accept_shared_attachments = "enable"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"

  tags = {
    Name = "${var.name_prefix}-tgw"
  }
}

resource "aws_flow_log" "tgw_flow_logs" {
  log_destination      = aws_s3_bucket.tgw_flow_logs.arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  transit_gateway_id   = aws_ec2_transit_gateway.this.id
  iam_role_arn         = aws_iam_role.tgw_flow_log_role.arn
}