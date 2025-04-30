terraform {
  required_version = "~> 1.9.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Optional cross-account role assumption
  assume_role {
    role_arn = var.assume_role_arn
  }
}

resource "aws_iam_role" "vpc_flow_logs_role" {
  name = "vpc-flow-logs-cross-account-role"

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

resource "aws_iam_policy" "vpc_flow_logs_policy" {
  name = "vpc-flow-logs-s3-write-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject"
      ]
      Resource = "${var.s3_bucket_arn}/AWSLogs/${var.source_account_id}/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_flow_logs_policy_attachment" {
  role       = aws_iam_role.vpc_flow_logs_role.name
  policy_arn = aws_iam_policy.vpc_flow_logs_policy.arn
}

resource "aws_flow_log" "vpc_flow_logs" {
  for_each = toset(var.vpc_ids)

  iam_role_arn         = aws_iam_role.vpc_flow_logs_role.arn
  log_destination      = var.s3_bucket_arn
  log_destination_type = "s3"
  resource_id          = each.value
  resource_type        = "VPC"
  traffic_type         = "ALL"

  tags = {
    Name = "FlowLog-${each.value}"
  }
}