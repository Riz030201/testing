# TGW Flow Logs Module

This Terraform module provisions:
- An AWS Transit Gateway (TGW)
- An S3 bucket for storing TGW flow logs
- IAM role and policy for TGW flow logs

## Usage

```hcl
module "tgw" {
  source                   = "github.com/your-org/tgw_flow_logs_module"
  name_prefix              = "my-tgw"
  tgw_flow_log_bucket_name = "my-tgw-flow-logs-bucket"
}
```