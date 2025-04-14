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
# 04-14-2025
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

ROLE_ARN = "arn:aws:iam::994653047345:role/rizwan-sts-role"
TRANSIT_GATEWAY_ROUTE_TABLE_ID = "tgw-rtb-CHANGEME"  # Replace with your Transit Gateway Route Table ID

def assume_role(role_arn):
    """Assume the specified role and return temporary credentials."""
    try:
        sts_client = boto3.client('sts')
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="TransitGatewayRouteTableInspectionSession"
        )
        credentials = response['Credentials']
        print("Successfully assumed the role.")
        return credentials
    except Exception as e:
        print(f"Error assuming role: {e}")
        return None

def list_vpcs_attached_to_tgw_route_table(credentials, regions, tgw_route_table_id):
    """List VPCs attached to a specific Transit Gateway Route Table across multiple regions."""
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    vpcs_by_region = {}

    for region in regions:
        print(f"Checking region: {region}")
        ec2_client = session.client('ec2', region_name=region)

        try:
            # Describe Transit Gateway Route Table Associations
            tgw_associations = ec2_client.search_transit_gateway_routes(
                TransitGatewayRouteTableId=tgw_route_table_id,
                Filters=[{'Name': 'attachment.resource-type', 'Values': ['vpc']}]
            )

            vpcs = []
            for route in tgw_associations['Routes']:
                for attachment in route.get('TransitGatewayAttachments', []):
                    if attachment['ResourceType'] == 'vpc':
                        vpcs.append(attachment['ResourceId'])

            vpcs_by_region[region] = vpcs
        except Exception as e:
            print(f"Error in region {region}: {e}")
            vpcs_by_region[region] = []

    return vpcs_by_region

if __name__ == "__main__":
    # Assume the role
    credentials = assume_role(ROLE_ARN)
    if not credentials:
        print("Failed to assume role. Exiting.")
        exit(1)

    # List all available AWS regions
    session = boto3.Session()
    ec2_client = session.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    # List VPCs attached to the specified Transit Gateway Route Table across regions
    vpcs_by_region = list_vpcs_attached_to_tgw_route_table(credentials, regions, TRANSIT_GATEWAY_ROUTE_TABLE_ID)

    # Print the results
    for region, vpcs in vpcs_by_region.items():
        if vpcs:
            print(f"Region {region} has the following VPCs attached to the Transit Gateway Route Table: {vpcs}")
        else:
            print(f"Region {region} has no VPCs attached to the Transit Gateway Route Table.")
