# This script lists only valid VPCs attached to multiple Transit Gateway Route Tables across specific regions using an STS role.

import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

ROLE_ARN = "arn:aws:iam::994653047345:role/rizwan-sts-role"
TRANSIT_GATEWAY_ROUTE_TABLE_IDS = [  # List of Transit Gateway Route Table IDs
    "tgw-rtb-003ce805f119b7ee5",
    "tgw-rtb-07968f2713f75ef88"  # Add more TGW Route Table IDs as needed
]
REGIONS = ["ap-south-1", "us-east-1"]  # Restrict to these regions

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

def list_valid_vpcs_attached_to_tgw_route_tables(credentials, regions, tgw_route_table_ids):
    """List only valid VPCs attached to multiple Transit Gateway Route Tables across specified regions."""
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    vpcs_by_tgw = {}

    for tgw_route_table_id in tgw_route_table_ids:
        print(f"\nProcessing Transit Gateway Route Table: {tgw_route_table_id}")
        vpcs_by_region = {}

        for region in regions:
            print(f"  Checking region: {region}")
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
                            vpc_id = attachment['ResourceId']

                            try:
                                # Fetch VPC details
                                vpc_details = ec2_client.describe_vpcs(VpcIds=[vpc_id])
                                for vpc in vpc_details['Vpcs']:
                                    cidr_block = vpc['CidrBlock']
                                    # Get the VPC name from tags if available
                                    vpc_name = next(
                                        (tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'),
                                        'N/A'
                                    )
                                    vpcs.append({'VpcId': vpc_id, 'CidrBlock': cidr_block, 'Name': vpc_name})
                            except ClientError as e:
                                if e.response['Error']['Code'] == 'InvalidVpcID.NotFound':
                                    print(f"    Skipping invalid VPC ID: {vpc_id} in region {region}")
                                else:
                                    print(f"    Error fetching details for VPC {vpc_id} in region {region}: {e}")

                vpcs_by_region[region] = vpcs
            except Exception as e:
                print(f"  Error in region {region}: {e}")
                vpcs_by_region[region] = []

        vpcs_by_tgw[tgw_route_table_id] = vpcs_by_region

    return vpcs_by_tgw

if __name__ == "__main__":
    # Assume the role
    credentials = assume_role(ROLE_ARN)
    if not credentials:
        print("Failed to assume role. Exiting.")
        exit(1)

    # Use only the specified regions
    regions = REGIONS

    # List valid VPCs attached to the specified Transit Gateway Route Tables across specified regions
    vpcs_by_tgw = list_valid_vpcs_attached_to_tgw_route_tables(credentials, regions, TRANSIT_GATEWAY_ROUTE_TABLE_IDS)

    # Print the results
    print("\nValid VPCs attached to the Transit Gateway Route Tables:")
    for tgw_route_table_id, vpcs_by_region in vpcs_by_tgw.items():
        print(f"\nTransit Gateway Route Table: {tgw_route_table_id}")
        for region, vpcs in vpcs_by_region.items():
            if vpcs:
                print(f"  Region {region}:")
                for vpc in vpcs:
                    print(f"    VPC ID: {vpc['VpcId']}, CIDR: {vpc['CidrBlock']}, Name: {vpc['Name']}")
            else:
                print(f"  Region {region} has no VPCs attached to the Transit Gateway Route Table.")
