import boto3
from botocore.exceptions import ClientError

# Define the STS role and regions
ROLE_ARN = "arn:aws:iam::994653047345:role/rizwan-sts-role"
TRANSIT_GATEWAY_ROUTE_TABLE_IDS = [  # List of Transit Gateway Route Table IDs
    "tgw-rtb-003ce805f119b7ee5",
    "tgw-rtb-07968f2713f75ef88"  # Add more TGW Route Table IDs as needed
]
REGIONS = ["us-east-1", "us-west-2", "ap-south-1"]  # Regions to query

def assume_role(role_arn):
    """Assume the specified role and return temporary credentials."""
    try:
        sts_client = boto3.client('sts')
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="TransitGatewayInspectionSession"
        )
        credentials = response['Credentials']
        print("Successfully assumed the role.")
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken']
        }
    except ClientError as e:
        print(f"Error assuming role: {e}")
        return None

def list_vpcs_by_tgw_attachment(credentials, regions, tgw_route_table_ids):
    """List VPC CIDRs and Transit Gateway Attachment IDs associated with Transit Gateway Route Tables."""
    session = boto3.Session(
        aws_access_key_id=credentials['aws_access_key_id'],
        aws_secret_access_key=credentials['aws_secret_access_key'],
        aws_session_token=credentials['aws_session_token']
    )

    vpcs_by_tgw = {}

    for tgw_route_table_id in tgw_route_table_ids:
        print(f"\nProcessing Transit Gateway Route Table: {tgw_route_table_id}")
        vpcs_by_region = {}

        for region in regions:
            print(f"  Checking region: {region}")
            ec2_client = session.client('ec2', region_name=region)

            try:
                # Search for routes in the Transit Gateway Route Table
                tgw_routes = ec2_client.search_transit_gateway_routes(
                    TransitGatewayRouteTableId=tgw_route_table_id,
                    Filters=[{'Name': 'attachment.resource-type', 'Values': ['vpc']}]
                )

                vpcs = []
                for route in tgw_routes['Routes']:
                    for attachment in route.get('TransitGatewayAttachments', []):
                        if attachment['ResourceType'] == 'vpc':
                            attachment_id = attachment['TransitGatewayAttachmentId']
                            vpc_id = attachment['ResourceId']

                            try:
                                # Fetch VPC details
                                vpc_details = ec2_client.describe_vpcs(VpcIds=[vpc_id])
                                for vpc in vpc_details['Vpcs']:
                                    cidr_block = vpc['CidrBlock']
                                    vpcs.append({
                                        'CidrBlock': cidr_block,
                                        'AttachmentId': attachment_id
                                    })
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

    # List VPCs attached to the specified Transit Gateway Route Tables across specified regions
    vpcs_by_tgw = list_vpcs_by_tgw_attachment(credentials, REGIONS, TRANSIT_GATEWAY_ROUTE_TABLE_IDS)

    # Print the results
    print("\nVPC CIDRs and Transit Gateway Attachment IDs associated with the Transit Gateway Route Tables:")
    for tgw_route_table_id, vpcs_by_region in vpcs_by_tgw.items():
        print(f"\nTransit Gateway Route Table: {tgw_route_table_id}")
        for region, vpcs in vpcs_by_region.items():
            if vpcs:
                print(f"  Region {region}:")
                for vpc in vpcs:
                    print(f"    CIDR: {vpc['CidrBlock']}, Attachment ID: {vpc['AttachmentId']}")
            else:
                print(f"  Region {region} has no VPCs attached to the Transit Gateway Route Table.")
