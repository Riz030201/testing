import boto3

# --- Inputs: Replace RED values with your actual inputs ---
accounts = ['111111111111', '222222222222']  # RED: Cross-account IDs
role_name = 'MyCrossAccountRole'            # RED: IAM Role name to assume
regions = ['us-east-1', 'us-west-2']
tgw_route_table_id = 'tgw-rtb-xxxxxxxxxxxx' # RED: Your TGW route table ID

# Function to assume role in a given account
def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='CrossAccountTGWSession'
    )
    credentials = response['Credentials']
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

# Function to get VPC attachment info associated with a TGW route table
def list_vpcs_for_tgw_route_table(session, region):
    ec2 = session.client('ec2', region_name=region)
    vpcs = {}

    # Get all TGW attachments associated with the route table
    attachments = ec2.describe_transit_gateway_route_table_associations(
        TransitGatewayRouteTableId=tgw_route_table_id
    )['Associations']

    for assoc in attachments:
        tgw_attachment_id = assoc.get('TransitGatewayAttachmentId')
        if not tgw_attachment_id:
            continue

        # Describe TGW attachment to get VPC ID
        tgw_attachment = ec2.describe_transit_gateway_attachments(
            TransitGatewayAttachmentIds=[tgw_attachment_id]
        )['TransitGatewayAttachments'][0]

        if tgw_attachment['ResourceType'] != 'vpc':
            continue  # Skip non-VPC attachments

        vpc_id = tgw_attachment['ResourceId']

        # Get VPC CIDR and name
        vpc_data = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
        cidr = vpc_data['CidrBlock']

        name_tag = next(
            (tag['Value'] for tag in vpc_data.get('Tags', []) if tag['Key'] == 'Name'),
            'NoName'
        )

        vpcs[vpc_id] = {
            'CIDR': cidr,
            'Name': name_tag,
            'Region': region
        }

    return vpcs

# Main execution
for account_id in accounts:
    print(f"\n--- Account: {account_id} ---")
    session = assume_role(account_id, role_name)

    for region in regions:
        print(f"\nRegion: {region}")
        try:
            vpc_info = list_vpcs_for_tgw_route_table(session, region)
            if vpc_info:
                for vpc_id, info in vpc_info.items():
                    print(f"VPC ID: {vpc_id}, CIDR: {info['CIDR']}, Name: {info['Name']}, Region: {info['Region']}")
            else:
                print("No VPCs attached to this route table in this region.")
        except Exception as e:
            print(f"Error in region {region}: {e}")