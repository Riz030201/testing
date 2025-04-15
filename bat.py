import boto3

# Configurable inputs
ACCOUNTS_AND_ROLES = [
    {"account_id": "541869889644", "role_name": "VAULT-AWSADMIN"},
    {"account_id": "123456789012", "role_name": "VAULT-AWSADMIN"},  # Add more accounts as needed
]

SECURITY_VPC_NAME = "dfs-secuse1-dev"
REGIONS = ["us-east-1", "us-west-2"]

def assume_role(account_id, role_name):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName='CrossAccountSession')
        credentials = response['Credentials']
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken'],
            'account_id': account_id
        }
    except Exception as e:
        print(f"ERROR: Unable to assume role for account {account_id}: {e}")
        return None

def find_security_vpc(ec2):
    response = ec2.describe_vpcs()
    for vpc in response['Vpcs']:
        for tag in vpc.get('Tags', []):
            if tag['Key'] == 'Name' and tag['Value'] == SECURITY_VPC_NAME:
                return vpc['VpcId']
    return None

def get_transit_gateway_for_vpc(ec2, vpc_id):
    response = ec2.describe_transit_gateway_attachments(
        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
    )
    attachments = response.get('TransitGatewayAttachments', [])
    if attachments:
        return attachments[0]['TransitGatewayId']
    return None

def get_attached_vpcs(ec2, tgw_id):
    attached_vpcs = []
    attachments = ec2.describe_transit_gateway_attachments(
        Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
    )['TransitGatewayAttachments']

    for att in attachments:
        if att['ResourceType'] == 'vpc' and att['State'] == 'available':
            vpc_id = att['ResourceId']
            vpc_info = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
            name_tag = next((tag['Value'] for tag in vpc_info.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
            cidrs = [block['CidrBlock'] for block in vpc_info['CidrBlockAssociationSet']]
            attached_vpcs.append({
                'VpcId': vpc_id,
                'VpcName': name_tag,
                'CidrBlocks': cidrs
            })
    return attached_vpcs

def main():
    for entry in ACCOUNTS_AND_ROLES:
        creds = assume_role(entry['account_id'], entry['role_name'])
        if not creds:
            continue

        boto_creds = {
            'aws_access_key_id': creds['aws_access_key_id'],
            'aws_secret_access_key': creds['aws_secret_access_key'],
            'aws_session_token': creds['aws_session_token']
        }

        for region in REGIONS:
            print(f"\nRegion: {region} | AWS Account: {entry['account_id']}")
            ec2 = boto3.client('ec2', region_name=region, **boto_creds)

            # Step 1: Find Security VPC
            security_vpc_id = find_security_vpc(ec2)
            if not security_vpc_id:
                print(f"Security VPC '{SECURITY_VPC_NAME}' not found in {region}")
                continue

            # Step 2: Get TGW attached to Security VPC
            tgw_id = get_transit_gateway_for_vpc(ec2, security_vpc_id)
            if not tgw_id:
                print(f"No Transit Gateway attached to Security VPC in {region}")
                continue

            # Step 3: Get all attached VPCs to TGW
            vpcs = get_attached_vpcs(ec2, tgw_id)
            print(f"VPCs attached to TGW ({tgw_id}):")
            for v in vpcs:
                print(f"  - Account: {entry['account_id']}, VPC ID: {v['VpcId']}, Name: {v['VpcName']}, CIDRs: {', '.join(v['CidrBlocks'])}")

if __name__ == "__main__":
    main()