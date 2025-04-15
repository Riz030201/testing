import boto3

SECURITY_ACCOUNT = {"account_id": "590782070138", "role_name": "VAULT-AWSADMIN"}
SECURITY_VPC_NAME = "dfs-secuse1-dev"

INSPECTION_ACCOUNTS = [
    {"account_id": "541869889644", "role_name": "VAULT-AWSADMIN"},
    {"account_id": "123456789012", "role_name": "VAULT-AWSADMIN"}
]

REGIONS = ["us-east-1", "us-west-2"]

def assume_role(account_id, role_name):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName='CrossAccountTGW')
        credentials = response['Credentials']
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken'],
            'account_id': account_id
        }
    except Exception as e:
        print(f"ERROR assuming role for account {account_id}: {e}")
        return None

def find_security_vpc_and_tgw_route_table(region, creds):
    ec2 = boto3.client('ec2', region_name=region, **creds)
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        for tag in vpc.get('Tags', []):
            if tag['Key'] == 'Name' and tag['Value'] == SECURITY_VPC_NAME:
                vpc_id = vpc['VpcId']
                attachments = ec2.describe_transit_gateway_attachments(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )['TransitGatewayAttachments']
                if not attachments:
                    return None, None, None
                tgw_id = attachments[0]['TransitGatewayId']
                rtb_id = attachments[0].get('Association', {}).get('TransitGatewayRouteTableId')
                if rtb_id:
                    return vpc_id, tgw_id, rtb_id
    return None, None, None

def get_vpc_ids_propagating_to_tgw(ec2, tgw_rtb_id):
    try:
        props = ec2.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId=tgw_rtb_id
        )['TransitGatewayRouteTablePropagations']
        return [p['ResourceId'] for p in props if p['ResourceType'] == 'vpc']
    except Exception as e:
        print(f"Error getting propagations: {e}")
        return []

def get_vpc_info_from_accounts(vpc_ids, region):
    results = []
    for acct in INSPECTION_ACCOUNTS:
        creds = assume_role(acct['account_id'], acct['role_name'])
        if not creds:
            continue
        boto_cross = {
            'aws_access_key_id': creds['aws_access_key_id'],
            'aws_secret_access_key': creds['aws_secret_access_key'],
            'aws_session_token': creds['aws_session_token']
        }
        ec2 = boto3.client('ec2', region_name=region, **boto_cross)
        for vpc_id in vpc_ids:
            try:
                vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
                for vpc in vpcs:
                    name_tag = next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                    cidrs = [block['CidrBlock'] for block in vpc['CidrBlockAssociationSet']]
                    results.append({
                        'VpcId': vpc['VpcId'],
                        'VpcName': name_tag,
                        'CidrBlocks': cidrs,
                        'AccountId': acct['account_id']
                    })
            except Exception:
                continue
    return results

def main():
    for region in REGIONS:
        print(f"=== Region: {region} ===")
        sec_creds = assume_role(SECURITY_ACCOUNT['account_id'], SECURITY_ACCOUNT['role_name'])
        if not sec_creds:
            continue
        boto_sec = {
            'aws_access_key_id': sec_creds['aws_access_key_id'],
            'aws_secret_access_key': sec_creds['aws_secret_access_key'],
            'aws_session_token': sec_creds['aws_session_token']
        }
        sec_vpc_id, tgw_id, tgw_rtb_id = find_security_vpc_and_tgw_route_table(region, boto_sec)
        if not tgw_rtb_id:
            print(f"Could not determine TGW Route Table in region {region}")
            continue

        ec2_sec = boto3.client('ec2', region_name=region, **boto_sec)
        vpc_ids = get_vpc_ids_propagating_to_tgw(ec2_sec, tgw_rtb_id)

        print(f"Found VPCs propagating to TGW RTB: {vpc_ids}")

        vpc_details = get_vpc_info_from_accounts(vpc_ids, region)
        for v in vpc_details:
            print(f"- Account: {v['AccountId']}, VPC ID: {v['VpcId']}, Name: {v['VpcName']}, CIDRs: {', '.join(v['CidrBlocks'])}")

if __name__ == "__main__":
    main()