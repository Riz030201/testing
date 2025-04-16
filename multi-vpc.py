import boto3

REGIONS = ["us-east-1", "us-west-2"]

# Security accounts and their Security VPC names
SECURITY_ACCOUNTS = [
    {
        "account_id": "590782070138",
        "role_name": "VAULT-AWSADMIN",
        "security_vpc_names": ["dfs-secuse1-dev", "dfs-secuse1-stage"]
    },
    {
        "account_id": "222222222222",
        "role_name": "VAULT-AWSADMIN",
        "security_vpc_names": ["dfs-secuse1-prod"]
    }
]

# Accounts where VPCs might be attached to the TGW
INSPECTION_ACCOUNTS = [
    {"account_id": "541869889644", "role_name": "VAULT-AWSADMIN"},
    {"account_id": "123456789012", "role_name": "VAULT-AWSADMIN"}
]

def assume_role(account_id, role_name):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        response = sts.assume_role(RoleArn=role_arn, RoleSessionName='CrossAccountTGW')
        creds = response['Credentials']
        return {
            'aws_access_key_id': creds['AccessKeyId'],
            'aws_secret_access_key': creds['SecretAccessKey'],
            'aws_session_token': creds['SessionToken'],
            'account_id': account_id
        }
    except Exception as e:
        print(f"Skipping account {account_id}: cannot assume role - {e}")
        return None

def find_tgw_rtb_from_vpc_name(ec2, vpc_name):
    vpcs = ec2.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        for tag in vpc.get('Tags', []):
            if tag['Key'] == 'Name' and tag['Value'] == vpc_name:
                vpc_id = vpc['VpcId']
                print(f"[DEBUG] Found VPC {vpc_name}: {vpc_id}")
                attachments = ec2.describe_transit_gateway_attachments(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )['TransitGatewayAttachments']
                if attachments:
                    tgw_id = attachments[0]['TransitGatewayId']
                    rtb_id = attachments[0].get('Association', {}).get('TransitGatewayRouteTableId')
                    print(f"[DEBUG] Found TGW: {tgw_id}, RTB: {rtb_id}")
                    return vpc_id, tgw_id, rtb_id
    return None, None, None

def get_propagating_vpc_ids(ec2, tgw_rtb_id):
    try:
        props = ec2.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId=tgw_rtb_id
        )['TransitGatewayRouteTablePropagations']
        return [p['ResourceId'] for p in props if p['ResourceType'] == 'vpc']
    except Exception as e:
        print(f"Error getting propagations for RTB {tgw_rtb_id}: {e}")
        return []

def describe_vpc_by_id(ec2, vpc_id):
    try:
        vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
        for vpc in vpcs:
            name = next((tag['Value'] for tag in vpc.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
            cidrs = [block['CidrBlock'] for block in vpc['CidrBlockAssociationSet']]
            return {"VpcId": vpc_id, "VpcName": name, "CidrBlocks": cidrs}
    except:
        return None

def main():
    for region in REGIONS:
        print(f"\n========== REGION: {region} ==========")

        for sec in SECURITY_ACCOUNTS:
            sec_creds = assume_role(sec['account_id'], sec['role_name'])
            if not sec_creds:
                continue

            boto_sec = {
                'aws_access_key_id': sec_creds['aws_access_key_id'],
                'aws_secret_access_key': sec_creds['aws_secret_access_key'],
                'aws_session_token': sec_creds['aws_session_token']
            }

            ec2_sec = boto3.client('ec2', region_name=region, **boto_sec)

            for vpc_name in sec['security_vpc_names']:
                print(f"\n[SECURITY VPC] Account: {sec['account_id']} | VPC: {vpc_name} | Region: {region}")
                vpc_id, tgw_id, rtb_id = find_tgw_rtb_from_vpc_name(ec2_sec, vpc_name)

                if not rtb_id:
                    print(f"Could not determine TGW RTB for {vpc_name} in region {region}")
                    continue

                vpc_ids = get_propagating_vpc_ids(ec2_sec, rtb_id)
                print(f"[DEBUG] VPCs propagating to RTB {rtb_id}: {vpc_ids}")

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

                    for vpc_id_check in vpc_ids:
                        vpc_info = describe_vpc_by_id(ec2, vpc_id_check)
                        if vpc_info:
                            print(f"- Account: {acct['account_id']}, VPC ID: {vpc_info['VpcId']}, Name: {vpc_info['VpcName']}, CIDRs: {', '.join(vpc_info['CidrBlocks'])}")

if __name__ == "__main__":
    main()