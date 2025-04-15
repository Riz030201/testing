import boto3

# Step 1: Security VPC Account Info
SECURITY_ACCOUNT = {"account_id": "590782070138", "role_name": "VAULT-AWSADMIN"}
SECURITY_VPC_NAME = "dfs-secuse1-dev"

# Step 2: Other accounts to scan for attached VPCs
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
                print(f"[DEBUG] Found Security VPC ID: {vpc_id}")

                attachments = ec2.describe_transit_gateway_attachments(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )['TransitGatewayAttachments']

                print(f"[DEBUG] TGW Attachments: {attachments}")
                if not attachments:
                    return None, None, None

                tgw_id = attachments[0]['TransitGatewayId']
                print(f"[DEBUG] TGW ID: {tgw_id}")

                rtbs = ec2.describe_transit_gateway_route_tables(
                    Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_id]}]
                )['TransitGatewayRouteTables']

                print(f"[DEBUG] TGW Route Tables: {rtbs}")

                for rtb in rtbs:
                    rtb_id = rtb['TransitGatewayRouteTableId']
                    associations = ec2.get_transit_gateway_route_table_associations(
                        TransitGatewayRouteTableId=rtb_id
                    )['Associations']

                    print(f"[DEBUG] Checking RTB: {rtb_id}")
                    print(f"[DEBUG] Associations: {associations}")

                    for assoc in associations:
                        if assoc['ResourceId'] == vpc_id:
                            return vpc_id, tgw_id, rtb_id
    return None, None, None

def get_vpcs_propagating_to_tgw(ec2, tgw_rtb_id):
    vpcs = []
    try:
        props = ec2.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId=tgw_rtb_id
        )['TransitGatewayRouteTablePropagations']
    except Exception as e:
        print(f"Propagation error: {e}")
        return vpcs

    for p in props:
        if p['ResourceType'] == 'vpc' and p['State'] == 'enabled':
            vpc_id = p['ResourceId']
            try:
                vpc_info = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs'][0]
                name_tag = next((tag['Value'] for tag in vpc_info.get('Tags', []) if tag['Key'] == 'Name'), 'N/A')
                cidrs = [block['CidrBlock'] for block in vpc_info['CidrBlockAssociationSet']]
                vpcs.append({
                    'VpcId': vpc_id,
                    'VpcName': name_tag,
                    'CidrBlocks': cidrs
                })
            except Exception as vpc_err:
                print(f"Could not describe VPC {vpc_id}: {vpc_err}")
    return vpcs

def main():
    for region in REGIONS:
        print(f"\n=== Region: {region} ===")
        # Step 1: Assume Security VPC Account to get TGW Route Table
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
        print(f"Security VPC: {sec_vpc_id}, TGW: {tgw_id}, TGW RTB: {tgw_rtb_id}")

        # Step 2: Loop through other accounts and find VPCs propagating to same TGW RTB
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
            vpcs = get_vpcs_propagating_to_tgw(ec2, tgw_rtb_id)
            if not vpcs:
                print(f"No VPCs propagating to TGW RTB from account {acct['account_id']}")
                continue
            for v in vpcs:
                print(f"  - Account: {acct['account_id']}, VPC ID: {v['VpcId']}, Name: {v['VpcName']}, CIDRs: {', '.join(v['CidrBlocks'])}")

if __name__ == "__main__":
    main()