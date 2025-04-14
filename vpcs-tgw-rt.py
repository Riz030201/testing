import boto3

# ----- REQUIRED INPUTS -----
accounts = ['111122223333', '444455556666']  # Replace with AWS account IDs
regions = ['us-east-1', 'us-west-2']         # Replace with desired AWS regions
role_name = 'YourCrossAccountRoleName'       # Replace with your IAM role name
tgw_route_table_id = 'tgw-rtb-xxxxxxxx'      # Replace with your Transit Gateway Route Table ID
# ---------------------------

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='TGWRouteTableSession'
        )
        return response['Credentials']
    except Exception as e:
        print(f"[ERROR] Failed to assume role in account {account_id}: {e}")
        return None

def get_vpcs_attached_to_route_table(credentials, region, tgw_route_table_id):
    ec2_client = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    vpc_ids = []

    try:
        # Get all attachments associated with the specified TGW route table
        response = ec2_client.search_transit_gateway_routes(
            TransitGatewayRouteTableId=tgw_route_table_id,
            Filters=[
                {'Name': 'type', 'Values': ['propagated', 'static']}
            ],
            MaxResults=100
        )

        attachments = response.get('Routes', [])
        attachment_ids = {r['TransitGatewayAttachments'][0]['TransitGatewayAttachmentId']
                          for r in attachments if r.get('TransitGatewayAttachments')}

        # Now map attachments back to VPCs
        if attachment_ids:
            describe_response = ec2_client.describe_transit_gateway_attachments(
                TransitGatewayAttachmentIds=list(attachment_ids)
            )
            for attachment in describe_response['TransitGatewayAttachments']:
                if attachment['ResourceType'] == 'vpc':
                    vpc_ids.append(attachment['ResourceId'])
    except Exception as e:
        print(f"[ERROR] Failed in {region}: {e}")

    return vpc_ids

def main():
    for account in accounts:
        credentials = assume_role(account, role_name)
        if not credentials:
            continue

        for region in regions:
            vpcs = get_vpcs_attached_to_route_table(credentials, region, tgw_route_table_id)
            if vpcs:
                for vpc_id in vpcs:
                    print(f"[FOUND] Account: {account}, Region: {region}, VPC: {vpc_id}")
            else:
                print(f"[INFO] No VPCs found in Account: {account}, Region: {region}")

if __name__ == "__main__":
    main()
    
What This Script Does:
	1.	Assumes a cross-account role using STS.
	2.	Searches the specified Transit Gateway Route Table.
	3.	Retrieves Transit Gateway Attachments associated with the route table.
	4.	Filters for VPC-type attachments.
	5.	Displays the VPC IDs that are linked to the TGW route table.