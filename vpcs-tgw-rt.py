import boto3

def assume_role(account_id, role_name):
    """
    Assumes an IAM role in a different AWS account and returns a boto3 session.
    """
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::994653047345:role/rizwan-sts-role"
    try:
        response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="CrossAccountSession")
        credentials = response['Credentials']
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    except Exception as e:
        print(f"Error assuming role {role_name} in account {account_id}: {e}")
        raise

def get_vpc_details(session, region):
    """
    Retrieves details of VPCs attached to transit gateway route tables in a specific region.
    """
    ec2_client = session.client('ec2', region_name=region)
    ec2_resource = session.resource('ec2', region_name=region)
    tgw_client = session.client('ec2', region_name=region)

    try:
        # Get all transit gateway route tables
        tgw_route_tables = tgw_client.describe_transit_gateway_route_tables()['TransitGatewayRouteTables']
        vpc_details = []

        for tgw_route_table in tgw_route_tables:
            tgw_attachments = tgw_client.describe_transit_gateway_attachments(
                Filters=[{'Name': 'transit-gateway-id', 'Values': [tgw_route_table['TransitGatewayId']]}]
            )['TransitGatewayAttachments']

            for attachment in tgw_attachments:
                if attachment['ResourceType'] == 'vpc':
                    vpc_id = attachment['ResourceId']
                    try:
                        vpc = ec2_resource.Vpc(vpc_id)
                        if vpc.state == 'available':
                            vpc_name = next(
                                (tag['Value'] for tag in vpc.tags if tag['Key'] == 'Name'), 'Unnamed VPC'
                            )
                            vpc_details.append({
                                'VpcName': vpc_name,
                                'VpcId': vpc_id,
                                'CidrBlock': vpc.cidr_block,
                                'TgwAttachmentId': attachment['TransitGatewayAttachmentId'],
                                'TransitGatewayRouteTableId': tgw_route_table['TransitGatewayRouteTableId']
                            })
                    except Exception as e:
                        print(f"Error processing VPC {vpc_id}: {e}")
                        continue

        return vpc_details
    except Exception as e:
        print(f"Error fetching VPC details in region {region}: {e}")
        return []

def main():
    """
    Main function to assume a role and fetch VPC details for specified regions.
    """
    account_id = "YOUR_ACCOUNT_ID"  # Replace with your account ID
    role_name = "YOUR_ROLE_NAME"    # Replace with your role name
    regions = ['us-east-1', 'us-west-2', 'ap-south-1']  # Add or modify regions as needed

    try:
        session = assume_role(account_id, role_name)

        for region in regions:
            print(f"Fetching VPC details for region: {region}")
            vpc_details = get_vpc_details(session, region)
            if vpc_details:
                for vpc in vpc_details:
                    print(f"VPC Name: {vpc['VpcName']}, VPC ID: {vpc['VpcId']}, "
                          f"CIDR: {vpc['CidrBlock']}, TGW Attachment: {vpc['TgwAttachmentId']}, "
                          f"TGW Route Table ID: {vpc['TransitGatewayRouteTableId']}")
            else:
                print(f"No VPCs attached to transit gateway route tables in region {region}.")
    except Exception as e:
        print(f"Error in main execution: {e}")

if __name__ == "__main__":
    main()
