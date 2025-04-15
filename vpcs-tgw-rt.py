import boto3

def assume_role(account_id, role_name):
    """
    Assumes an IAM role in a different AWS account and returns a boto3 session.
    """
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
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

def find_security_vpc(session, region, security_vpc_name):
    """
    Finds the Security VPC by its name in the specified region.
    """
    ec2_client = session.client('ec2', region_name=region)
    try:
        vpcs = ec2_client.describe_vpcs()['Vpcs']
        for vpc in vpcs:
            tags = vpc.get('Tags', [])
            for tag in tags:
                if tag['Key'] == 'Name' and tag['Value'] == security_vpc_name:
                    return vpc['VpcId']
        print(f"Security VPC '{security_vpc_name}' not found in region {region}.")
        return None
    except Exception as e:
        print(f"Error finding Security VPC in region {region}: {e}")
        return None

def list_vpcs_associated_with_security_vpc(session, region, security_vpc_id):
    """
    Lists all VPCs associated with the Security VPC via Transit Gateway attachments.
    """
    ec2_client = session.client('ec2', region_name=region)
    ec2_resource = session.resource('ec2', region_name=region)

    try:
        # Get all Transit Gateway attachments for the Security VPC
        tgw_attachments = ec2_client.describe_transit_gateway_attachments(
            Filters=[{'Name': 'resource-id', 'Values': [security_vpc_id]}]
        )['TransitGatewayAttachments']

        associated_vpcs = []

        for attachment in tgw_attachments:
            if attachment['ResourceType'] == 'vpc':
                tgw_attachment_id = attachment['TransitGatewayAttachmentId']
                associated_vpc_id = attachment['ResourceId']
                try:
                    vpc = ec2_resource.Vpc(associated_vpc_id)
                    if vpc.state == 'available':
                        vpc_name = next(
                            (tag['Value'] for tag in vpc.tags if tag['Key'] == 'Name'), 'Unnamed VPC'
                        )
                        associated_vpcs.append({
                            'VpcName': vpc_name,
                            'VpcId': associated_vpc_id,
                            'CidrBlock': vpc.cidr_block,
                            'TgwAttachmentId': tgw_attachment_id
                        })
                except Exception as e:
                    print(f"Error processing VPC {associated_vpc_id}: {e}")
                    continue

        return associated_vpcs
    except Exception as e:
        print(f"Error fetching associated VPCs for Security VPC {security_vpc_id} in region {region}: {e}")
        return []

def main():
    """
    Main function to assume roles across multiple accounts and list VPCs associated with the Security VPC.
    """
    accounts = ["ACCOUNT_ID_1", "ACCOUNT_ID_2"]  # Replace with your AWS account IDs
    role_name = "YOUR_ROLE_NAME"  # Replace with your IAM role name
    regions = ['us-east-1', 'us-west-2']  # Regions to inspect
    security_vpc_name = "security-vpc"  # Replace with the name of your Security VPC

    for account_id in accounts:
        print(f"Processing account: {account_id}")
        try:
            session = assume_role(account_id, role_name)

            for region in regions:
                print(f"Checking region: {region}")
                security_vpc_id = find_security_vpc(session, region, security_vpc_name)
                if security_vpc_id:
                    associated_vpcs = list_vpcs_associated_with_security_vpc(session, region, security_vpc_id)
                    if associated_vpcs:
                        print(f"VPCs associated with Security VPC '{security_vpc_name}' in region {region}:")
                        for vpc in associated_vpcs:
                            print(f"  VPC Name: {vpc['VpcName']}, VPC ID: {vpc['VpcId']}, "
                                  f"CIDR: {vpc['CidrBlock']}, TGW Attachment: {vpc['TgwAttachmentId']}")
                    else:
                        print(f"No VPCs associated with Security VPC '{security_vpc_name}' in region {region}.")
        except Exception as e:
            print(f"Error processing account {account_id}: {e}")

if __name__ == "__main__":
    main()
