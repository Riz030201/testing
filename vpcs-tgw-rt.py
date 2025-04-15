import boto3
from botocore.exceptions import ClientError

# Define the STS role and regions
ROLE_ARN = "arn:aws:iam::994653047345:role/rizwan-sts-role"
TRANSIT_GATEWAY_ATTACHMENT_IDS = [  # List of Transit Gateway Attachment IDs
    "tgw-attach-0123456789abcdef0",
    "tgw-attach-0abcdef1234567890"  # Add more TGW Attachment IDs as needed
]
REGIONS = ["us-east-1", "us-west-2", "ap-south-1"]  # Regions to query

def assume_role(role_arn):
    """Assume the specified role and return temporary credentials."""
    try:
        sts_client = boto3.client('sts')
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="TransitGatewayAttachmentInspectionSession"
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

def list_vpcs_by_tgw_attachment(credentials, regions, tgw_attachment_ids):
    """List VPC CIDRs and Transit Gateway Attachment IDs associated with Transit Gateway Attachments."""
    session = boto3.Session(
        aws_access_key_id=credentials['aws_access_key_id'],
        aws_secret_access_key=credentials['aws_secret_access_key'],
        aws_session_token=credentials['aws_session_token']
    )

    vpcs_by_attachment = {}

    for region in regions:
        print(f"\nChecking region: {region}")
        ec2_client = session.client('ec2', region_name=region)

        for attachment_id in tgw_attachment_ids:
            print(f"  Processing Transit Gateway Attachment: {attachment_id}")

            try:
                # Describe the Transit Gateway Attachment
                tgw_attachment = ec2_client.describe_transit_gateway_attachments(
                    TransitGatewayAttachmentIds=[attachment_id]
                )

                vpcs = []
                for attachment in tgw_attachment['TransitGatewayAttachments']:
                    if attachment['ResourceType'] == 'vpc':
                        vpc_id = attachment['ResourceId']

                        try:
                            # Fetch VPC details
                            vpc_details = ec2_client.describe_vpcs(VpcIds=[vpc_id])
                            for vpc in vpc_details['Vpcs']:
                                cidr_block = vpc['CidrBlock']
                                vpcs.append({
                                    'CidrBlock': cidr_block,
                                    'VpcId': vpc_id,
                                    'AttachmentId': attachment_id
                                })
                        except ClientError as e:
                            if e.response['Error']['Code'] == 'InvalidVpcID.NotFound':
                                print(f"    Skipping invalid VPC ID: {vpc_id} in region {region}")
                            else:
                                print(f"    Error fetching details for VPC {vpc_id} in region {region}: {e}")

                vpcs_by_attachment[attachment_id] = vpcs
            except Exception as e:
                print(f"  Error processing Transit Gateway Attachment {attachment_id} in region {region}: {e}")
                vpcs_by_attachment[attachment_id] = []

    return vpcs_by_attachment

if __name__ == "__main__":
    # Assume the role
    credentials = assume_role(ROLE_ARN)
    if not credentials:
        print("Failed to assume role. Exiting.")
        exit(1)

    # List VPCs attached to the specified Transit Gateway Attachments across specified regions
    vpcs_by_attachment = list_vpcs_by_tgw_attachment(credentials, REGIONS, TRANSIT_GATEWAY_ATTACHMENT_IDS)

    # Print the results
    print("\nVPC CIDRs and Transit Gateway Attachment IDs associated with the Transit Gateway Attachments:")
    for attachment_id, vpcs in vpcs_by_attachment.items():
        print(f"\nTransit Gateway Attachment: {attachment_id}")
        if vpcs:
            for vpc in vpcs:
                print(f"    CIDR: {vpc['CidrBlock']}, VPC ID: {vpc['VpcId']}")
        else:
            print(f"    No VPCs associated with this Transit Gateway Attachment.")
