import boto3

# ----- REQUIRED INPUTS -----
accounts = ['111122223333', '444455556666']  # Replace with your AWS account IDs
regions = ['us-east-1', 'us-west-2']         # Replace with your target regions
role_name = 'YourCrossAccountRoleName'       # Replace with your role name
tgw_attachment_id = 'tgw-attach-xxxxxxxx'    # Replace with the TGW attachment ID
# ---------------------------

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='TGWAttachmentSession'
        )
        return response['Credentials']
    except Exception as e:
        print(f"[ERROR] Unable to assume role in account {account_id}: {e}")
        return None

def get_vpc_for_attachment(credentials, region, attachment_id):
    ec2_client = boto3.client(
        'ec2',
        region_name=region,
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    try:
        response = ec2_client.describe_transit_gateway_attachments(
            TransitGatewayAttachmentIds=[attachment_id]
        )
        attachments = response['TransitGatewayAttachments']

        for attach in attachments:
            if attach['ResourceType'] == 'vpc':
                vpc_id = attach['ResourceId']
                return vpc_id
    except Exception as e:
        print(f"[ERROR] Failed to fetch attachment in {region}: {e}")
        return None

def main():
    for account in accounts:
        credentials = assume_role(account, role_name)
        if not credentials:
            continue

        for region in regions:
            vpc_id = get_vpc_for_attachment(credentials, region, tgw_attachment_id)
            if vpc_id:
                print(f"[SUCCESS] Account: {account}, Region: {region}, VPC: {vpc_id}")
            else:
                print(f"[INFO] No VPC found for TGW attachment {tgw_attachment_id} in {account}/{region}")

if __name__ == "__main__":
    main()
    


⸻

What You Need to Update:
	•	Replace:
	•	'111122223333', '444455556666' with your actual AWS account IDs
	•	'YourCrossAccountRoleName' with the name of the IAM role to assume in each account
	•	'tgw-attach-xxxxxxxx' with your Transit Gateway attachment ID

⸻

Output:

The script will print VPC IDs associated with the specified TGW attachment across accounts and regions.
