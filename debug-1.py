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
                rtb_id = attachments[0].get('Association', {}).get('TransitGatewayRouteTableId')

                print(f"[DEBUG] TGW ID: {tgw_id}")
                print(f"[DEBUG] Route Table ID from Attachment Association: {rtb_id}")

                if rtb_id:
                    return vpc_id, tgw_id, rtb_id
    return None, None, None