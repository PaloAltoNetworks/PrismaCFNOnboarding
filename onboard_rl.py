import boto3
import os
import uuid
import time
import json
import logging
import botocore
from botocore.exceptions import ClientError
from botocore.vendored import requests
import json
import logging
import signal
from urllib.request import build_opener, HTTPHandler, Request

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

from time import sleep


iamRole=None
flowLogsPermPolicy=None
multitrails = {}
multiAlltrails = {}

iamClient   = boto3.client   ( 'iam')
ec2Client   = boto3.client   ( 'ec2')
ctClient    = boto3.client   ( 'cloudtrail')
account_id = boto3.client('sts').get_caller_identity().get('Account')

globalVars = {}
globalVars['tagName']               = "Prisma-flowlogs"
globalVars['Log-GroupName']         = "Prisma-flowlogs"
globalVars['IAM-RoleName']          = "Prisma-VPC-flowlogs-role"
globalVars['regions']               = [region['RegionName'] for region in ec2Client.describe_regions()['Regions']]
globalVars['username']              = os.environ["PRISMA_USER_NAME"]
globalVars['password']              = os.environ["PRISMA_PASSWORD"]
globalVars['customerName']          = os.environ["PRISMA_CUSTOMER_NAME"]
globalVars['accountname']           = os.environ["PRISMA_ACCOUNT_NAME"]
globalVars['accountgroupid']        = os.environ["PRISMA_ACCOUNT_GROUP"]
globalVars['createacct']            = os.environ["PRISMA_ACCOUNT"]

if os.environ["PRISMA_TENANT"]=="app":
  tenant="api"
elif os.environ["PRISMA_TENANT"]=="app2":
  tenant="api2"
elif os.environ["PRISMA_TENANT"]=="app3":
  tenant="api3"
elif os.environ["PRISMA_TENANT"]=="app.eu":
  tenant="api.eu"
elif os.environ["PRISMA_TENANT"]=="app.anz":
  tenant="api.anz"
enablevpc = os.environ["PRISMA_VPC"]
enablecloudtrail = os.environ["PRISMA_CLOUDTRAIL"]
ExternalID = os.environ["EXTERNAL_ID"]
rolename = os.environ["ROLE_NAME"]
### Create IAM Role
flowLogsTrustPolicy = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
"""

flowLogsPermissions = """{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}"""


S3BucketPolicy ="""{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::redlocktrails3-%s"
        },
        {
            "Sid": "AWSCloudTrailWrite20150319",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::redlocktrails3-%s/AWSLogs/%s/*",
            "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
        }
    ]
}""" % (account_id, account_id, account_id)


def start(globalVars):
    logging.basicConfig(
        #filename='onboarding.log',
        format='%(asctime)s %(message)s',
        level=logging.INFO
    )
    account_information = create_account_information(globalVars['accountname'])
    LOGGER.info(account_information)
    response = register_account_with_redlock(globalVars, account_information)
    if enablevpc =="true":
      setupvpc(globalVars)
    return

def setupvpc(globalVars):
  create_iam()
  print((globalVars['regions']))
  for region in globalVars['regions']:
    print("Processing region ", region)
    createCloudwatchLog(region)
    vpcs = get_vpc_list(region)
    print("VPCS for region named", region, vpcs)

def create_account_information(account_name):
    external_id = ExternalID
    account_id = boto3.client('sts').get_caller_identity().get('Account')
    arn = "arn:aws:iam::"+ account_id + ":role/" + rolename
    account_information = {
        'name': account_name,
        'external_id': external_id,
        'account_id': account_id,
        'arn': arn
    }
    return account_information

def get_auth_token(globalVars):
    url = "https://%s.prismacloud.io/login" % (tenant)
    headers = {'Content-Type': 'application/json'}
    payload = {
        "username": globalVars['username'],
        "password": globalVars['password'],
        "customerName": globalVars['customerName']
    }
    payload = json.dumps(payload)
    response = requests.request("POST", url, headers=headers, data=payload)
    token = response.json()['token']
    return token

def call_redlock_api(auth_token, action, endpoint, payload, globalVars):
    url = "https://%s.prismacloud.io/" % tenant + endpoint
    headers = {'Content-Type': 'application/json', 'x-redlock-auth': auth_token}
    payload = json.dumps(payload)
    LOGGER.info(payload)
    response = requests.request(action, url, headers=headers, data=payload)
    return response

def register_account_with_redlock(globalVars, account_information):
    token = get_auth_token(globalVars)
    LOGGER.info('In register_account_with_redlock')
    LOGGER.info(token)
    payload = {
        "accountId": account_information['account_id'],
        "enabled": True,
        "externalId": account_information['external_id'],
        "groupIds": [ globalVars['accountgroupid']],
        "name": account_information['name'],
        "roleArn": account_information['arn']
    }
    if globalVars['createacct'] == "true":
       logging.info("Adding account to Prisma")
       response = call_redlock_api(token, 'POST', 'cloud/aws', payload, globalVars)
       logging.info("Account: " + account_information['name'] + " has been on-boarded to Prisma.")
       LOGGER.info(response)
    else:
       logging.info("Updating account in Prisma")
       endpoint = 'cloud/aws/' + account_information['account_id']
       response = call_redlock_api(token,'PUT', endpoint, payload, globalVars)
    return response

def create_trail():
    print("creating S3Bucket for CloudTrail")
    s3Client    = session.client   ( 's3')
    try:
      if session.region_name == 'us-east-1':
        response = s3Client.create_bucket(
          ACL="private",
          Bucket=("redlocktrails-%s" % account_id)
        )
      else:
        response = s3Client.create_bucket(
          ACL="private",
          Bucket=("redlocktrails-%s" % account_id),
          CreateBucketConfiguration={'LocationConstraint': session.region_name}
        )

    except ClientError as e:
      if e.response['Error']['Code'] == 'BucketAlreadyExists' or e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou' :
        print('Bucket Already Exists... Continuing')
      else:
        print((e.response))

    response = s3Client.put_bucket_policy(
      Bucket=("redlocktrails-%s" % account_id),
      Policy=S3BucketPolicy,
    )

    print("creating CloudTrail")
    try:
      response = ctClient.create_trail(
        Name="RedlockTrail",
        S3BucketName=("redlocktrails-%s" % account_id),
        IsOrganizationTrail=False,
        IsMultiRegionTrail=True,
        IncludeGlobalServiceEvents=True
        )
    except ClientError as e:
      if e.response['Error']['Code'] == 'TrailAlreadyExistsException':
        print('Trail Already Exists... Continuing')
      else:
        print((e.response))



def is_cloudtrail_enabledd():
  ctenabled=False
  response = ctClient.describe_trails()
  if len(response['trailList']) != 0:
    for each in response['trailList']:
      if each['IsMultiRegionTrail']==True:
        multitrails.update({each['Name']: each['HomeRegion']})
    for each in multitrails:
        regionclient  = boto3.client   ( 'cloudtrail', region_name=multitrails[each])
        selectors = regionclient.get_event_selectors(
            TrailName=each
            )
        if selectors['EventSelectors'][0]['ReadWriteType'] == "All":
          ctenabled=True
          break
  else:
    create_trail()
    ctenabled=True

  if ctenabled==False:
    create_trail()

def create_iam():
  try:
    global iamRole
    iamRole = iamClient.create_role( RoleName = globalVars['IAM-RoleName'] ,
                                     AssumeRolePolicyDocument = flowLogsTrustPolicy
                                    )
    print('Created IAM Role')

  except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
      print('Role Already Exists...')
      iamRole = {
          'Role': {
              'Arn': 'arn:aws:iam::%s:role/%s' % (account_id, globalVars['IAM-RoleName'])
          }
      }


  #### Attach permissions to the role
  try:
    global flowLogsPermPolicy
    flowLogsPermPolicy = iamClient.create_policy( PolicyName    = "flowLogsPermissions",
                                                  PolicyDocument= flowLogsPermissions,
                                                  Description   = 'Provides permissions to publish flow logs to the specified log group in CloudWatch Logs'
                                                )
    print('Created IAM Policy')

  except ClientError as e:
    if e.response['Error']['Code'] == 'EntityAlreadyExists':
      print('Policy Already Exists...Continuing')
      flowLogsPermPolicy = {
          'Policy': {
              'Arn': 'arn:aws:iam::%s:policy/flowLogsPermissions' % account_id
          }
      }
      print(flowLogsPermPolicy)




  try:
    sleep(1)
    print((globalVars['IAM-RoleName']))
    response = iamClient.attach_role_policy( RoleName = globalVars['IAM-RoleName'] ,
                                             PolicyArn= flowLogsPermPolicy['Policy']['Arn']
                                            )
    print('Attached IAM Policy')


  except ClientError as e:
    print('Unexpected error')
    print(e)

  sleep(10)


def createCloudwatchLog(region):
  try:
    logsClient  = boto3.client   ( 'logs', region_name = region )
    logGroup = logsClient.create_log_group( logGroupName = globalVars['Log-GroupName'],
                                          tags = {'Key': globalVars['tagName'] , 'Value':'Flow-Logs'}
                                          )
    print(('Created CloudWatchLog in %s' % region))

  except logsClient.exceptions.ResourceAlreadyExistsException as e:
   print("LogGroup already exists for ", region)
   pass

def createflowlog(region,vpc):
  ec2Client   = boto3.client   ( 'ec2', region_name = region )
  try:
    nwFlowLogs = ec2Client.create_flow_logs( ResourceIds              = [vpc, ],
                                           ResourceType             = 'VPC',
                                           TrafficType              = 'ALL',
                                           LogGroupName             = globalVars['Log-GroupName'],
                                           DeliverLogsPermissionArn = iamRole['Role']['Arn']
                                          )
    print(('Created FlowLog in %s' % region))
  except ClientError as e:
    print(e)






def is_flow_logs_enabled(region,vpc):
  try:
    vpc_id=vpc
    ec2Client   = boto3.client   ( 'ec2', region_name = region )
    response = ec2Client.describe_flow_logs(
        Filter=[
            {
                'Name': 'resource-id',
                'Values': [
                    vpc_id,
                ]
            },
        ],
    )
    if len(response['FlowLogs']) != 0 and response['FlowLogs'][0]['LogDestinationType']=='cloud-watch-logs': return True
  except ClientError as e:
    raise(e)
    print(e)




def get_vpc_list(region):
  vpcs = []
  ec2 = boto3.resource('ec2', region_name=region)
  vpcarray = list(ec2.vpcs.filter())
  print('VPC Array')
  print(vpcarray)
  if not vpcarray:
    pass
  else:
    for each in vpcarray:
      print(each.vpc_id)
      if is_flow_logs_enabled(region,each.vpc_id):
        print(("Flowlog exists for %s" % each.vpc_id))
      else:
        print("No flowlog found for", each.vpc_id, "creating")
        createflowlog(region,each.vpc_id)

def send_response(event, context, response_status, response_data):
    '''Send a resource manipulation status response to CloudFormation'''
    response_body = json.dumps({
        "Status": response_status,
        "Reason": "See the details in CloudWatch Log Stream: " + context.log_stream_name,
        "PhysicalResourceId": context.log_stream_name,
        "StackId": event['StackId'],
        "RequestId": event['RequestId'],
        "LogicalResourceId": event['LogicalResourceId'],
        "Data": response_data
    })

    LOGGER.info('ResponseURL: %s', event['ResponseURL'])
    LOGGER.info('ResponseBody: %s', response_body)

    opener = build_opener(HTTPHandler)
    request = Request(event['ResponseURL'], data=response_body.encode("utf-8"))
    request.add_header('Content-Type', '')
    request.add_header('Content-Length', len(response_body))
    request.get_method = lambda: 'PUT'
    response = opener.open(request)
    LOGGER.info("Status code: %s", response.getcode())
    LOGGER.info("Status message: %s", response.msg)


def timeout_handler(_signal, _frame):
    '''Handle SIGALRM'''
    raise Exception('Time exceeded')


def main(event, context):
  try:
      LOGGER.info('REQUEST RECEIVED:\n %s', event)
      LOGGER.info('REQUEST RECEIVED:\n %s', context)
      if event['RequestType'] == 'Create':
          LOGGER.info('CREATE!')
          send_response(event, context, "SUCCESS",
                        {"Message": "Resource creation successful!"})
          start(globalVars)
      elif event['RequestType'] == 'Update':
          LOGGER.info('UPDATE!')
          send_response(event, context, "SUCCESS",
                        {"Message": "Resource update successful!"})
      elif event['RequestType'] == 'Delete':
          LOGGER.info('DELETE!')
          send_response(event, context, "SUCCESS",
                        {"Message": "Resource deletion successful!"})
      else:
          LOGGER.info('FAILED!')
          send_response(event, context, "FAILED",
                        {"Message": "Unexpected event received from CloudFormation"})
  except: #pylint: disable=W0702
      LOGGER.info('FAILED!')
      send_response(event, context, "FAILED", {
          "Message": "Exception during processing"})
