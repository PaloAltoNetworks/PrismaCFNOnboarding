# RedlockCFNOnboarding

Cloudformation template to onboard Redlock to AWS.

Includes Python Lambda script to create VPC Flow logs and Cloudtrail


CFT PARAMETERS 

PrismaRoleName       (Name you would like the role to be called within your AWS Account)

ExternalID           (Unique ID for Cross account role access, eg, 8298nshslkj28dnhw2hn3nlks8  https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)

PrismaUsername       (Your local Prisma account username -- not PANW SSO -- or Access Key)

PrismaPassword       (Your local Prisma account password -- not PANW SSO -- or Secret Key)

PrismaCustomerName   (The name of your tenant within Prisma)

PrismaAccountName    (Name you would like to give the account within Prisma)

PrismaTenant         (Selectable dropdown, app, app2, app3, app.eu etc)

PrismaAccountGroup   (Account Group you would like the account added to -- default is Default Account Group)

CreatePrismaAccount  (True or False, True will onboard an account as new, False will only update the account and run lambda script)

EnableCloudTrailLogs (True or False, currently does nothing. Prisma does not require creation of a CT any longer as we pull from the CT API and this is enabled by default for all AWS accounts. There is currently a known issue within the product that will provide a Yellow warning stating that we can't find a CT for the account but this can be ignored. Event ingestion will work without it.)

EnableVpcFlowLogs    (True or False, True will iterate through all of your VPCs and enable flowlogs if there isn't one already available)



