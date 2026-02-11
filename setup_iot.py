#!/usr/bin/env python3
"""
Setup AWS IoT Core Fleet Provisioning resources.

Creates: IoT Policies, Lambda pre-provision hook, Provisioning Template,
         IAM Roles, Thing Group, and Claim Certificate.

All account-specific values (account ID, endpoint) are dynamically resolved.
"""
import json, boto3, os, time, zipfile, io

REGION = os.environ.get("AWS_REGION", "us-east-1")
TEMPLATE_NAME = os.environ.get("IOT_TEMPLATE_NAME", "CertRotationTemplate")
DEVICE_POLICY = "DevicePolicy"
CLAIM_POLICY = "ClaimPolicy"
THING_GROUP = "fleet-devices"
LAMBDA_NAME = "iot-pre-provision-hook"
LAMBDA_ROLE_NAME = "iot-pre-provision-hook-role"
IOT_ROLE_NAME = "IoTFleetProvisioningRole"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

os.makedirs(CERTS_DIR, exist_ok=True)

iot = boto3.client("iot", region_name=REGION)
iam = boto3.client("iam")
lambda_client = boto3.client("lambda", region_name=REGION)

endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]

print(f"Account: {account_id}, Region: {REGION}, Endpoint: {endpoint}")

# ============================================================
# 1. IoT Policies
# ============================================================

device_policy_doc = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iot:Connect",
            "Resource": f"arn:aws:iot:{REGION}:{account_id}:client/${{iot:Connection.Thing.ThingName}}"
        },
        {
            "Effect": "Allow",
            "Action": "iot:Publish",
            "Resource": [
                f"arn:aws:iot:{REGION}:{account_id}:topic/device/${{iot:Connection.Thing.ThingName}}/*",
                f"arn:aws:iot:{REGION}:{account_id}:topic/$aws/certificates/create/*",
                f"arn:aws:iot:{REGION}:{account_id}:topic/$aws/provisioning-templates/{TEMPLATE_NAME}/provision/*",
            ]
        },
        {
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                f"arn:aws:iot:{REGION}:{account_id}:topicfilter/device/${{iot:Connection.Thing.ThingName}}/*",
                f"arn:aws:iot:{REGION}:{account_id}:topicfilter/$aws/certificates/create/*",
                f"arn:aws:iot:{REGION}:{account_id}:topicfilter/$aws/provisioning-templates/{TEMPLATE_NAME}/provision/*",
            ]
        },
        {
            "Effect": "Allow",
            "Action": "iot:Receive",
            "Resource": [
                f"arn:aws:iot:{REGION}:{account_id}:topic/device/${{iot:Connection.Thing.ThingName}}/*",
                f"arn:aws:iot:{REGION}:{account_id}:topic/$aws/certificates/create/*",
                f"arn:aws:iot:{REGION}:{account_id}:topic/$aws/provisioning-templates/{TEMPLATE_NAME}/provision/*",
            ]
        }
    ]
}

claim_policy_doc = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "iot:Connect", "Resource": "*"},
        {
            "Effect": "Allow",
            "Action": ["iot:Publish", "iot:Receive"],
            "Resource": [
                f"arn:aws:iot:{REGION}:{account_id}:topic/$aws/certificates/create/*",
                f"arn:aws:iot:{REGION}:{account_id}:topic/$aws/provisioning-templates/{TEMPLATE_NAME}/provision/*",
            ]
        },
        {
            "Effect": "Allow",
            "Action": "iot:Subscribe",
            "Resource": [
                f"arn:aws:iot:{REGION}:{account_id}:topicfilter/$aws/certificates/create/*",
                f"arn:aws:iot:{REGION}:{account_id}:topicfilter/$aws/provisioning-templates/{TEMPLATE_NAME}/provision/*",
            ]
        }
    ]
}


def create_or_update_policy(name, doc):
    try:
        iot.create_policy(policyName=name, policyDocument=json.dumps(doc))
        print(f"  Created policy: {name}")
    except iot.exceptions.ResourceAlreadyExistsException:
        versions = iot.list_policy_versions(policyName=name)["policyVersions"]
        if len(versions) >= 5:
            non_default = [v for v in versions if not v["isDefaultVersion"]]
            if non_default:
                iot.delete_policy_version(policyName=name, policyVersionId=non_default[0]["versionId"])
        iot.create_policy_version(policyName=name, policyDocument=json.dumps(doc), setAsDefault=True)
        print(f"  Updated policy: {name}")


print("\n[1/5] Creating IoT Policies...")
create_or_update_policy(DEVICE_POLICY, device_policy_doc)
create_or_update_policy(CLAIM_POLICY, claim_policy_doc)

# ============================================================
# 2. Pre-provisioning hook Lambda
# ============================================================

print("\n[2/5] Creating Pre-Provisioning Lambda...")

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
}

try:
    role_arn = iam.create_role(RoleName=LAMBDA_ROLE_NAME, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    iam.attach_role_policy(RoleName=LAMBDA_ROLE_NAME, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    print(f"  Created IAM role: {LAMBDA_ROLE_NAME}")
    print("  Waiting for IAM propagation...")
    time.sleep(10)
except iam.exceptions.EntityAlreadyExistsException:
    role_arn = iam.get_role(RoleName=LAMBDA_ROLE_NAME)["Role"]["Arn"]
    print(f"  IAM role exists: {LAMBDA_ROLE_NAME}")

lambda_code = 'def handler(event, context):\n    return {"allowProvisioning": bool(event.get("parameters", {}).get("SerialNumber"))}\n'

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr("lambda_function.py", lambda_code)
buf.seek(0)

try:
    lambda_client.create_function(
        FunctionName=LAMBDA_NAME, Runtime="python3.12", Role=role_arn,
        Handler="lambda_function.handler", Code={"ZipFile": buf.read()}, Timeout=10
    )
    print(f"  Created Lambda: {LAMBDA_NAME}")
except lambda_client.exceptions.ResourceConflictException:
    buf.seek(0)
    lambda_client.update_function_code(FunctionName=LAMBDA_NAME, ZipFile=buf.read())
    print(f"  Updated Lambda: {LAMBDA_NAME}")

lambda_arn = lambda_client.get_function(FunctionName=LAMBDA_NAME)["Configuration"]["FunctionArn"]

try:
    lambda_client.add_permission(
        FunctionName=LAMBDA_NAME, StatementId="iot-invoke",
        Action="lambda:InvokeFunction", Principal="iot.amazonaws.com"
    )
except lambda_client.exceptions.ResourceConflictException:
    pass

# ============================================================
# 3. Provisioning Template + IAM Role
# ============================================================

print("\n[3/5] Creating Provisioning Template...")

iot_trust = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}]
}

iot_role_policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "iot:AddThingToThingGroup", "iot:AttachPolicy", "iot:AttachPrincipalPolicy",
            "iot:AttachThingPrincipal", "iot:CreateThing",
            "iot:DescribeCertificate", "iot:DescribeThing", "iot:DescribeThingGroup",
            "iot:DetachPolicy", "iot:DetachThingPrincipal",
            "iot:GetPolicy", "iot:ListAttachedPolicies", "iot:ListPolicyVersions",
            "iot:ListTargetsForPolicy", "iot:ListThingGroupsForThing", "iot:ListThingPrincipals",
            "iot:RegisterCertificate", "iot:RegisterThing",
            "iot:RemoveThingFromThingGroup", "iot:UpdateCertificate",
            "iot:UpdateThing", "iot:UpdateThingGroupsForThing",
        ],
        "Resource": "*"
    }]
}

try:
    iot_role_arn = iam.create_role(RoleName=IOT_ROLE_NAME, AssumeRolePolicyDocument=json.dumps(iot_trust))["Role"]["Arn"]
    print(f"  Created IoT role: {IOT_ROLE_NAME}")
    time.sleep(10)
except iam.exceptions.EntityAlreadyExistsException:
    iot_role_arn = iam.get_role(RoleName=IOT_ROLE_NAME)["Role"]["Arn"]
    print(f"  IoT role exists: {IOT_ROLE_NAME}")

iam.put_role_policy(RoleName=IOT_ROLE_NAME, PolicyName="IoTProvisionPolicy", PolicyDocument=json.dumps(iot_role_policy))

template_body = {
    "Parameters": {
        "SerialNumber": {"Type": "String"},
        "AWS::IoT::Certificate::Id": {"Type": "String"}
    },
    "Resources": {
        "certificate": {
            "Properties": {"CertificateId": {"Ref": "AWS::IoT::Certificate::Id"}, "Status": "ACTIVE"},
            "Type": "AWS::IoT::Certificate"
        },
        "policy": {
            "Properties": {"PolicyName": DEVICE_POLICY},
            "Type": "AWS::IoT::Policy"
        },
        "thing": {
            "Properties": {
                "ThingName": {"Ref": "SerialNumber"},
                "ThingGroups": [THING_GROUP],
                "AttributePayload": {"version": "v1"}
            },
            "Type": "AWS::IoT::Thing",
            "OverrideSettings": {"ThingGroups": "REPLACE", "AttributePayload": "MERGE"}
        }
    }
}

try:
    iot.create_thing_group(thingGroupName=THING_GROUP)
    print(f"  Created thing group: {THING_GROUP}")
except iot.exceptions.ResourceAlreadyExistsException:
    print(f"  Thing group exists: {THING_GROUP}")

try:
    iot.create_provisioning_template(
        templateName=TEMPLATE_NAME, templateBody=json.dumps(template_body),
        enabled=True, provisioningRoleArn=iot_role_arn,
        preProvisioningHook={"targetArn": lambda_arn}
    )
    print(f"  Created template: {TEMPLATE_NAME}")
except iot.exceptions.ResourceAlreadyExistsException:
    versions = iot.list_provisioning_template_versions(templateName=TEMPLATE_NAME)["versions"]
    if len(versions) >= 5:
        non_default = sorted([v for v in versions if not v["isDefaultVersion"]], key=lambda v: v["versionId"])
        for v in non_default[:len(non_default) - 3]:
            iot.delete_provisioning_template_version(templateName=TEMPLATE_NAME, versionId=v["versionId"])
    ver = iot.create_provisioning_template_version(
        templateName=TEMPLATE_NAME, templateBody=json.dumps(template_body), setAsDefault=True
    )
    iot.update_provisioning_template(
        templateName=TEMPLATE_NAME, enabled=True,
        provisioningRoleArn=iot_role_arn, preProvisioningHook={"targetArn": lambda_arn}
    )
    print(f"  Updated template: {TEMPLATE_NAME} (v{ver['versionId']})")

# ============================================================
# 4. Claim Certificate (idempotent)
# ============================================================

print("\n[4/5] Creating Claim Certificate...")


def claim_cert_valid():
    if not os.path.exists(CONFIG_PATH):
        return False
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        cid = cfg.get("claim_cert_id")
        if not cid:
            return False
        return iot.describe_certificate(certificateId=cid)["certificateDescription"]["status"] == "ACTIVE"
    except Exception:
        return False


if claim_cert_valid():
    print("  Claim certificate already exists and is active, skipping")
else:
    keys_and_cert = iot.create_keys_and_certificate(setAsActive=True)
    cert_arn = keys_and_cert["certificateArn"]
    cert_id = keys_and_cert["certificateId"]
    iot.attach_policy(policyName=CLAIM_POLICY, target=cert_arn)

    for fname, key in [("claim.cert.pem", "certificatePem"), ("claim.key.pem", "keyPair.PrivateKey")]:
        data = keys_and_cert
        for k in key.split("."):
            data = data[k]
        path = os.path.join(CERTS_DIR, fname)
        with open(path, "w") as f:
            f.write(data)
        os.chmod(path, 0o600)

    config = {
        "endpoint": endpoint,
        "region": REGION,
        "template_name": TEMPLATE_NAME,
        "claim_cert": os.path.join(CERTS_DIR, "claim.cert.pem"),
        "claim_key": os.path.join(CERTS_DIR, "claim.key.pem"),
        "root_ca": os.path.join(CERTS_DIR, "AmazonRootCA1.pem"),
        "certs_dir": CERTS_DIR,
        "claim_cert_id": cert_id,
    }
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  Created claim certificate: {cert_id[:16]}...")

# ============================================================
# 5. Download Root CA
# ============================================================

print("\n[5/5] Checking Root CA...")
root_ca_path = os.path.join(CERTS_DIR, "AmazonRootCA1.pem")
if not os.path.exists(root_ca_path):
    import urllib.request
    urllib.request.urlretrieve("https://www.amazontrust.com/repository/AmazonRootCA1.pem", root_ca_path)
    print("  Downloaded AmazonRootCA1.pem")
else:
    print("  AmazonRootCA1.pem exists")

print(f"\n{'='*50}")
print(f"  Setup Complete!")
print(f"  Endpoint: {endpoint}")
print(f"  Template: {TEMPLATE_NAME}")
print(f"  Run: python3 app.py")
print(f"{'='*50}")
