#!/usr/bin/env python3
"""
Cleanup all AWS IoT resources created by setup_iot.py.
"""
import json, os, boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

iot = boto3.client("iot", region_name=REGION)
iam = boto3.client("iam")
lambda_client = boto3.client("lambda", region_name=REGION)

TEMPLATE_NAME = "CertRotationTemplate"
DEVICE_POLICY = "DevicePolicy"
CLAIM_POLICY = "ClaimPolicy"
LAMBDA_NAME = "iot-pre-provision-hook"
LAMBDA_ROLE_NAME = "iot-pre-provision-hook-role"
IOT_ROLE_NAME = "IoTFleetProvisioningRole"
THING_GROUP = "fleet-devices"


def safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
        return True
    except Exception as e:
        print(f"  Skip: {e}")
        return False


def delete_policy(name):
    """Detach all targets and delete all versions before deleting policy."""
    try:
        targets = iot.list_targets_for_policy(policyName=name)["targets"]
        for t in targets:
            iot.detach_policy(policyName=name, target=t)
        versions = iot.list_policy_versions(policyName=name)["policyVersions"]
        for v in versions:
            if not v["isDefaultVersion"]:
                iot.delete_policy_version(policyName=name, policyVersionId=v["versionId"])
        iot.delete_policy(policyName=name)
        print(f"  Deleted policy: {name}")
    except Exception as e:
        print(f"  Skip policy {name}: {e}")


print("[1/6] Deleting Provisioning Template...")
try:
    versions = iot.list_provisioning_template_versions(templateName=TEMPLATE_NAME)["versions"]
    for v in versions:
        if not v["isDefaultVersion"]:
            safe(iot.delete_provisioning_template_version, templateName=TEMPLATE_NAME, versionId=v["versionId"])
    safe(iot.delete_provisioning_template, templateName=TEMPLATE_NAME)
    print(f"  Deleted template: {TEMPLATE_NAME}")
except Exception as e:
    print(f"  Skip: {e}")

print("\n[2/6] Revoking Claim Certificate...")
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    cid = cfg.get("claim_cert_id")
    if cid:
        cert_arn = f"arn:aws:iot:{REGION}:{boto3.client('sts').get_caller_identity()['Account']}:cert/{cid}"
        safe(iot.detach_policy, policyName=CLAIM_POLICY, target=cert_arn)
        safe(iot.update_certificate, certificateId=cid, newStatus="INACTIVE")
        safe(iot.delete_certificate, certificateId=cid, forceDelete=True)
        print(f"  Deleted claim cert: {cid[:16]}...")

print("\n[3/6] Deleting IoT Policies...")
delete_policy(DEVICE_POLICY)
delete_policy(CLAIM_POLICY)

print("\n[4/6] Deleting Lambda...")
safe(lambda_client.delete_function, FunctionName=LAMBDA_NAME)
print(f"  Deleted Lambda: {LAMBDA_NAME}")

print("\n[5/6] Deleting IAM Roles...")
for role_name in [LAMBDA_ROLE_NAME, IOT_ROLE_NAME]:
    try:
        # Detach managed policies
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        # Delete inline policies
        for p in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
        iam.delete_role(RoleName=role_name)
        print(f"  Deleted role: {role_name}")
    except Exception as e:
        print(f"  Skip role {role_name}: {e}")

print("\n[6/6] Deleting Thing Group...")
safe(iot.delete_thing_group, thingGroupName=THING_GROUP)
print(f"  Deleted thing group: {THING_GROUP}")

# Clean local files
if os.path.exists(CONFIG_PATH):
    os.remove(CONFIG_PATH)
    print("\n  Removed config.json")

print("\n=== Cleanup Complete ===")
