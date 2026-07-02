import boto3
import os


def load_env_file():
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip().strip("'\"")

load_env_file()


# Commonly used regions where instances are expected to run
COMMON_REGIONS = [
    {"id": "ap-south-1", "name": "Asia Pacific (Mumbai)"},
    {"id": "ap-southeast-1", "name": "Asia Pacific (Singapore)"},
    {"id": "ap-southeast-2", "name": "Asia Pacific (Sydney)"},
    {"id": "ap-northeast-1", "name": "Asia Pacific (Tokyo)"},
    {"id": "us-east-1", "name": "US East (N. Virginia)"},
    {"id": "us-west-2", "name": "US West (Oregon)"},
    {"id": "eu-central-1", "name": "Europe (Frankfurt)"},
]


def list_regions():
    # Returning hardcoded list for faster loading and to only show relevant regions
    return COMMON_REGIONS


def list_instances_in_region(region_name):
    ec2 = boto3.client("ec2", region_name=region_name)
    instances = []
    try:
        paginator = ec2.get_paginator('describe_instances')
        page_iterator = paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )
        for page in page_iterator:
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    name = "Unnamed"
                    for tag in instance.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]
                    instances.append({
                        "id": instance["InstanceId"],
                        "name": name,
                        "state": instance["State"]["Name"],
                        "type": instance["InstanceType"],
                        "private_ip": instance.get("PrivateIpAddress", "N/A"),
                        "public_ip": instance.get("PublicIpAddress", "N/A"),
                        "region": region_name,
                        "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                    })
    except Exception as e:
        print(f"[ec2_helper] Could not list instances in {region_name}: {e}")
    return instances


if __name__ == "__main__":
    print("Checking regions:", list_regions())
    print()
    total = 0
    for region in list_regions():
        print(f"--- {region} ---")
        instances = list_instances_in_region(region)
        total += len(instances)
        for inst in instances:
            print(f"  {inst['name']} | {inst['id']} | {inst['state']} | {inst['public_ip']}")
        if not instances:
            print("  (none)")
        print()
    print(f"Total instances found: {total}")