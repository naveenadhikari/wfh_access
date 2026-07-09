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


import concurrent.futures
import time
from botocore.config import Config

COMMON_REGIONS = [
    {"id": "ap-south-1", "name": "Asia Pacific (Mumbai)"},
    {"id": "ap-southeast-1", "name": "Asia Pacific (Singapore)"},
    {"id": "ap-southeast-2", "name": "Asia Pacific (Sydney)"},
    {"id": "ap-northeast-1", "name": "Asia Pacific (Tokyo)"},
    {"id": "us-east-1", "name": "US East (N. Virginia)"},
    {"id": "us-west-2", "name": "US West (Oregon)"},
    {"id": "eu-central-1", "name": "Europe (Frankfurt)"},
]

AWS_REGION_NAMES = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "af-south-1": "Africa (Cape Town)",
    "ap-east-1": "Asia Pacific (Hong Kong)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ca-central-1": "Canada (Central)",
    "eu-central-1": "Europe (Frankfurt)",
    "eu-west-1": "Europe (Ireland)",
    "eu-west-2": "Europe (London)",
    "eu-south-1": "Europe (Milan)",
    "eu-west-3": "Europe (Paris)",
    "eu-north-1": "Europe (Stockholm)",
    "me-south-1": "Middle East (Bahrain)",
    "sa-east-1": "South America (São Paulo)",
}

_cached_active_regions = None
_cache_time = 0
CACHE_TTL = 30  # 30 seconds for faster updates

def _check_region_has_instances(region_name):
    # Short timeout since we only care if it responds quickly with instances
    config = Config(connect_timeout=2, read_timeout=2, retries={'max_attempts': 1})
    try:
        ec2 = boto3.client("ec2", region_name=region_name, config=config)
        response = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped", "pending", "shutting-down", "stopping"]}],
            MaxResults=5
        )
        if response.get("Reservations"):
            return region_name
    except Exception:
        pass
    return None

def list_regions():
    """Dynamically fetches active AWS regions and caches them."""
    global _cached_active_regions, _cache_time
    if _cached_active_regions is not None and (time.time() - _cache_time < CACHE_TTL):
        return _cached_active_regions

    try:
        config = Config(connect_timeout=2, read_timeout=2, retries={'max_attempts': 1})
        ec2 = boto3.client("ec2", region_name="us-east-1", config=config)
        all_regions = [r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"]]
        
        active_region_ids = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(_check_region_has_instances, all_regions)
            for r in results:
                if r:
                    active_region_ids.append(r)
        
        # Fallback if none found
        if not active_region_ids:
            return COMMON_REGIONS
            
        _cached_active_regions = [{"id": r, "name": AWS_REGION_NAMES.get(r, r)} for r in active_region_ids]
        _cache_time = time.time()
        return _cached_active_regions
    except Exception as e:
        print(f"[ec2_helper] Error fetching active regions dynamically: {e}")
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