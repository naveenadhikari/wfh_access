import time
import requests
import os
import boto3

def load_env():
    with open('/home/naveen/wfh_access_app/.env') as f:
        for line in f:
            if '=' in line and not line.startswith('#'):
                k, v = line.strip().split('=', 1)
                os.environ[k] = v.strip('"\' ')
load_env()

print("Testing AWS boto3...")
start = time.time()
try:
    ec2 = boto3.client('ec2', region_name='us-east-1')
    res = ec2.describe_instances()
except Exception as e:
    print(f"Exception: {e}")
print(f"Boto3 request took: {time.time() - start:.2f} seconds")
