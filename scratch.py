import paramiko
import logging
import sys

logging.basicConfig(level=logging.DEBUG)
paramiko.util.log_to_file('paramiko.log')

key_path = "/home/naveen/wfh_access_app/keys/test-key.pem"
key = paramiko.RSAKey.from_private_key_file(key_path)

ip = "3.25.115.39"
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    client.connect(hostname=ip, username='ubuntu', pkey=key, timeout=10)
    print("Success ubuntu")
except Exception as e:
    print("Failed ubuntu:", e)

try:
    client.connect(hostname=ip, username='ec2-user', pkey=key, timeout=10)
    print("Success ec2-user")
except Exception as e:
    print("Failed ec2-user:", e)

