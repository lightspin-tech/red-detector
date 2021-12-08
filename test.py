import subprocess
import argparse
import sys
import threading
import boto3

# Ill change this later by the method we will choose. this is kind of a poc...
def scan(region, id, keypair, log_level):
    command = "python3 main.py --region {region} --instance-id {id} --keypair {keypair} --log-level {loglevel}". \
        format(region=region, id=id, keypair=keypair, loglevel=log_level)
    output = subprocess.getoutput(command)
    print(output)


ec2 = boto3.resource('ec2')
lst_of_account_instances = []  # this lst will contain all of the running instances ids. for scanning later
for instance in ec2.instances.all():
    if "16" in str(instance.state):  # getting just the running instances
        lst_of_account_instances.append(instance.id)


exit(99)
parser = argparse.ArgumentParser()
parser.add_argument('--region', action='store', dest='region', type=str,
                    help='region name', required=False)
parser.add_argument('--instance-id', action='store', dest='instance_id', type=str,
                    help='EC2 instance id', required=False)
parser.add_argument('--keypair', action='store', dest='keypair', type=str,
                    help='existing key pair name', required=False)
parser.add_argument('--log-level', action='store', dest='log_level', type=str,
                    help='log level', required=False, default="INFO")
region = "us-east-2"
source_volume_id = "id"
keypair = "red_detector_key3"
log_level = "INFO"

cmd_args = parser.parse_args()
if cmd_args.region:
    region = cmd_args.region
if cmd_args.instance_id:
    source_volume_id = cmd_args.instance_id
if cmd_args.keypair:
    keypair = cmd_args.keypair
if cmd_args.log_level:
    log_level = cmd_args.log_level

lst_of_ids = source_volume_id.split("_")  # need to provide the ids with a _ between them.
for id in lst_of_ids:
    # scan(region, id, keypair, log_level)
    x = threading.Thread(target=scan, args=(region, id, keypair, log_level,))
    x.start()

