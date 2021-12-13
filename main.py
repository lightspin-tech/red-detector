import subprocess
import argparse
import sys
import threading
from art import text2art
import datetime
import boto3
begin_time = datetime.datetime.now()


class Scan(threading.Thread):
    def __init__(self, instance_region, instance_id, instance_keypair, instance_log_level):
        threading.Thread.__init__(self)
        self.region = instance_region
        self.id = instance_id
        self.keypair = instance_keypair
        self.log_level = instance_log_level

    def run(self):
        """
        running the main with "one instance at a time" (in threads of course)
        """
        command = "python3 exec.py --region {region} --instance-id {id} --keypair {keypair} --log-level {loglevel}". \
            format(region=self.region, id=self.id, keypair=self.keypair, loglevel=self.log_level)
        command = command.split(" ")  # the command should be in this format in order to get live output
        with open('test.log', 'wb') as f:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE)
            for c in iter(lambda: process.stdout.readline(1), b''):
                # sys.stdout.write(" [ From: " + self.instance_id + " ]" + str(c))
                pass

if __name__ == "__main__":

    text_art = text2art("RED   DETECTOR")
    print(text_art)
    print("            +++ WELCOME RED-DETECTOR - CVE SCANNER USING VULS +++\n\n")

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

    """
    sample inputs for instance-id:
    *    ami-0fb653ca2d3203ac1
    *    i-008966f80522a3c34_i-0ff28ad4240aef353
    *    account_scan
    *    regions:us-east-1,us-east-2
    """


    cmd_args = parser.parse_args()
    if cmd_args.region:
        region = cmd_args.region
    if cmd_args.instance_id:
        source_volume_id = cmd_args.instance_id
    if cmd_args.keypair:
        keypair = cmd_args.keypair
    if cmd_args.log_level:
        log_level = cmd_args.log_level

    lst_of_ids = []
    ec2 = boto3.resource('ec2')

    if source_volume_id == "account_scan":
        ec2 = boto3.resource('ec2')
        for instance in ec2.instances.all():
            if str(instance.state["Code"]) == "16":  # getting just the running instances
                lst_of_ids.append(instance.id)

    elif "region" in source_volume_id:  # input in this form:  region:us-east-2
        # source_volume_id = "regions:us-east-2,us-east-1"
        source_volume_id = source_volume_id.replace("regions:", "")
        try:
            regions = source_volume_id.split(",")
        except:
            regions = source_volume_id[0]  # means got one region
        source_volume_id = source_volume_id.split(":")
        client = boto3.client('ec2')
        for region in regions:
            conn = boto3.resource('ec2', region_name=region)
            instances = conn.instances.filter()
            for instance in instances:
                if instance.state["Name"] == "running":
                    # without the if below: scan all regions.
                    if region in regions:
                        # print(instance.id, instance.instance_type, region)
                        lst_of_ids.append(instance.id)
    elif "ami" in source_volume_id:
        # ami = "ami-0fb653ca2d3203ac1"
        ami = source_volume_id
        client = boto3.client('ec2')
        cl = client.describe_instances()
        for data in cl['Reservations']:
            for i in data["Instances"]:
                if i['ImageId'] == ami:
                    lst_of_ids.append(i['InstanceId'])
    else:
        lst_of_ids = source_volume_id.split("_")  # need to provide the ids with a _ between them.

    print("Going to scan: ", lst_of_ids)
    threads = []
    for instance_id in lst_of_ids:
        # print(instance_id)
        instance_scan = Scan(region, instance_id, keypair, log_level)
        instance_scan.start()
        threads.append(instance_scan)
    
    for x in threads:
        x.join()  # wait for all the threads to end.
    
print("Time took to execute: ", datetime.datetime.now() - begin_time)
