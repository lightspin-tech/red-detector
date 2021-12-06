import json
import random
import time

import boto3
import subprocess
import paramiko
import requests
from botocore.exceptions import ClientError, WaiterError
from dateutil.parser import parse

from src import remote_scripts


class Scanner:
    def __init__(self, logger, region, key_pair_name):
        self.logger = logger
        self.region = region
        self.key_pair_name = key_pair_name
        self.client = boto3.client('ec2', region_name=region)
        self.ec2 = boto3.resource('ec2', region_name=region)
        self.keypair_name = None

    def create_keypair(self, key_name):
        try:
            new_keypair = self.ec2.create_key_pair(KeyName=key_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidKeyPair.Duplicate":
                self.logger.warning(f"key pair: {key_name} already exists.")
                val = input("use the existing keypair?[Y/N]\n")
                if val.lower() == "y":
                    return key_name
            self.logger.error(f"create key pair: {err}")
            exit(99)
        self.logger.info('creating key pair: {red_detector_key}'.format(red_detector_key=self.key_pair_name))
        with open(self.key_pair_name+'.pem', 'w') as f:  # NEED TO OPEN A LOCAL FILE FOR "OLD" KEY PAIR TOO.
            f.write(new_keypair.key_material)
            output = subprocess.getoutput("chmod 400 "+self.key_pair_name+'.pem')
        return key_name

    @staticmethod
    def gen_port():
        port = random.randrange(10000, 30000)
        return port

    def check_ip_address(self):
        try:
            r = requests.get(r'http://jsonip.com')
            if r.status_code != 200:
                raise ValueError
        except (ConnectionError, TimeoutError, ValueError):
            r = requests.get(r'https://ifconfig.co/json')
            if r.status_code != 200:
                self.logger.error("failed getting your internet ip address")
        ip = r.json()['ip']
        return ip

    def generate_security_group(self, port):
        ip_address = self.check_ip_address()
        group_name = "vuls-sg-{}".format(port)
        try:
            vpcs = self.client.describe_vpcs(
                Filters=[
                    {
                        'Name': 'isDefault',
                        'Values': [
                            'true',
                        ]
                    },
                ])
        except ClientError as err:
            self.logger.error(f"describe vpcs: {err}")
            exit(99)
        vpc_id = vpcs.get('Vpcs', [{}])[0].get('VpcId', '')
        try:
            sec_group = self.client.create_security_group(GroupName=group_name,
                                                      Description='DESCRIPTION',
                                                      VpcId=vpc_id)
        except ClientError as err:
            self.logger.error(f"create security group: {err}")
            exit(99)
        security_group_id = sec_group['GroupId']
        try:
            self.client.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {'IpProtocol': 'tcp',
                     'FromPort': 22,
                     'ToPort': 22,
                     'IpRanges': [{'CidrIp': f'{ip_address}/32'}]},
                    {'IpProtocol': 'tcp',
                     'FromPort': port,
                     'ToPort': port,
                     'IpRanges': [{'CidrIp': f'{ip_address}/32'}]}
                ])
        except ClientError as err:
            self.logger.error(f"authorize security group ingress: {err}")
            exit(99)
        return security_group_id

    def get_latest_ami_by_filter(self, owners=[], filters=[]):
        try:
            response = self.client.describe_images(Owners=owners, Filters=filters)
            latest = None
            for image in response['Images']:
                if not latest:
                    latest = image
                    continue
                if parse(image['CreationDate']) > parse(latest['CreationDate']):
                    latest = image
            return latest['ImageId']
        except ClientError as err:
            self.logger.error(f"describe images: {err}")
            exit(99)

    def create_ec2(self, selected_az):
        report_service_port = self.gen_port()
        security_group_id = self.generate_security_group(port=report_service_port)
        ubuntu20_image_id = self.get_latest_ami_by_filter(owners=["099720109477"], filters=[{
            'Name': 'name',
            'Values': ['ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*']
        }])

        user_data = remote_scripts.script_a.format(region=self.region)
        self.logger.info("creating EC2 instance...")
        try:
            instances = self.client.run_instances(
                BlockDeviceMappings=[
                    {
                        'DeviceName': '/dev/sda1',
                        'Ebs': {
                            'VolumeSize': 40,
                        },
                    },
                ],
                Placement={
                    'AvailabilityZone': selected_az,
                },
                ImageId=ubuntu20_image_id,
                MinCount=1,
                MaxCount=1,
                InstanceType='t2.large',
                KeyName=self.key_pair_name,
                UserData=user_data,
                SecurityGroupIds=[
                    security_group_id,
                ],
            )
        except ClientError as err:
            self.logger.error(f"run instance: {err}")
            exit(99)
        ec2_instance = instances['Instances'][0]
        ec2_instance_id = ec2_instance['InstanceId']

        try:
            self.client.get_waiter('instance_running').wait(Filters=[
                {
                    'Name': 'instance-id',
                    'Values': [
                        ec2_instance_id,
                    ]
                },
            ], WaiterConfig={
                'Delay': 15,
                'MaxAttempts': 123}
            )
        except WaiterError as err:
            self.logger.error(f"waiting for EC2 instance to be available: {err}")
        try:
            ec2_instance_describe = self.client.describe_instances(
                InstanceIds=[
                    ec2_instance_id,
                ],
            )
        except ClientError as err:
            self.logger.error(f"describe instances: {err}")
            exit(99)
        ec2_instance_public_ip = ec2_instance_describe['Reservations'][0]['Instances'][0]['PublicIpAddress']
        self.logger.info(f"EC2 instance: {ec2_instance_id} is running ({ec2_instance_public_ip})")
        return ec2_instance_id, ec2_instance_public_ip, report_service_port

    def attach_volume_to_ec2(self, ec2_instance_id, volume_id):
        try:
            response = self.client.attach_volume(
                Device='/dev/sdm',
                InstanceId=ec2_instance_id,
                VolumeId=volume_id
            )
        except ClientError as err:
            self.logger.error(f"attach volume: {err}")
            exit(99)
        if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            self.logger.error(f"attaching volume failed: {response.get('Error')}")
            exit(99)
        try:
            self.client.get_waiter('volume_in_use').wait(Filters=[
                {
                    'Name': 'volume-id',
                    'Values': [
                        volume_id,
                    ]
                },
            ], WaiterConfig={
                'Delay': 15,
                'MaxAttempts': 123}
            )
        except WaiterError as err:
            self.logger.error(f"waiting for volume to be available: {err}")
        self.logger.info("Finished attaching volume to instance")

    def scan_and_report(self, ec2_instance_public_ip, report_service_port, ec2_instance_id, snapshot_id):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        privet_key = paramiko.RSAKey.from_private_key_file(self.key_pair_name+".pem")
        connect = 0
        while not connect:
            try:
                ssh.connect(hostname=ec2_instance_public_ip, username='ubuntu', pkey=privet_key)
                connect = 1
            except Exception as err:
                self.logger.error(f"failed connecting to EC2 instance: {err}. Trying again...")

        wait_4_update = True
        c = 0
        self.logger.info("updating the scanners' databases... It takes about 30 minutes")
        while wait_4_update and c < 45:
            stdin, stdout, stderr = ssh.exec_command('ls /tmp/userData.finished')
            if stdout.read():
                self.logger.debug("userData script finished")
                wait_4_update = False
            else:
                self.logger.info("updating...")
                c += 1
                time.sleep(60)

        if wait_4_update:
            self.logger.error("failed to initialize scanners' databases")
            exit(99)

        self.logger.info("EC2 instance is ready")
        self.logger.info("Scanning...")
        mount_list = []
        stdin, stdout, stderr = ssh.exec_command("lsblk --json -fs")
        lsblk = json.loads(stdout.read())
        for item in lsblk["blockdevices"]:
            if item["fstype"] in ["ext2", "xfs", "ext3", "ext4"] and not (item['mountpoint']):
                mount_dev = f"/dev/{item['name']}"
                mount_list.append(mount_dev)

        for mount in mount_list:

            stdin, stdout, stderr = ssh.exec_command(
                remote_scripts.script_b.format(port=report_service_port, ip_address=ec2_instance_public_ip,
                                               instance_id=ec2_instance_id,
                                               mount_point=mount))

            # add here code to take the chkrootkit output add save it to the wanted place on the ec2.


            stdout = stdout.readlines()
            for line in stdout:
                self.logger.debug(line)

        wait_4_update = True
        c = 0
        while wait_4_update and c < 360:
            stdin, stdout, stderr = ssh.exec_command('ls /tmp/script.finished')
            if stdout.read():
                stdin, stdout, stderr = ssh.exec_command(
                    remote_scripts.script_c.format(port=report_service_port, ip_address=ec2_instance_public_ip,
                                                   instance_id=ec2_instance_id))
                stdout = stdout.readlines()
                for line in stdout:
                    self.logger.debug(line)
                self.logger.info(f"Check the report at: http://{ec2_instance_public_ip}:{report_service_port}")
                wait_4_update = False
            else:
                c += 1
                time.sleep(1)

        if wait_4_update:
            self.logger.error("generating scan report failed")
            exit(99)

        ssh.close()
        self.logger.info(f"cleaning up snapshot: {snapshot_id}")
        try:
            self.client.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as err:
            self.logger.error(f"delete snapshot: {err}")
            exit(99)
        return
