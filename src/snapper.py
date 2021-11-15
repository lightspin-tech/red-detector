import random

import boto3
from botocore.exceptions import WaiterError, ClientError


class Snapper:
    def __init__(self, logger):
        self.logger = logger
        self.region = "us-east-1"
        self.client = boto3.client('ec2', region_name=self.region)
        self.ec2 = boto3.resource('ec2', region_name=self.region)

    def create_client(self):
        self.client = boto3.client('ec2', region_name=self.region)
        self.ec2 = boto3.resource('ec2', region_name=self.region)

    def get_regions_list(self):
        try:
            regions_names = [region['RegionName'] for region in self.client.describe_regions()['Regions']]
            return regions_names
        except ClientError as err:
            self.logger.error(f"describe regions: {err}")
            exit(99)

    def select_region(self):
        regions_names = self.get_regions_list()
        val = input("Please select a number:\n1 Select a region\n2 Use default region\n")
        c = 0
        while not (val.isdigit()) or int(val) not in [1, 2]:
            if c == 10:
                print("Wrong input... Exiting...")
                exit()
            val = input("Please select one of the following options only:\n1 Select a region\n2 Use default region\n")

        checker = -1
        while checker != 1:
            if int(val) == 1:
                if checker == -1:  # first loop
                    print("Please select a region:\n")
                elif checker == 0:
                    selected_option = input(
                        "Your selected region does not contain an EC2 instance.\nPlease selecet another region or exit:\n"
                        "1 Select a region\n2 Exit\n")
                    if selected_option == 1:
                        print("Exiting...")
                        exit()
                for i, iid in enumerate(regions_names):
                    print(i, iid)
                selected_region = input()
                region = regions_names[int(selected_region)]
                checker = self.check_region_for_instances(region=region)
            else:
                region = "us-east-1"
                checker = self.check_region_for_instances(region=region)
                val = 1 if checker != 1 else 0
        self.logger.info(f"{region} region was selected")
        return region

    def check_region_for_instances(self, region):
        inst_id, inst_vol = self.create_instances_list_for_region(region=region)
        if len(inst_id) == 0:
            return 0
        else:
            return 1

    @staticmethod
    def create_instances_list_for_region(region):
        client = boto3.client('ec2', region_name=region)
        inst_id = []
        inst_vol = []
        response = client.describe_instances()
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                if instance['State']['Name'] == 'running':
                    inst_id.append(instance['InstanceId'])
                    inst_vol.append(instance['BlockDeviceMappings'][0]['Ebs']['VolumeId'])
        return inst_id, inst_vol

    def get_volume_id(self, doc, name):
        for item in doc['BlockDeviceMappings']:
            if item["DeviceName"] == name:
                return item['Ebs']['VolumeId']
        self.logger.error(f"could not find root volume id: {doc['InstanceId']} - {name}")

    @staticmethod
    def get_instance_name(doc):
        tags = doc.get("Tags")
        if tags:
            for item in tags:
                if item["Key"] == "Name":
                    return item["Value"]
        return ""

    def get_instance_root_vol(self, instance_id):
        try:
            response = self.client.describe_instances(InstanceIds=[instance_id])
            instance_doc = response["Reservations"][0]["Instances"][0]
            volume_id = self.get_volume_id(doc=instance_doc, name=instance_doc["RootDeviceName"])
            return volume_id
        except (ClientError, KeyError) as err:
            self.logger.error(f"describe instances: {err}")
            exit(99)

    def select_ec2_instance(self):
        all_instances = []
        try:
            response = self.client.describe_instances()
        except ClientError as err:
            self.logger.error(f"describe instances: {err}")
            exit(99)
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                if instance['State']['Name'] == 'running':
                    instance_id = instance['InstanceId']
                    instance_name = self.get_instance_name(doc=instance)
                    volume_id = self.get_volume_id(doc=instance, name=instance["RootDeviceName"])
                    all_instances.append(
                        {"instance_id": instance_id, "instance_name": instance_name, "volume_id": volume_id})
        print("Avaliable EC2 instances:")
        for i, instance in enumerate(all_instances):
            print(i, instance["instance_id"], instance["instance_name"])
        selected_instance = input("Select EC2 instance id: ")
        c = 0
        while not (selected_instance.isdigit()) or int(selected_instance) not in range(len(all_instances)):
            if c == 10:
                print("Wrong input... Exiting...")
                exit(-1)
            selected_instance = input("Please select a number in the range of 0 to {}\n".format(len(all_instances) - 1))
            c = c + 1
        selected_ec2_vol_id = all_instances[int(selected_instance)]["volume_id"]
        return selected_ec2_vol_id

    def get_availability_zone(self):
        try:
            response = self.client.describe_availability_zones()
            available_zones = [az['ZoneName'] for az in response['AvailabilityZones'] if az['State'] == 'available']
            selected_az = random.choice(available_zones)
            return selected_az
        except ClientError as err:
            self.logger.error(f"describe availability zones: {err}")
            exit(99)

    def snapshot2volume(self, volume_id):
        self.logger.info("taking snapshot...")
        try:
            snapshot = self.client.create_snapshot(
                Description='Root volume snapshot',
                VolumeId=volume_id,
                TagSpecifications=[
                    {
                        'ResourceType': 'snapshot',
                        'Tags': [{'Key': 'Name', 'Value': 'Red-detector-snapshot'}],
                    },
                ],
            )
        except ClientError as err:
            self.logger.error(f"create snapshot: {err}")
            exit(99)
        if snapshot["ResponseMetadata"]["HTTPStatusCode"] == 200:
            snapshot_id = snapshot["SnapshotId"]
            self.logger.info(f"waiting for snapshot {snapshot_id} to be available...")
            try:
                self.client.get_waiter('snapshot_completed').wait(SnapshotIds=[snapshot_id], WaiterConfig={
                    'Delay': 15,
                    'MaxAttempts': 123})
            except WaiterError as err:
                self.logger.error(f"waiting for snapshot to be available: {err}")
            self.logger.info("creating volume")
            selected_az = self.get_availability_zone()
            try:
                volume = self.client.create_volume(
                    AvailabilityZone=selected_az,
                    SnapshotId=snapshot_id,
                )
            except ClientError as err:
                self.logger.error(f"create volume: {err}")
                exit(99)
            volume_id = volume['VolumeId']
            self.logger.info("waiting for volume to be available...")
            try:
                self.client.get_waiter('volume_available').wait(VolumeIds=[volume_id], WaiterConfig={
                    'Delay': 15,
                    'MaxAttempts': 123})
            except WaiterError as err:
                self.logger.error(f"waiting for volume to be available: {err}")
            self.logger.info("Done creating volume")
            return volume_id, selected_az, snapshot_id
        else:
            self.logger.error("snapshot process failed exiting.")
            exit(99)


