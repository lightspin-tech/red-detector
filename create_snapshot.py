import random
import boto3


def get_regions_list(client):
    regions_names = [region['RegionName'] for region in client.describe_regions()['Regions']]
    return regions_names


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


def check_of_region_has_instances(region):
    inst_id, inst_vol = create_instances_list_for_region(region)
    if len(inst_id) == 0:
        return 0
    else:
        return 1


def get_region():
    client = boto3.client('ec2')
    regions_names = get_regions_list(client)
    print("Would you like to select a region or to use the default region us-east-1?")
    val = input("Please select a number:\n1 Select a region\n2 Use default region\n")
    counter = 0;
    while not(val.isdigit()) or int(val) not in [1,2]:
        if counter == 30:
            print("Wrong input... Exiting...")
            exit()
        val = input("Please select one of the following options only:\n1 Select a region\n2 Use default region\n")

    checker = -1
    while checker != 1:
        if int(val) == 1:
            if checker == -1: #first loop
                print("Please select a region:\n")
            elif checker == 0:
                selected_option = input("Your selected region does not contain an EC2 instance.\nPlease selecet another region or exit:\n"
                                        "1 Select a region\n2 Exit\n")
                if selected_option == 1:
                    print("Exiting...")
                    exit()
            for i, iid in enumerate(regions_names):
                print(i, iid)
            selected_region = input()
            region = regions_names[int(selected_region)]
            checker = check_of_region_has_instances(region)
        else:
            region = "us-east-1"
            checker = check_of_region_has_instances(region)
            val = 1 if checker != 1 else 0
    print("{} region was selected".format(region))
    return region


def select_ec2_instance(client):
    response = client.describe_instances()

    inst_id = []
    inst_vol = []
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance['State']['Name'] == 'running':
                inst_id.append(instance['InstanceId'])
                inst_vol.append(instance['BlockDeviceMappings'][0]['Ebs']['VolumeId'])
    for i, iid in enumerate(inst_id):
        print(i, iid)
    val = input("Select EC2 instance id: ")
    counter = 0;
    while not (val.isdigit()) or int(val) not in range(len(inst_id)):
        if counter == 30:
            print("Wrong input... Exiting...")
            exit()
        val = input("Please select a number in the range of {}\n".format(len(inst_id)))

    # selected_ec2_id = inst_id[int(val)]
    selected_ec2_vol_id = inst_vol[int(val)]

    # returns selected ec2 instance volume id
    print("Done selecting EC2 instance")
    return selected_ec2_vol_id


def generate_availability_zone(client):
    response = client.describe_availability_zones()
    available_zones = [az['ZoneName'] for az in response['AvailabilityZones'] if az['State'] == 'available']

    selected_az = random.choice(available_zones)

    return selected_az


def snapshot2volume(client, volume_id):
    #Take snapshot
    print("Taking snapshot...")
    snapshot = client.create_snapshot(
        Description='Root volume snapshot',
        VolumeId=volume_id,
    )
    ss_id = snapshot['SnapshotId']

    # Wait until snapshot is ready
    print("Completing snapshot...")
    client.get_waiter('snapshot_completed').wait(SnapshotIds=[ss_id])

    # Crate volume
    print("Creating volume")
    selected_az = generate_availability_zone(client)
    volume = client.create_volume(
        AvailabilityZone=selected_az,
        SnapshotId=ss_id,
    )

    ss_volume_id = volume['VolumeId']
    # Hold until volume is ready
    print("Waiting for volume to be available...")
    client.get_waiter('volume_available').wait(VolumeIds=[ss_volume_id])

    print("Done creating volume")
    return ss_volume_id, selected_az


