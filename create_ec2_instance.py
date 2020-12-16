import json
import time
import boto3.ec2
import random
import script2
import paramiko
import subprocess

ec2 = boto3.resource('ec2')


def create_keypair():
    # Create keypair
    key_name='red_detector_key'
    new_keypair = ec2.create_key_pair(KeyName=key_name)

    # Save key as pem file
    with open('./my_key.pem', 'w') as file:
        file.write(new_keypair.key_material)

    return key_name


def gen_port():
    port = random.randrange(10000, 30000)
    print("Selected port is: " + str(port))
    return port


def check_own_ip_address():
    curl_process = subprocess.Popen(
        ["curl", "-4", "ifconfig.co"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    curl_process.wait()
    return curl_process.stdout.read().decode("utf-8").strip()


def generate_security_group(client, port):
    ip_address = check_own_ip_address()
    group_name = "vuls-sg-{}".format(port)
    vpcs = client.describe_vpcs(
        Filters=[
        {
            'Name': 'isDefault',
            'Values': [
                'true',
            ]
        },
    ])

    vpc_id = vpcs.get('Vpcs', [{}])[0].get('VpcId', '')
    sec_group = client.create_security_group(GroupName=group_name,
                                             Description='DESCRIPTION',
                                             VpcId=vpc_id)
    security_group_id = sec_group['GroupId']
    data = client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': str(ip_address)+"/32"}]},
            {'IpProtocol': 'tcp',
             'FromPort': port,
             'ToPort': port,
             'IpRanges': [{'CidrIp': str(ip_address)+"/32"}]}
        ])

    return security_group_id


def create_ec2(client, selected_az, region):
    # key_name = create_keypair()
    key_name = 'snapshot_key1'
    rand_port = gen_port()
    security_group_id = generate_security_group(client, rand_port)

    ubuntu20_image_id = 'ami-0885b1f6bd170450c'
    print("Legal image owner is Canonical (id = 099720109477)")
    image = ec2.Image(ubuntu20_image_id)
    print("\nVerifying image owner...\nEC2 image owner id is: " + str(image.owner_id) + "\n")
    if image.owner_id != '099720109477':
        print("Illigal owner id... Exiting...")

    user_data = script2.script_a.format(region=region)

    print("Creating EC2 instance...")
    instances = client.run_instances(
        BlockDeviceMappings=[
            {
                'DeviceName': '/dev/sdh',
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
        KeyName=key_name,
        UserData=user_data,
        SecurityGroupIds=[
            security_group_id,
        ],
     )

    ec2_inst_id = instances['Instances'][0]['InstanceId']
    instance = instances['Instances'][0]

    waiter = client.get_waiter('instance_running').wait(Filters=[
            {
                'Name': 'instance-id',
                'Values': [
                    ec2_inst_id,
                ]
            },
        ],
    )

    describe = client.describe_instances(
        InstanceIds=[
            ec2_inst_id,
        ],
    )

    instance_ip = describe['Reservations'][0]['Instances'][0]['PublicIpAddress']
    print("EC2 instance is running")

    return ec2_inst_id, instance_ip, rand_port


def attach_volume_to_ec2(client, ec2_inst_id, ss_volume_id):
    attach_resp = client.attach_volume(
            Device='/dev/sdm',
            InstanceId = ec2_inst_id,
            VolumeId = ss_volume_id
    )

    waiter = client.get_waiter('volume_in_use').wait(Filters=[
            {
                'Name': 'volume-id',
                'Values': [
                    ss_volume_id,
                ]
            },
        ],
    )

    print("Finished attaching volume to instance.")


def scan_and_report(client, instance_ip, rand_port, instance_id, snapshot_id):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    privet_key = paramiko.RSAKey.from_private_key_file("my_key.pem")
    connect = 0
    while not connect:
        try:
            ssh.connect(hostname=instance_ip, username='ubuntu', pkey=privet_key, timeout=1200)
            connect = 1
        except Exception as e:
            print("Connecting to instance...")

    counter = 0
    print("Updating the scanner databases... It takes about 30 minutes")
    while counter < 30:
        stdin, stdout, stderr = ssh.exec_command('ls /tmp/userData.finished')
        if stdout.read():
            print("userData script finished")
            break
        else:
            print("Updating...")
            counter += 1
            time.sleep(60)
    if counter == 45:
        print("Error: failed to initialize instance.\nExiting...")
        exit()

    print("EC2 instance is ready\n")
    print("Scanning...")
    mount_list = []
    stdin, stdout, stderr = ssh.exec_command("lsblk --json -fs")
    lsblk = json.loads(stdout.read())
    for item in lsblk["blockdevices"]:
        if item["fstype"] in ["ext2", "xfs", "ext3", "ext4"] and not(item['mountpoint']):
            mount_dev = f"/dev/{item['name']}"
            mount_list.append(mount_dev)

    for i in range(len(mount_list)):
        stdin, stdout, stderr = ssh.exec_command(script2.script_b.format(port=rand_port, ip_address=instance_ip, instance_id=instance_id, mount_point=mount_list[i]))
        if stderr:
            print(f"Errors {i}:")
            for line in stderr:
                print(line)

    stdin, stdout, stderr = ssh.exec_command(script2.script_c.format(port=rand_port, ip_address=instance_ip,instance_id=instance_id))
    if stderr:
        print("Errors:")
        for line in stderr:
            print(line)

    counter = 0
    while counter < 30:
        stdin, stdout, stderr = ssh.exec_command('ls /tmp/script.finished')
        if stdout.read():
            print("\nCheck the report at: http://{ip_address}:{port}".format(ip_address=instance_ip, port=rand_port))
            print("Finished scanning and created a report")
        else:
            print(counter)
            counter += 1
            time.sleep(1)

    if counter == 30:
        print("Error: can not create UI report")

    ssh.close()
    client.delete_snapshot(SnapshotId=snapshot_id)
    return
