import boto3
from collections import defaultdict
import boto.ec2
import os
import paramiko
import boto
import subprocess
import time
from creator import Creator
import time

start_time = time.time()
# Before running this:
# need to "aws configure" in terminal and provide data.


ec2 = boto3.client('ec2')

region = "us-east-2"
response = ec2.describe_vpcs()


def get_vpc():
    # vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')  # giving a wrong vpc
    vpc_id = ""
    str_i = ""
    client = boto3.client('ec2')
    data = client.describe_instances()
    for i in data['Reservations']:
        str_i = str(i)
        if "vpc" in str_i:
            str_i = str_i.split("'VpcId': '")
            str_i = str_i[1]
            str_i = str_i.split("', 'Architecture':")  # the thing that comes after the VpcId
            vpc_id = str_i[0]
    return vpc_id


def security_group_settings(vpc_id_, group_name):
    try:
        response1 = ec2.create_security_group(GroupName=group_name, Description='DESCRIPTION', VpcId=vpc_id_)
        security_group_id = response1['GroupId']
        print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id_))

        data = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                # add here kibana ports later.
                {'IpProtocol': 'tcp',
                 'FromPort': 22,
                 'ToPort': 22,
                 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
            ])
        print('Ingress Successfully Set %s' % data)
        return security_group_id
    except Exception as e:
        print(e)


def create_ec2(security_group_id, key_pair_name):
    """
    
    :param security_group_id: getting this from a function above
    :param key_pair_name: key pair is created here with a hardcoded name.
    :return: new ec2's id.
    """
    # maybe get ImageId too.

    ec21 = boto3.resource('ec2')
    # create a file to store the key locally
    outfile = open(key_pair_name+'.pem', 'w')
    key_pair = ec21.create_key_pair(KeyName=key_pair_name)

    # capture the key and store it in a file
    KeyPairOut = str(key_pair.key_material)
    outfile.write(KeyPairOut)

    # create a new EC2 instance
    instances = ec21.create_instances(
         ImageId='ami-00399ec92321828f5',
         MinCount=1,
         MaxCount=1,
         InstanceType='t2.large',
         KeyName=key_pair_name,
         SecurityGroupIds=[
             security_group_id,
         ]
     )
    instance_id_ = str(instances[0])  # raw output: [ec2.Instance(id='i-0e379dc5b2efc913c')]
    instance_id_ = instance_id_.replace("ec2.Instance(id='", "")
    instance_id_ = instance_id_.replace("')", "")
    print(instance_id_)
    return instance_id_


def instance_id_ip(instance_id):
    """
    
    :param instance_id: instance_id
    :return: ec2's global ip
    """
    ec2_global_ip = ""
    # instance_id = "i-073ae94f0d3e7b4d3"
    temp = boto.ec2.connect_to_region(region)  # check here for the new error
    reservations = temp.get_all_instances()
    for r in reservations:
        for i in r.instances:
            if i.state == 'running':
                if i.id == instance_id:
                    ec2_global_ip = i.ip_address
                    vpc_id = i.vpc_id
                    # print("On: " + ec2_global_ip)
    return ec2_global_ip


def ssh_operations(ec2_global_ip, key_pair_name, sudo_pass, file_path_to_pass, destination_file_path):
    """
    transferring and running a python file in the new ec2 machine (or another machine if wanted..)
    :param ec2_global_ip:
    :param key_pair_name:
    :param sudo_pass:
    :return:
    """
    # IMPORTANT- without chmod 400 (etc) the ssh will not work due to too open access to the key file.
    sudo_password = "echo " + sudo_pass + " | sudo -S "
    commands1 = sudo_password + "sudo chmod 400 " + "/home/idan/PycharmProjects/pythonProject/" + key_pair_name + ".pem"
    output = subprocess.getoutput(commands1)  # ill change the path later

    username = "ubuntu"  # may get this as parameter later on
    ssh = paramiko.SSHClient()
    private_key = paramiko.RSAKey.from_private_key_file(key_pair_name + ".pem")
    ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(hostname=ec2_global_ip, port=22, username=username, pkey=private_key)
    sftp = ssh.open_sftp()
    sftp.put(file_path_to_pass, destination_file_path)  # put is writing over
    sftp.close()

    # running the file:
    stdin_, stdout_, stderr_ = ssh.exec_command("sudo python3 " + destination_file_path, get_pty=True)
    # this will be the sudo of the new machine- I guess it won't have a password?
    time.sleep(5)  # don't know why, but prevents crashing :) (well, apparently just sometimes. need to check more.)
    stdout_.channel.recv_exit_status()
    lines = stdout_.readlines()
    for line in lines:
        print(line)


def main():
    key_pair_name = "idan15"  # without .pem
    sudo_password = "Idan2408"
    group_name = "idantest31"
    vpc_id = get_vpc()
    print(vpc_id)

    security_group_id = security_group_settings(vpc_id, group_name)
    print(security_group_id)

    instance_id = create_ec2(security_group_id, key_pair_name)
    print("instance id: ", instance_id)
    # instance_id = "i-0a70851a2af9eec29"

    global_ip = instance_id_ip(instance_id)
    print("instace global ip:", global_ip)  # global ip of the new machine
    time.sleep(20)
    ec2_to_snap_from = "i-0e379dc5b2efc913c" # id of the ec2 we want to scan.
    a = Creator("us-east-2", instance_id,  ec2_to_snap_from)  # (region, ec2 just created, ec2 to snap from)
    a.create_and_attach_volume_from_snapshot()
    ssh_operations(global_ip, key_pair_name, sudo_password, "/commands.py", "/home/ubuntu/test.py")
    ssh_operations(global_ip, key_pair_name, sudo_password, "/main_elk.py", "/home/ubuntu/test1.py")

    print("main file took to execute: ", time.time()-start_time, " S")  # about 10 minutes +-


if __name__ == "__main__":
    main()


"""
If getting this error:
"paramiko.ssh_exception.SSHException: Channel closed."  -
try to reboot the new ec2 instance (it's IP and ID printed here)
"""

"""
rarely getting this error, but if:
Error: An error occurred (InvalidVolume.ZoneMismatch) when calling the AttachVolume operation: The volume 
'vol-*****************' is not in the same availability zone as instance 'i-****************'
solve: change AZ in creator file to one of: "us-east-a" or "us-east-b" or "us-east-c".
if still get this error, add large amount of sleep before the volume attaching things.
"""

