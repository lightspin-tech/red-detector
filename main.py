import boto3
from art import *

import create_ec2_instance
import create_snapshot


def main():
    art = text2art("cloud   scanner")
    print(art)
    print("            +++ WELCOME RED-SONAR -  CVE SCANNER USING VULS +++\n\n")

    region = create_snapshot.get_region()
    client = boto3.client('ec2', region_name=region)

    selected_ec2_vol_id = create_snapshot.select_ec2_instance(client)
    ss_volume_id, selected_az = create_snapshot.snapshot2volume(client, selected_ec2_vol_id)

    ec2_inst_id, instance_ip, rand_port = create_ec2_instance.create_ec2(client, selected_az, region)
    create_ec2_instance.attach_volume_to_ec2(client, ec2_inst_id, ss_volume_id)
    create_ec2_instance.scan_and_report(instance_ip, rand_port, ec2_inst_id)


if __name__ == "__main__":
    main()

