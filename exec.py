import argparse
from art import text2art
import random
import boto3
import os
import glob
from src.logger import setup_logger
from src.snapper import Snapper
from src.scanner import Scanner


def getting_all_pem_file_names():
    """
    :return: .pem file names from the red-detector directory.
    """
    file_path = os.path.realpath(__file__)  # getting the script's path
    file_path = file_path.split("red-detector")
    files_path = file_path[0] + "red-detector"  # (the pem files arent in the same directory as the script.)

    lst = (glob.glob(files_path+"/*.pem"))
    index = 0
    for i in lst:
        lst[index] = lst[index].replace(files_path+"/", "").replace(".pem","")
        index += 1
    return lst


def used_key_pairs():
    keypairs = []  # list of used keyPair names
    ec2 = boto3.client('ec2')
    response = ec2.describe_key_pairs()

    for i in response["KeyPairs"]:
        keypairs.append(i["KeyName"])
    return keypairs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', action='store', dest='region', type=str,
                        help='region name', required=False)
    parser.add_argument('--instance-id', action='store', dest='instance_id', type=str,
                        help='EC2 instance id', required=False)
    parser.add_argument('--keypair', action='store', dest='keypair', type=str,
                        help='existing key pair name', required=False)
    parser.add_argument('--log-level', action='store', dest='log_level', type=str,
                        help='log level', required=False, default="INFO")

    cmd_args = parser.parse_args()
    logger = setup_logger(id=cmd_args.instance_id,log_level=cmd_args.log_level)
    snapper = Snapper(logger=logger)
    if cmd_args.region:
        snapper.region = cmd_args.region
    else:
        snapper.region = snapper.select_region()

    snapper.create_client()

    if cmd_args.instance_id:
        try:
            source_volume_id = snapper.get_instance_root_vol(instance_id=cmd_args.instance_id)
        except Exception as e:
            print(e, " : (probably problem with the given instance id or internet connection)")
            exit(99)
    else:
        source_volume_id = snapper.select_ec2_instance()

    volume_id, selected_az, snapshot_id = snapper.snapshot2volume(volume_id=source_volume_id)

    if cmd_args.keypair:
        scanner = Scanner(logger=logger, region=snapper.region, key_pair_name=cmd_args.keypair)
    else:
        used_key_pairs_list_from_aws = used_key_pairs()
        used_key_pairs_list_locally = getting_all_pem_file_names()
        num = 0
        key_name = "red_detector_key{number}".format(number=str(num))
        while key_name in used_key_pairs_list_from_aws or key_name in used_key_pairs_list_locally:
            num += 1
            key_name = "red_detector_key{number}".format(number=str(num))

        scanner = Scanner(logger=logger, region=snapper.region, key_pair_name=key_name)
        scanner.keypair_name = scanner.create_keypair(key_name=key_name)

    ec2_instance_id, ec2_instance_public_ip, report_service_port = scanner.create_ec2(selected_az=selected_az)
    scanner.attach_volume_to_ec2(ec2_instance_id=ec2_instance_id, volume_id=volume_id)
    scanner.scan_and_report(ec2_instance_public_ip=ec2_instance_public_ip,
                            report_service_port=report_service_port, ec2_instance_id=ec2_instance_id,
                            snapshot_id=snapshot_id)
