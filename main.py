import argparse
from art import text2art
import random
import boto3
from src.logger import setup_logger
from src.snapper import Snapper
from src.scanner import Scanner


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

    text_art = text2art("RED   DETECTOR")
    print(text_art)
    print("            +++ WELCOME RED-DETECTOR - CVE SCANNER USING VULS +++\n\n")

    cmd_args = parser.parse_args()
    logger = setup_logger(log_level=cmd_args.log_level)
    snapper = Snapper(logger=logger)
    if cmd_args.region:
        snapper.region = cmd_args.region
    else:
        snapper.region = snapper.select_region()

    snapper.create_client()

    if cmd_args.instance_id:
        source_volume_id = snapper.get_instance_root_vol(instance_id=cmd_args.instance_id)
    else:
        source_volume_id = snapper.select_ec2_instance()

    volume_id, selected_az, snapshot_id = snapper.snapshot2volume(volume_id=source_volume_id)

    if cmd_args.keypair:
        scanner = Scanner(logger=logger, region=snapper.region, key_pair_name=cmd_args.keypair)
    else:
        used_key_pairs_list = used_key_pairs()
        num = 0
        key_name = "red_detector_key{number}".format(number=str(num))
        while key_name in used_key_pairs_list:
            num += 1
            key_name = "red_detector_key{number}".format(number=str(num))


        scanner = Scanner(logger=logger, region=snapper.region, key_pair_name=key_name)
        scanner.keypair_name = scanner.create_keypair(key_name=key_name)

    ec2_instance_id, ec2_instance_public_ip, report_service_port = scanner.create_ec2(selected_az=selected_az)
    scanner.attach_volume_to_ec2(ec2_instance_id=ec2_instance_id, volume_id=volume_id)
    scanner.scan_and_report(ec2_instance_public_ip=ec2_instance_public_ip,
                            report_service_port=report_service_port, ec2_instance_id=ec2_instance_id,
                            snapshot_id=snapshot_id)
