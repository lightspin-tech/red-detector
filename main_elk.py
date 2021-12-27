import subprocess

# add pip installations via subprocess. probably need to obtain sudo pass for installing pip first:
try:
    output = subprocess.getoutput("sudo apt install python3-pip -y")
except Exception as e:
    print("pip error. need to install manually.")
    print(e)

import json
import uuid
import datetime
import socket
import os
import re
import glob
from requests import get

try:
    output = subprocess.getoutput("pip3 install boto3")
    import boto3
except Exception as e:
    import boto3
    print(e)

try:
    output = subprocess.getoutput("pip3 install ec2_metadata")
    import ec2_metadata
    #print(output)
except Exception as e:
    import ec2_metadata
    print("no ec2_metadata")

try:
    output = subprocess.getoutput("pip3 install elasticsearch")
    from elasticsearch import Elasticsearch
except Exception as e:
    from elasticsearch import Elasticsearch
    print("elasticsearch package error")
try:
    output = subprocess.getoutput("pip3 install art")
    from art import *  # the try here can crash so im importing in the except (for all)
except Exception as e:
    from art import *
    print(e)


def escape_ansi(line):
    """
    when running lynis, the output in the terminal is colored.
    when getting the data in python, there is a lot of unwanted  ANSI stuff (from the coloring)
    that this function removes.
    :param line: getting the "ruined" text
    :return: the "correct" text
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def vuls(vuls_root, sudo_password):
    print("in vuls function")
    data = {}
    vuls_scan = 'sudo docker run --rm \
        -v ~/.ssh:/root/.ssh:ro \
        -v $PWD:/vuls \
        -v $PWD/vuls-log:/var/log/vuls \
        -v /etc/localtime:/etc/localtime:ro \
        -v /etc/timezone:/etc/timezone:ro \
        vuls/vuls scan \
        -config=./config.toml # path to config.toml in docker'

    vuls_report = 'sudo docker run --rm \
        -v ~/.ssh:/root/.ssh:ro \
        -v $PWD:/vuls \
        -v $PWD/vuls-log:/var/log/vuls \
        -v /etc/localtime:/etc/localtime:ro \
        vuls/vuls report \
        -format-json \
        -config=./config.toml # path to report.toml in docker'
    commands = "cd /" + "; " + "cd " + vuls_root + "; " + sudo_password + vuls_scan
    output1 = subprocess.getoutput(commands)  # running the commands in the terminal and get the output.

    commands1 = "cd /" + ";" + "cd " + vuls_root + ";" + sudo_password + vuls_report
    output = subprocess.getoutput(commands1)
    # getting the data from the new json file:
    directory = "/" + vuls_root + "/results"
    command = sudo_password + " chmod 777 " + directory  # change before finish
    output = subprocess.getoutput(command)
    # we need the newest folder from the result folder:
    subfolders = [f.path for f in os.scandir(directory) if f.is_dir()]
    max = 0
    max_file = ""
    for i in subfolders:
        # print (i)
        temp = i
        i = i.replace(directory, "")
        i = i.replace("-", "")
        i = i.replace("/", "")
        i = i.replace(":", "")
        i = i.replace("+", "")
        i = i.replace("T", "")
        i = i.replace("Z", "")
        try:
            if int(i) > int(max):
                max = i
                max_file = temp
        except:
            max_file = temp
    command = sudo_password+" chmod 777 " + max_file
    output = subprocess.getoutput(command)

    json_file = glob.glob(max_file + "/*")[0]  # there is only one file in each folder.
    command = sudo_password + " chmod 777 " + json_file
    output = subprocess.getoutput(command)
    with open(json_file, 'r') as outfile:
        json_dict = json.loads(outfile.read())  # the json string
        # loading into variable pretty big json file (about 20000 lines) and not really need all of it.
    json_cves = json_dict["scannedCves"]

    # data = {}
    with open('cves.json', 'w') as outfile:
        outfile.write("")
    for cve_name in json_cves:
        data = json_cves[cve_name]
        with open('cves.json', 'a') as outfile:
            outfile.write(json.dumps(data) + "\n")


def chkrotkit(sudo_password):
    print("in chkrootkit function")
    second_command = sudo_password + " sudo chkrootkit -r /newvolume1"
    commands = "cd /" + ";" + second_command
    output_rootkit = subprocess.getoutput(commands)  # getting the output from the terminal
    # cleaning the output from the terminal and prepare it fot json-ing.
    text = output_rootkit
    # strings to remove:
    chkrotkit_strs = ["ROOTDIR is `/newvolume1/'", ", it may take a while", "Checking", "...", "", " `", "'"]
    for i in chkrotkit_strs:
        text = text.replace(i, "")
    text = text.split("\n")
    anomaly = "Searching for Ambients rootkit"
    anomaly1 = "Searching for suspicious files and dirs"
    data = {}
    index = 0
    mini_index = 1
    temp = ""

    with open('rootkit.json', 'w') as outfile:
        outfile.write("")
    for i in text:
        if "  " not in i and "/" in i:
            data = {"scanned file:": i}
            with open('rootkit.json', 'a') as outfile:
                outfile.write(json.dumps(data) + "\n")
            data = {}
        else:
            i = i.split("  ")
            # i eg: ['basename', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'not infected']
            for j in i:
                if anomaly in j or anomaly1 in j:
                    # pass ?
                    if anomaly in j:
                        # maybe calling a file or a user with this name will break the thing here.
                        j = j.split(anomaly)
                        data[anomaly] = j
                    else:
                        for k in text:
                            if "Searching" not in text[index + mini_index]:
                                temp = temp + text[index + mini_index] + ", "
                                text[index + mini_index] = ""
                                mini_index += 1

                            else:
                                break
                        data[anomaly1] = temp

                elif j != "" and j != i[0]:
                    if "infected" in j or "found" in j:
                        data[j] = i[0]
                        # print (data)
                        """
                        # to get rootkit as terminal:
                        data[i[0]] = j
                        # without the else below.
                        """
                    else:
                        data[i[0]] = j

            with open('rootkit.json', 'a') as outfile:
                if data != {}:
                    outfile.write(json.dumps(data) + "\n")
            data = {}
            index += 1


def lynis(directory, sudo_password):
    print("in lynis function")
    to_execute = ""
    """
    if cloned from their github:
    run it from the lynis dir: 
    sudo ./lynis audit system

    The git version gives a bit more output, I have a comparison in my email.
    """
    # run on the new root:
    command = """sudo chroot /newvolume1 /bin/bash <<"EOT"
sudo lynis audit system
echo $$
EOT"""
    # need to see how to eventually call the /newvolume1 above. maybe adding 1 or a random string is safer
    # for preventing overwrite (?)
    output = subprocess.getoutput(command)  # saving terminal's output

    commands = "cd /" + sudo_password + " lynis audit system"

    output_lynis = subprocess.getoutput(commands)  # saving terminal's output
    # text = output_lynis

    text = output
    escaped_line = escape_ansi(text)  # cleaning output from ANSI stuff.

    text = escaped_line
    text = text.split("Boot and services")  # first title, don't need the things before it.
    #  cleaning text and prepare to json-ing:
    text = text[1]
    text = text.replace("'", "")
    text = text.replace(".", "")
    text = text.replace("  ", "was empty")
    text = text.split("\n")
    title = "Boot and services"  # we deleted it earlier, this will be the first.
    data = {}
    with open('lynis.json', 'w') as outfile:
        outfile.write("")  # got to clean the file before appending.
    for line in text:
        line = line.replace("-", "")
        if "[+]" in line:
            title = line
        elif line != "":
            try:
                line = line.split("[")
                data["title"] = title.replace("[+]", "")
                line[1] = line[1].replace("]", "")
                data[line[0]] = line[1]

                with open('lynis.json', 'a') as outfile:
                    outfile.write(json.dumps(data) + "\n")
                data = {}
            except Exception as e:
                # print(e)
                pass


def send_json_to_elk(file_name, index_name, instance_id, time, account_id, session_id, type_of, es):
    """
    file got to be in ndjson format
    """
    try:
        jdoc = {"instance_id": instance_id, "time": time, "account_id": account_id,
                "session_id": session_id,
                "type_of_scan": type_of, "data": "later_in_loop"}
        with open(file_name) as fp:
            for line in fp:
                line = line.replace("\n", "")
                # line = line.replace(" ", "")
                line = line.strip()
                # jdoc = {"hostname": hostname, "ipaddr": ipaddr, "type": type_of, "data": json.loads(line)}
                if type_of != "lynis":
                    jdoc["data"] = json.loads(line)
                else:
                    # lynis:
                    # need to break the title thing:
                    json_line = json.loads(line)
                    title = json_line["title"]
                    json_line.pop("title")
                    jdoc = {"instance_id": instance_id, "time": time, "account_id": account_id,
                            "session_id": session_id,
                            "type_of_scan": type_of, "title": title, title: json_line}  # about "title":title
                es.index(index=index_name, doc_type='_doc', body=jdoc)

        print("finished upload: " + index_name)
    except Exception as e:
        print(e)


def main():
    # tprint("ELK    EC2    SCAN")
    """
    link = input("insert your ELK URL (e.g: localhost:9200) : ")
    username = input("insert your Elk username for auth(if there is no auth, click ENTER): ")

    # (?) need to get the directories too (vuls and lynis), sudo password

    if username != "":
        password = input("insert your Elk password for auth: ")
        elastic = Elasticsearch([link], http_auth=(username, password))
    else:
        elastic = Elasticsearch([link])
    ACCESS_KEY = input("insert your AWS_ACCESS_KEY: ")
    SECRET_KEY = input("insert your AWS_SECRET_KEY: ")
    print("")
    
    link = "localhost:9200"
    username = "elastic"
    password = "changeme"
    """
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--elastic_user_name', type=str, required=True)
    parser.add_argument('--elastic_password', type=str, required=True)
    parser.add_argument('--elastic_url', type=str, required=True)
    parser.add_argument('--type_of_scan', type=str, required=True)
    args = parser.parse_args()

    link = args.elastic_url
    username = args.elastic_user_name
    password = args.elastic_password
    type_of_scan = args.type_of_scan
    
    elastic = Elasticsearch([link], http_auth=(username, password))
    """
    print("running ...")

    # get IP:
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    sudo_pass = ''  # sudo password of the machine
    sudo_password = "echo " + sudo_pass + " | sudo -S "

    begin_time = datetime.datetime.now()

    vuls_directory = "home/ubuntu/vuls"  # vuls_directory = "home/ubuntu/vuls"
    lynis_directory = "home/ubuntu/lynis"  # don't really use it the function, explanation there.

    chkrotkit(sudo_password)
    print("finished rootkit")

    vuls(vuls_directory, sudo_password)
    print("finished vuls")

    lynis(lynis_directory, sudo_password)
    print("finished lynis")

    # get the public IP:
    public_ip = str(get('https://api.ipify.org').text)

    # get the instance_id:
    # instance_id = ec2_metadata.instance_id
    # uuid:
    uuid_string = str(uuid.uuid4())

    # timeStamp:
    date_and_hour = datetime.datetime.now()
    temp = str(date_and_hour).split(" ")
    date = temp[0]  # getting the date only without hours

    # need to fill this before running:
    # probably there is a way to get this data without filling.
    try:
        # ACCESS_KEY = ''
        # SECRET_KEY = ''
        iam = boto3.resource('iam',
                             aws_access_key_id=ACCESS_KEY,
                             aws_secret_access_key=SECRET_KEY,
                             )
        account_id = iam.CurrentUser().arn.split(':')[4]
    except Exception as e:
        account_id = "failed to get account_id"
    # all of the uploading take about 8 seconds:
    """
    send_json_to_elk("rootkit.json", "aws_rootkit_scan_", instance_id, date, account_id, uuid_string, "rootkit",
                     elastic)
    send_json_to_elk("cves.json", "aws_vuls_cves_scan_", instance_id, date, account_id, uuid_string, "vuls", elastic)
    send_json_to_elk("lynis.json", "aws_lynis_scan_", instance_id, date, account_id, uuid_string, "lynis", elastic)
    # how to see: in kibana -> settings -> index patterns -> create index pattern -> providing the names etc.
    """
    print("Elk file execution time took: ", datetime.datetime.now() - begin_time, " S to execute.")
    # locally about 2:30 minutes. less on ec2- about 1:30


if __name__ == "__main__":
    main()  # don't run this file directly

"""
mini tutorial before running :
- install Vuls with docker from: https://vuls.io/docs/en/tutorial-docker.html
- install chkrootkit: apt-get install chkrootkit
- install lynis: apt-get install lynis

- Helping with setting auth to ELK: https://github.com/deviantony/docker-elk

pip3 install:
boto3
art
ec2_metadata
elasticsearch
requests
datetime
re
"""
