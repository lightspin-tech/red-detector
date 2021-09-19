import subprocess  # probably for python 3 only.
import json
import datetime
import threading
import socket
import os
import urllib.request
import re
import sys
from requests import get
import requests
import boto3
from ec2_metadata import ec2_metadata
import uuid
import datetime
from pprint import pprint
from elasticsearch import Elasticsearch
import time

es = Elasticsearch(
    'localhost:9200'
)


def escape_ansi(line):
    """
    when running lynis, the output in the terminal is colored.
    when getting the data in python, there is a lot of unwanted  ANSI stuff that this function removes.
    :param line: getting the "ruined" text
    :return: the "correct" text
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def vuls(vuls_root, sudo_password,server_):
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
    # sudo_password += sudo_password+ " command"

    commands = ["cd /", "cd " + vuls_root, vuls_scan]
    to_execute = ""  # the string that will run in the terminal at the end
    for i in commands:
        to_execute += i + ';'  # merging the commands into one line
    output1 = subprocess.getoutput(to_execute)  # running the commands in the terminal and get the output.
    # running the scan and then the report- in order to get just the report output.
    commands = ["cd /", "cd " + vuls_root,  vuls_report]
    to_execute = ""
    for i in commands:
        to_execute += i + ';'
    output = subprocess.getoutput(to_execute)
    # getting the data from the new json file:
    directory = "/" + vuls_root + "/results"
    output = subprocess.getoutput(sudo_password + " chmod -R 777 " + directory)  # giving access
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
        # print (i)
        try:
            if int(i) > int(max):
                max = i
                max_file = temp
        except:
            max_file = temp

    json_file = max_file + "/"+server_+".json"
    with open(json_file, 'r') as outfile:
        json_dict = json.loads(outfile.read())  # the json string
    json_cves = json_dict["scannedCves"]
    data = {}
    with open('cves.json', 'w') as outfile:
        outfile.write("")
    for cve_name in json_cves:
        data = json_cves[cve_name]
        with open('cves.json', 'a') as outfile:
            outfile.write(json.dumps(data) + "\n")


def chkrotkit(sudo_password):
    second_commnd = "sudo chkrootkit"
    commands = ["cd /", second_commnd]
    to_execute = ""  # the string that will run in the terminal at the end
    for i in commands:
        to_execute += i + ';'
    output_rootkit = subprocess.getoutput(to_execute)  # getting the output from the terminal
    # cleaning the output from the terminal and prepare it fot json-ing.
    text = output_rootkit
    text = text.replace("ROOTDIR is `/'", "")
    text = text.replace("Checking", "")
    text = text.replace(", it may take a while", "")
    text = text.replace("...", "")
    text = text.replace("", "")
    text = text.replace(" `", "")
    text = text.replace("'", "")
    text = text.split("\n")
    anomaly = "Searching for Ambients rootkit"
    anomaly1 = "Searching for suspicious files and dirs"
    # got to check how it looks when the thing detecting something.
    data = {}
    index = 0
    mini_index = 1
    temp = ""

    with open('rootkit.json', 'w') as outfile:
        outfile.write("")
    for i in text:
        i = i.split("  ")
        # i eg: ['basename', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', 'not infected']
        for j in i:

            if anomaly in j or anomaly1 in j:
                # pass ?
                if anomaly in j:
                    # maybe calling a file or user this name will break the program.
                    j = j.split(anomaly)
                    data[anomaly] = j
                else:
                    for k in text:
                        if "Searching" not in text[index + mini_index]:
                            temp = temp + text[index + mini_index] + ", "
                            text[index + mini_index] = ""
                            mini_index += 1
                            # print "here"

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
            outfile.write(json.dumps(data) + "\n")
        data = {}
        index += 1


def lynis(directory, sudo_password):
    to_execute = ""
    commands = ["cd /",  "sudo lynis audit system"]
    for i in commands:
        to_execute += i + ';'

    output_lynis = subprocess.getoutput(to_execute)  # saving terminal's output
    title = ""
    text = output_lynis

    escaped_line = escape_ansi(text)  # cleaning output from ANSI stuff. wasted a few hours here :(

    text = escaped_line
    text = text.split("Boot and services")  # need to look on original output to understand.
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
                # print line
                line = line.split("[")
                # line = line.split(":")
                # line = line.split("...")
                # print line
                data["title"] = title.replace("[+]", "")
                line[1] = line[1].replace("]", "")
                data[line[0]] = line[1]

                with open('lynis.json', 'a') as outfile:
                    outfile.write(json.dumps(data) + "\n")
                data = {}
            except Exception as e:
                # print e
                pass  # :)


def send_json_to_ELK(file_name, index_name,instance_id, time, account_id, session_id, type_of):
    """
    file got to be in ndjson format
    """
    try:
        with open(file_name) as fp:
            for line in fp:
                line = line.replace("\n", "")
                # line = line.replace(" ", "")
                line = line.strip()
                #jdoc = {"hostname": hostname, "ipaddr": ipaddr, "type": type_of, "data": json.loads(line)}
                if type_of!="lynis":
                    jdoc = {"instance_id": instance_id, "time": time, "account_id": account_id, "session_id": session_id,
                            "type_of_scan": type_of, "data": json.loads(line)}
                else:
                    # need to break the title thing:
                    json_line = json.loads(line)
                    title = json_line["title"]
                    json_line.pop("title")
                    jdoc = {"instance_id": instance_id, "time": time, "account_id": account_id, "session_id": session_id,
                            "type_of_scan": type_of, "title": title, title: json_line} # about "title":title
                es.index(index=index_name, doc_type='_doc', body=jdoc)

        print("finished upload: " + index_name)
    except Exception as e:
        print(e)


def main():
    # get IP:
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    # external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')

    sudo_pass = 'Idan2408'  # sudo password of the machine
    sudo_password = "echo " + sudo_pass + " | sudo -S "

    begin_time = datetime.datetime.now()

    vuls_directory = "home/ubuntu/idannos"
    lynis_directory = "home/idan/lynis"  # don't really use it the function

    chkrotkit(sudo_password)

    print("finished rootkit")
    host_in_config = "host"  # server.host_in_config
    vuls(vuls_directory, sudo_password, host_in_config)
    print("finished vuls")
    lynis(lynis_directory, sudo_password)
    print("finished lynis")

    # get the public IP:
    public_ip = str(get('https://api.ipify.org').text)

    # get the instance_id:
    instance_id = ec2_metadata.instance_id
    # uuid:
    uuid_string = str(uuid.uuid4())

    # timeStamp:
    date_and_hour = datetime.datetime.now()
    temp = str(date_and_hour).split(" ")
    date = temp[0]  # getting the date only without hours

    # account id:
    # from what I understood, getting the Account ID requires AWS_ACCESS_KEY_ID and an AWS_SECRET_KEY,
    # which is not reachable from just a python script(?). that means that the user will need to insert them manually?.
    # I don't know what the final plan- how will the user run it etc.
    # code for that from SO:

    # probably not a good idea to upload this data to github,
    # so need to fill this bedore running:
    ACCESS_KEY = ''
    SECRET_KEY = ''
    iam = boto3.resource('iam',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
    )
    account_id = iam.CurrentUser().arn.split(':')[4]

    # all of the uploadings take about 8 seconds:
    send_json_to_ELK("rootkit.json", "aws_rootkit_scan_3", instance_id, date, account_id, uuid_string ,"rootkit")
    send_json_to_ELK("cves.json", "aws_vuls_cves_scan_3", instance_id, date, account_id, uuid_string ,"vuls")
    send_json_to_ELK("lynis.json", "aws_lynis_scan_3", instance_id, date, account_id, uuid_string ,"lynis")
    # how to see: in kibana -> settings -> index patterns -> create index pattern -> providing the names etc.

    print("Took: ", datetime.datetime.now() - begin_time, " to execute.")  # about 2:30 minutes


if __name__ == "__main__":
    main()

"""
For later:
- need to check problems with file names- it can break the program. especially with the splits.
"""
# runned this.
