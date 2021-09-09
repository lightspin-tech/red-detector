import subprocess
import json
import datetime
import threading
import os
import re
import sys
from pprint import pprint
from elasticsearch import Elasticsearch
import time

es = Elasticsearch(
    'localhost:9200'
)
sudo_pass = 'Idan2408'  # sudo password of the machine
sudo_password = "echo " + sudo_pass + " | sudo -S "


def escape_ansi(line):
    """
    when running lynis, the output in the terminal is colored.
    when getting the data in python, there is a lot of unwanted  ANSI stuff that this function removes.
    :param line: getting the "ruined" text
    :return: the "correct" text
    """
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def vuls(vuls_root):
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
        -format-list \
        -config=./config.toml # path to report.toml in docker'
    sudo_password = "echo 'Idan2408' | sudo -S command"
    #  From what I understand, the line above is not supposed to work, but it is.
    #  So I don't touch it for now :)
    commands = ["cd /", "cd " + vuls_root, sudo_password,
                vuls_report]  # gotta check on "clean" machine the scan. may need to add few more commands.
    to_execute = ""  # the string that will run in the terminal at the end
    for i in commands:
        to_execute += i + ';'  # merging the commands into one line
    output = subprocess.getoutput(to_execute)  # running the commands in the terminal and get the output.
    # cleaning the data in order to get ndjson from the terminal output
    table = output.split("CVE-ID")[1]
    table = table.split("NVD")[1]
    table = table.split("|")
    table.remove(str(table[0]))
    table.remove(str(table[0]))
    index = 0
    # clean the file before running again, because we append:
    with open('cves.json', 'w') as outfile:
        outfile.write("")
    for i in table:
        """
        IMPORTANT FOR LATER:
        if vuls is getting updated, the code here may not clean as well as now, or even break.  
        used this:
        CVE_ID = "" # 0,8,16...
        CVSS = "" # 1 +8...
        FIXED = "" #5 +8 ...
        NVD = "" #6 +8... 
        """
        if index % 8 == 0 and "CVE" in table[index]:
            data = {
                "Cve": table[index],
                "Cvss": table[index + 1],
                "FIXED": table[index + 5],
                "NVD": table[index + 6]
            }
            # write from here the data to the file and \n
            with open('cves.json', 'a') as outfile:
                outfile.write(str(data) + "\n")
        index += 1



def chkrotkit():
    second_commnd = "chkrootkit"
    commands = ["cd /", sudo_password + " " + second_commnd]
    to_execute = ""  # the string that will run in the terminal at the end
    for i in commands:
        to_execute += i + ';'
    output_rootkit = subprocess.getoutput(to_execute) # getting the output from the terminal
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
                pass
                # this is stupid but helped to organize (the first if statement is pretty useless codewise.
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
            outfile.write(str(data) + "\n")
        data = {}
        index += 1


def lynis(directory):

    try_later_maybe = "export HISTIGNORE='*sudo -S*"
    to_execute = ""
    sudo_password = "echo 'Idan2408' | sudo -S"  # Idan2408 is the sudo password.
    commands = ["cd /", "cd " + directory, sudo_password, sudo_password + " ./lynis audit system"]
    for i in commands:
        to_execute += i + ';'

    output_lynis = subprocess.getoutput(to_execute) # saving terminal's output
    title = ""
    text = output_lynis

    escaped_line = escape_ansi(text)  # cleaning output from ANSI stuff. wasted a few hours here :(

    text = escaped_line
    text = text.split("Boot and services")  # need to look on original output to understand.
    #  cleaning text and prepare to json-ing:
    text = text[1]
    text = text.replace("'","")
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
                    outfile.write(str(data) + "\n")
                data = {}
            except Exception as e:
                # print e
                pass  # :)


def send_json_to_kibana(file_name, index_name):
    """
    file got to be in ndjson format
    """
    try:
        # Should include .json in file name.
        MyFile = open(file_name, 'r').read()
        ClearData = MyFile.splitlines(True)

        for line in ClearData:
            line = line.replace("\n", "")
            line = line.replace(" ", "")
            line = line.replace("'", '"')

            temp = json.loads(line)
            es.index(index=index_name, doc_type='_doc', body=temp)
        print("finished upload: " + index_name)
    except Exception as e:
        print(e)


def main():
    begin_time = datetime.datetime.now()
    # getting the date:
    date_and_hour = datetime.datetime.now()
    temp = str(date_and_hour).split(" ")
    date = temp[0] # getting the date only without hours

    vuls_directory = "home/idan/idannos"
    lynis_directory = "home/idan/lynis"

    # prepared threads for later, running takes a lot of time.
    # now it doesnt run in parallelity because of the .join()
    t_rootkit = threading.Thread(target=chkrotkit)
    t_rootkit.start()
    t_rootkit.join()

    t_vuls = threading.Thread(target=vuls, args=(vuls_directory,))
    t_vuls.start()
    t_vuls.join()

    t_lynis = threading.Thread(target=lynis,  args=(lynis_directory,))
    t_lynis.start()
    t_lynis.join()

    # well, sending the jsons to kibana:
    
    send_json_to_kibana("rootkit.json", "rootkit_scan_"+date)
    send_json_to_kibana("cves.json", "vuls_cves_scan_"+date)
    send_json_to_kibana("lynis.json", "vuls_cves_scan_"+date)
    # how to see then: in kibana -> settings -> index patterns -> create index pattern -> providing the names etc.
    
    print("Took: ", datetime.datetime.now() - begin_time, " to execute.")  # about 2:30 minutes


if __name__ == "__main__":
    main()

"""
For later:
- need to check problems with file names- it can break the program. especially with the splits.
- The program will install the vuls, chkrootkit and lynis automatically. with sudo password provided
- Check if the Jsons are valid and usable. I'm not sure but it will be a quick fix.
"""
