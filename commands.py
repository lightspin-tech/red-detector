import subprocess
import time
import json
import os

start_time = time.time()
command9 = "cd /home/ubuntu/vuls"  # vuls folder
new_vol_name = "newvolume1"
try:
    # get the new volume name:
    output = subprocess.getoutput("lsblk --json -fs")
    lsblk = json.loads(output)
    mount_dev = "/dev/xvdr1"  # prevent the maybe undefined.
    for item in lsblk["blockdevices"]:
        if item["fstype"] in ["ext2", "xfs", "ext3", "ext4"] and not (item['mountpoint']):
            mount_dev = f"/dev/{item['name']}"

    disk_name = str(mount_dev)
    commands = "cd /; sudo mkdir /"+new_vol_name+"/; sudo mount "+disk_name+" /"+new_vol_name+"/"
    output = subprocess.getoutput(commands)
    print("mount-ed the new volume")
except Exception as e:
    print("failed to mount the new volume:")
    print(e)
    # if it crashed: may ran this file before the creator.
    # means we try to mount a file that didn't even created.
try:
    command20 = """sudo mount -t proc none /{fname}/proc; 
sudo mount -o bind /dev /{fname}/dev; 
sudo mount -o bind /sys /{fname}/sys; 
sudo mount -o bind /run /{fname}/run""".format(fname=new_vol_name)
    output = subprocess.getoutput(command20)
except Exception as e:
    print("problem:")
    print(e)
try:
    command1 = "sudo apt-get update -y"
    output = subprocess.getoutput(command1)  # saving terminal's output
except Exception as e:
    print(e)

# chkrootkit:
try:
    command2 = "sudo apt-get install chkrootkit -y"
    output = subprocess.getoutput(command2)
    print("downloaded chkrootkit.")
    # activate by running "sudo chkrootkit" in terminal.
except Exception as e:
    print("problem with downloading chkrootkit:")
    print(e)

# lynis on the entire ec2:
try:
    command3 = "sudo apt-get install apt-transport-https -y"
    command4 = "sudo apt-get install lynis -y"
    output = subprocess.getoutput(command3)
    output = subprocess.getoutput(command4)
    # activate by running "sudo lynis audit system" in terminal
    print("downloaded lynis.")
except Exception as e:
    print("problem with downloading lynis:")
    print(e)
# lynis right to the new volume:
try:
    command21 = """sudo chroot /{fname} /bin/bash <<"EOT"
sudo apt-get install --fix-missing
sudo apt-get install apt-transport-https -y
sudo apt-get install lynis -y
echo $$
EOT""".format(fname=new_vol_name)
    output = subprocess.getoutput(command21)
except Exception as e:
    print("problem with installing lynis to the new root")
# vuls

# todo: develop the ssh into chrooted environment- will fix the issue with vuls. now vuls in scanning all of the ec2.
try:
    command5 = "sudo apt install docker.io -y"
    command6 = "sudo apt install docker -y"
    output = subprocess.getoutput(command5+"; "+command6)
    print("downloaded docker.")
except Exception as e:
    print("problem with downloading docker:")
    print(e)
try:
    command7 = "sudo docker pull vuls/go-cve-dictionary; " \
               "sudo docker pull vuls/goval-dictionary; " \
               "sudo docker pull vuls/gost; " \
               "sudo docker pull vuls/go-exploitdb;" \
               "sudo docker pull vuls/gost; " \
               "sudo docker pull vuls/vuls; "
    output = subprocess.getoutput(command7)
    print("pulled first vuls thing.")
except Exception as e:
    print("problem with pulling vuls things")
    print(e)
try:
    command8 = "mkdir /home/ubuntu/vuls"
    command10 = "mkdir go-cve-dictionary-log goval-dictionary-log gost-log go-exploitdb-log go-msfdb-log"
    output = subprocess.getoutput(command8+"; "+command9+"; "+command10)
except Exception as e:
    print("problem with creating vuls dirs:")
    print(e)

try:
    # that's taking a bit more than 5 minutes:
    
    command9 = "cd /home/ubuntu/vuls"
    command11 = "sudo docker run --rm -it \
        -v $PWD:/go-cve-dictionary \
        -v $PWD/go-cve-dictionary-log:/var/log/go-cve-dictionary \
        vuls/go-cve-dictionary fetch nvd"
    command12 = "sudo docker run --rm -it \
        -v $PWD:/goval-dictionary \
        -v $PWD/goval-dictionary-log:/var/log/goval-dictionary \
        vuls/goval-dictionary fetch ubuntu 20"
    command13 = "sudo docker run --rm -i \
        -v $PWD:/gost \
        -v $PWD/gost-log:/var/log/gost \
        vuls/gost fetch ubuntu"
    command14 = "sudo docker run --rm -i \
        -v $PWD:/go-exploitdb \
        -v $PWD/go-exploitdb-log:/var/log/go-exploitdb \
        vuls/go-exploitdb fetch exploitdb"
    command15 = "sudo docker run --rm -i \
        -v $PWD:/go-msfdb \
        -v $PWD/go-msfdb-log:/var/log/go-msfdb \
        vuls/go-msfdb fetch msfdb"
    output = subprocess.getoutput(command9+"; "+command11+"; "+command12+"; "+command13+"; "+command14+"; "+command15)
    print("fetched DBs")
    
except Exception as e:
    print("error fetching DBs")
    print(e)

try:
    command16 = "sudo echo | ssh-keygen -P ''"
    output = subprocess.getoutput(command9 + "; " + command16)  
    print("generated ssh key")
except Exception as e:
    print("problem with creating ssh key:")
    print(e)

try:
    # need to run it remotely on the chrooted environment. so the config file should be different.
    command17 = """cat > config.toml <<EOF
[servers]
[servers.localhost]
host = "localhost"
port = "local"

EOF
"""
    output = subprocess.getoutput(command9+"; "+command17)
    print("created config file")
except Exception as e:
    print(e)


print("commands took to execute: ", time.time()-start_time)  # about 6 minutes
