script_a = '''#!/bin/bash -ex
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

apt-get update
mkdir -p /home/ubuntu/vuls
cd /home/ubuntu/vuls
apt install docker.io -y 

docker pull vuls/go-cve-dictionary
docker pull vuls/goval-dictionary
docker pull vuls/gost
docker pull vuls/go-exploitdb
docker pull vuls/gost
docker pull vuls/vuls

PWD=/home/ubuntu/vuls/
for i in `seq 2002 $(date +"%Y")`; do \
    docker run --rm -i\
    -v $PWD:/vuls \
    -v $PWD/go-cve-dictionary-log:/var/log/vuls \
    vuls/go-cve-dictionary fetchnvd -years $i; \
  done

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-redhat 5 6 7 8

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-debian 7 8 9 10
    
docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-alpine 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-ubuntu 14 16 18 19 20

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-suse -opensuse 13.2

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-suse -suse-enterprise-server 12  

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-oracle 

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/goval-dictionary-log:/var/log/vuls \
    vuls/goval-dictionary fetch-amazon  

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/gost-log:/var/log/gost \
    vuls/gost fetch redhat

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/go-exploitdb-log:/var/log/go-exploitdb \
    vuls/go-exploitdb fetch exploitdb

docker run --rm -i \
    -v $PWD:/vuls \
    -v $PWD/go-msfdb-log:/var/log/go-msfdb \
    vuls/go-msfdb fetch msfdb
    
cat > config_scan.toml <<EOF
[servers]
[servers.host]
host        = "172.17.0.1"
port        = "2222"
user        = "root"
sshConfigPath = "/root/.ssh/config"
keyPath     = "/root/.ssh/id_rsa_vuls"
scanMode    = ["fast-root", "offline"]
EOF

cat > config_db.toml <<EOF
[cveDict]
type = "sqlite3"
SQLite3Path = "/vuls/cve.sqlite3"

[ovalDict]
type = "sqlite3"
SQLite3Path = "/vuls/oval.sqlite3"

[gost]
type = "sqlite3"
SQLite3Path = "/vuls/gost.sqlite3"

[exploit]
type = "sqlite3"
SQLite3Path = "/vuls/go-exploitdb.sqlite3"

[metasploit]
type = "sqlite3"
SQLite3Path = "/vuls/go-msfdb.sqlite3"
EOF

touch /tmp/userData.finished
'''

script_b = '''
set -ex

sudo mkdir -p /vol/
sudo mount {mount_point} /vol/

FILE="/vol/usr/sbin/sshd"
if [ -f "$FILE" ]; then
/bin/rm -f ~/.ssh/id_rsa_vuls
/bin/rm -f ~/.ssh/id_rsa_vuls.pub
ssh-keygen -q -f ~/.ssh/id_rsa_vuls -N ""
sudo cat ~/.ssh/id_rsa_vuls.pub > /tmp/tmp_authorized_keys
sudo mv /tmp/tmp_authorized_keys /vol/root/.ssh/tmp_authorized_keys
sudo chown root:root /vol/root/.ssh/tmp_authorized_keys 
sudo chmod 600 /vol/root/.ssh/tmp_authorized_keys

sudo mount -t proc none /vol/proc
sudo mount -o bind /dev /vol/dev
sudo mount -o bind /sys /vol/sys
sudo mount -o bind /run /vol/run

sudo chroot /vol /bin/mount devpts /dev/pts -t devpts
sudo su -c "chroot /vol /usr/sbin/sshd -p 2222 -o 'AuthorizedKeysFile=/root/.ssh/tmp_authorized_keys' -o 'AuthorizedKeysCommand=none' -o 'AuthorizedKeysCommandUser=none' -o 'GSSAPIAuthentication=no' -o 'UseDNS=no'"

echo "Creating ssh config"
sudo cat > ~/.ssh/config <<EOF
Host *
    StrictHostKeyChecking no
EOF

PWD=/home/ubuntu/vuls/
cd /home/ubuntu/vuls

echo "Scanning..."
sudo docker run --rm -i \
-v /home/ubuntu/.ssh:/root/.ssh:ro \
-v /home/ubuntu/vuls:/vuls \
-v /home/ubuntu/vuls/vuls-log:/var/log/vuls \
-v /etc/localtime:/etc/localtime:ro \
-v /etc/timezone:/etc/timezone:ro \
vuls/vuls scan \
-config=./config_scan.toml

echo "Creating report..."
sudo docker run --rm -i \
    -v /home/ubuntu/.ssh:/root/.ssh:ro \
    -v /home/ubuntu/vuls:/vuls \
    -v /home/ubuntu/vuls/vuls-log:/var/log/vuls \
    -v /etc/localtime:/etc/localtime:ro \
    vuls/vuls report \
    -format-list \
    -config=./config_db.toml

touch /tmp/script.finished
sudo pkill -9 -f "/usr/sbin/sshd -p 2222" & sudo umount /vol/proc  & sudo umount /vol/sys & sudo umount /vol/run & sudo umount /vol/dev/pts & sudo umount /vol/dev & sudo umount {mount_point}
fi
'''

script_c = '''
set -ex
echo "Starting report webUI..."

cd /home/ubuntu/vuls

sudo docker run -dt --name vuls-report-srv-{instance_id} \
    -v $PWD:/vuls \
    -p {port}:5111 \
    ishidaco/vulsrepo

echo "Check the report at: http://{ip_address}:{port}"
'''
