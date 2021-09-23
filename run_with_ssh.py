import os
import paramiko

ec2_global_ip = ''
username = "ubuntu"
# transferring the file to the ec2:
ssh = paramiko.SSHClient()
privet_key = paramiko.RSAKey.from_private_key_file("/home/idan/idan-r.pem")
ssh.load_host_keys(os.path.expanduser(os.path.join("~", ".ssh", "known_hosts")))
ssh.connect(hostname=ec2_global_ip, username=username, pkey=privet_key)
sftp = ssh.open_sftp()
sftp.put("/home/idan/PycharmProjects/pythonProject/main.py", "/home/ubuntu/test3.py")
sftp.close()

# running the file:
stdin_, stdout_, stderr_ = ssh.exec_command("python3 test3.py", get_pty=True)  # put is writing over
stdout_.channel.recv_exit_status()
lines = stdout_.readlines()
for line in lines:
    print(line)
