import paramiko

hostname = 'example.com'
username = 'user'
password = 'password'

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

client.connect(hostname, username=username, password=password)

stdin, stdout, stderr = client.exec_command('ls')

for line in stdout:
    print(line.strip())

client.close()
