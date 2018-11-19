#!/usr/bin/env python
import time

import paramiko
import subprocess
import os
import sys
import fnmatch
import mac2ip
from scp import SCPClient
from shutil import copyfile
import multiprocessing
import traceback
from io import StringIO

#  sudo ip neigh flush all
#  fping -c 1 -g ip/24 && arp -n

mac_addr_prefix = ['9c:65:f9', '']


def current_path():
    return os.path.dirname(os.path.abspath(__file__))


def list_bin(path):
    return fnmatch.filter(os.listdir(path), '*.bin')


def query_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,"no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


# Define progress callback that prints the current percentage completed for the file
def _file_transfer_progress(filename, size, sent):
    print("%s\'s progress: %.2f%%   \r" % (filename.decode('ascii'), float(sent)/float(size)*100), end='')


def _exec(_client, comm):
    stdin, stdout, stderr = _client.exec_command(comm)
    print(stdout.read().decode('ascii').strip("\n"))
    print(stderr.read().decode('ascii').strip("\n"))
    print('-' * 87)


def upgrade(_filename, host, _script, pkey):
    print('Task {0} pid {1} is running, parent id is {2}'.format(host, os.getpid(), os.getppid()))
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, port=22, username='root', password='password')
        except paramiko.ssh_exception.AuthenticationException:
            rsa = paramiko.RSAKey.from_private_key(StringIO(pkey))
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, port=22, username='root', pkey=rsa, password='password')

        with SCPClient(ssh.get_transport(), progress=_file_transfer_progress) as scp:
            scp.put(_script, '/tmp/upgrade.sh')
            scp.put(_filename, '/tmp/' + _filename)
            scp.close()

        _exec(ssh, 'chmod a+x /tmp/upgrade.sh')
        _exec(ssh, '/tmp/upgrade.sh > /dev/null 2>&1 &')

        ssh.close()
    except paramiko.ssh_exception.AuthenticationException:
        print('password or ssh login fail.')

    return 'connect fail'


def handle_error(e):
    traceback.print_exception(type(e), e, e.__traceback__)


if __name__ == '__main__':

    scan_result = mac2ip.scan(mac2ip.get_host_ip() + '/24', mac_addr_prefix)
    mac2ip.print_result(scan_result)

    try:
        choice_target = int(input('\nWhich one device would you choose to upgrade? upgrade all please type zero(0): ').lower())
    except ValueError:
        exit(0)

    print(choice_target)

    bin_list = list_bin(current_path())

    for count, filename in enumerate(bin_list, start=1):
        print(' ' + str(count) + ')\t' + filename)

    try:
        choice = int(input('\nWhich one would you choose? : ').lower()) - 1
    except ValueError:
        exit(0)

    bin_file = ''

    if query_yes_no('Do you want to continue ? ' + bin_list[choice], 'yes'):
        bin_file = bin_list[choice]
    else:
        exit(0)

    copyfile('upgrade.sh', 'temp.sh')
    subprocess.Popen('echo sysupgrade --test /tmp/' + bin_file + ' >> ./temp.sh', shell=True, stdout=subprocess.PIPE)
    subprocess.Popen('echo sysupgrade -n /tmp/' + bin_file + ' >> ./temp.sh', shell=True, stdout=subprocess.PIPE)

    p = multiprocessing.Pool(len(scan_result))

    if choice_target == 0:
        for count, client in enumerate(scan_result, start=1):
            p.apply_async(upgrade, args=(bin_file, client["ip"], 'temp.sh', scan_result[choice_target-1]["pkey"]), error_callback=handle_error)
    else:
        p.apply_async(upgrade, args=(bin_file, scan_result[choice_target-1]["ip"], 'temp.sh', scan_result[choice_target-1]["pkey"]), error_callback=handle_error)

    p.close()
    p.join()

    try:
        os.remove('temp.sh')
    except os.NotImplementedError as e:
        pass
    exit(0)
