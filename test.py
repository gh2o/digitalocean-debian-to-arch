#!/usr/bin/env python3

import argparse
import datetime
import tempfile
import subprocess
import re
import json
import time
import socket
import os.path
import urllib.request
import urllib.error

scriptdir = os.path.dirname(os.path.realpath(__file__))

def log(*x):
    print(datetime.datetime.now(), ':', *x)

def doapi(token, path, args_or_method=None):
    if args_or_method is None:
        method = 'GET'
        data = None
    elif isinstance(args_or_method, dict):
        method = 'POST'
        data = json.dumps(args_or_method).encode()
    else:
        method = args_or_method
        data = None
    req = urllib.request.Request(
        url='https://api.digitalocean.com' + path,
        method=method,
        data=data,
        headers={
            'Authorization': 'Bearer {}'.format(token),
            'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as hnd:
        res = hnd.read().decode()
        if res:
            return json.loads(res)
        else:
            return None

def waitssh(ipaddr):
    log('Waiting for SSH ...')
    sshup = False
    while not sshup:
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((ipaddr, 22))
            sshup = True
        except OSError:
            pass
        finally:
            sock.close()
        time.sleep(5)

def main(args):
    # parse args
    parser = argparse.ArgumentParser(description='tests the install script')
    parser.add_argument('access_token', help='DigitalOcean API access token')
    args = parser.parse_args(args)
    token = args.access_token
    # check the token
    log('Validating access token ...')
    try:
        doapi(token, '/v2/droplets')
    except urllib.error.URLError:
        log('Token is invalid.')
        raise SystemExit
    # create tempdir
    tempdir = tempfile.TemporaryDirectory()
    tempname = re.sub(r'[^A-Za-z0-9]+', '-', tempdir.name)
    # generate a key
    log('Generating SSH key ...')
    subprocess.check_call(['ssh-keygen', '-f', tempdir.name + '/key', '-N', '', '-q'])
    # add the key
    log('Adding key ...')
    keyid = doapi(token, '/v2/account/keys', {
        'name': tempname,
        'public_key': open(tempdir.name + '/key.pub').read()
    })['ssh_key']['id']
    # create new droplet
    log('Creating droplet ...')
    dropid = doapi(token, '/v2/droplets', {
        'name': tempname,
        'region': 'sfo1',
        'size': '512mb',
        'image': 'debian-7-0-x64',
        'ssh_keys': [keyid]
    })['droplet']['id']
    # wait for completion
    completed = False
    while not completed:
        time.sleep(5)
        result = doapi(token, '/v2/droplets/{}/actions'.format(dropid))
        completed = all(x['status'] == 'completed' for x in result['actions'])
    # get ip address
    v4nets = doapi(token, '/v2/droplets/{}'.format(dropid))['droplet']['networks']['v4']
    ipaddr = next(x['ip_address'] for x in v4nets if x['type'] == 'public')
    # wait for SSH to start
    waitssh(ipaddr)
    # run the script
    commonsshargs = [
        'ssh',
        '-i', tempdir.name + '/key',
        '-o', 'StrictHostKeyChecking=no',
        'root@{}'.format(ipaddr)]
    log('Running script ...')
    with open(scriptdir + '/install.sh', 'rb') as scr:
        subprocess.check_call(
            commonsshargs + ['cat > install.sh && yes "" | bash install.sh'],
            stdin=scr)
    # wait for SSH to restart
    time.sleep(5)
    waitssh(ipaddr)
    # check for /etc/arch-release
    try:
        subprocess.check_call(commonsshargs + ['cat /etc/arch-release'])
        success = True
    except subprocess.CalledProcessError:
        success = False
    # cleanup
    if success:
        log('>>> SUCCESS! Deleting droplet... <<<')
        doapi(token, '/v2/droplets/{}'.format(dropid), 'DELETE')
    else:
        log('>>> FAILURE! Droplet saved for analysis. Remember to delete it to avoid charges. <<<')
    doapi(token, '/v2/account/keys/{}'.format(keyid), 'DELETE')

if __name__ == '__main__':
    import sys
    try:
        main(sys.argv[1:])
    except SystemExit:
        sys.exit(1)
