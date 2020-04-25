#!/usr/bin/env python3

'''
Author: Nik Alleyne
Author Blog: www.securitynik.com
Date: 2020-03-10
File: checkTshark.py
'''

__author__ = 'Nik Alleyne'
__contact__ = 'nikalleyne at gmail dot com'
__version__ = '1.0'
__status__ = 'Development'
__date__ = '2020-04-20'

import configparser as cfgP
import os
import subprocess as sp
import sys
import time
from signal import (signal, SIGINT)

# Configuration file path
config_file = './pktIntel.conf'

# Catch CTRL+C
def handler(signal_received, frame):
    print('[*] CTRL+C detected Exiting Gracefully.')
    sys.exit(0)

# Store the basic information for the config file
def pkt_ini():
    pkt_config = cfgP.ConfigParser()
    pkt_config.read(config_file)
    
    return pkt_config

# Check if TShark is inatalled
def verify_tshark_installed():
    print('[*] Checking for a TShark installation ...')
    time.sleep(2)
    check_tshark = sp.run(['which', 'tshark'], stdout=sp.PIPE)
    if ( check_tshark.returncode == 0):
        tshark_path = str(check_tshark.stdout).replace("b'", '').replace("\\n'", '')
        print(' [*] Found tshark: {}'.format(tshark_path))
    else:
        print('[*] TShark not found!')
        print('[*] Exiting!')
        sys.exit(-1)

# start TShark
def start_tshark():
    # Check for main section
    if (pkt_ini().has_section('MAIN')):
        print('      Main section found!')
    else:
        print('      Error default section not found!')
        sys.exit(-1)

    print('[*] Verifying PCAP directory exists in MAIN section ...')
    pcap_dir = pkt_ini()['MAIN']['pcap_dir']
    print('    PCAP directory reported as "{}"'.format(pcap_dir))
    print('[*] Starting TShark')
    print('[*] PCAPs are being written to {} folder!'.format(pcap_dir))

    print('\033[1;31;40m [*] Press CTRL+C to exit \033[1;31;0m')
    
    signal(SIGINT, handler)
    while True:
        '''
        perform continuous capture for files up to size 100M (100,000 Kb)
        Once the file gets to 100M rotate to a new pcap
        '''
        sp.call(['tshark', '--interface', 'any', '-w', pcap_dir + 'securitynik.pcap', '--ring-buffer', '--files:100', '--ring-buffer', 'filesize:100000', '--color', '--print'], stderr=sp.PIPE)

def main():
    sp.call('clear')
    print('--------------------------||' * 2)
    print(' checkTshark.py')
    print(' Tool used to perform threat intelligence against packet data')
    print(' Author: Nik Alleyne')
    print(' Author Blog: www.securitynik.com')
    print('--------------------------||' * 2)

    verify_tshark_installed()

    # Check permission. I need to be run as root or with UID=0
    print('[*] Checking your permission ...')
    time.sleep(2)
    if ( os.getuid() != 0):
        print('[*] Sorry you need to run me as root!')
        print('[*] Exiting ...')
        sys.exit(-1)

    print('[*] Running as {} with UID {} \n'.format(os.getlogin(), os.getuid()))
    print('[*] Checking if TShark is running ... ')
    tshark_process_running = sp.Popen('ps aux | grep tshark --only-matching', shell=True, stdout=sp.PIPE)
    tshark_process_running = tshark_process_running.stdout.read().decode('utf-8').split('\n')
    
    time.sleep(2)
    if (len(tshark_process_running) > 3):
        print('[*] Looks like TShark may be running already ')
    else:
        start_ts = input('[*] TShark is currently not running, start TShark?-  YES/NO: ').upper()
        if (start_ts == 'YES'):
            start_tshark()
        else:
            print('[*] Exiting ... ')
            sys.exit(0)
        
if __name__ == '__main__':
    main()
