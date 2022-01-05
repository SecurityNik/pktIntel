#!/usr/bin/env python3

'''
Author: Nik Alleyne
Author Blog: www.securitynik.com
Date: 2020-03-10
Updated on: Dec 24, 2021.
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

# Verify capture tool installed
def verify_capture_tool_installed():
    capture_tool = 0
    global capture_tool_info
    capture_tool_info = {'tshark':[False, ""], 'tcpdump':[False, ""], 'dumpcap':[False, ""]}
    global tool_choice

    print('[*] Checking for an installed packet capturing tool, ie. tshark, tcpdump or dumpcap')
    time.sleep(2)

    check_tshark = sp.run(['which', 'tshark'], stdout=sp.PIPE)
    if ( check_tshark.returncode == 0):
        capture_tool_info['tshark'][0] = True
        capture_tool_info['tshark'][1] = str(check_tshark.stdout).replace("b'", '').replace("\\n'", '')

    check_tcpdump = sp.run(['which', 'tcpdump'], stdout=sp.PIPE)
    if ( check_tcpdump.returncode == 0):
        capture_tool_info['tcpdump'][0] = True
        capture_tool_info['tcpdump'][1] = str(check_tcpdump.stdout).replace("b'", '').replace("\\n'", '')

    check_dumpcap = sp.run(['which', 'dumpcap'], stdout=sp.PIPE)
    if ( check_tcpdump.returncode == 0):
        capture_tool_info['dumpcap'][0] = True
        capture_tool_info['dumpcap'][1] = str(check_dumpcap.stdout).replace("b'", '').replace("\\n'", '')

    print("-" * 50)
    print("Found the following capturing tools")
    print("Please select a number for a capturing tool")
    print("-" * 50)

    for key in capture_tool_info:
        capture_tool += 1
        print(f'{capture_tool} : Found { key } -> { capture_tool_info[key][0] } -> {capture_tool_info[key][1]} ')

    # Read which tool the user would like to capture with
    tool_choice = int(input("\n[*] Please select a number: "))    


def tshark():
    print('\033[1;31;40m [*] Press CTRL+C to exit \033[1;31;0m')
    print(f'[*] Capturing with tshark ...')
    while True:
        sp.call(['tshark', '-n', '--interface', 'any', '-w', pcap_dir + 'securitynik.pcap', '--ring-buffer', '--files:100', '--ring-buffer', 'filesize:100000', '--color', '--print'])

def tcpdump():
    print('\033[1;31;40m [*] Press CTRL+C to exit \033[1;31;0m')
    print(f'[*] Capturing with tcpdump ... ...')
    while True:
        sp.call(['tcpdump', '-n', '--interface', 'any', '-w', pcap_dir + 'securitynik.pcap', '-vv', '--number', '-C', '100', '-W', '100'])

def dumpcap():
    print('\033[1;31;40m [*] Press CTRL+C to exit \033[1;31;0m')
    print(f'[*] Capturing with dumpcap ...')
    while True:
        sp.call(['dumpcap', '--interface', 'any', '-w', pcap_dir + 'securitynik.pcap', '--ring-buffer', '--files:100', '--ring-buffer', 'filesize:100000','filename'])


# start TShark
def start_capturing():   
    global pcap_dir
    signal(SIGINT, handler)
    print('[*] Verifying PCAP directory exists in MAIN section ...')
    pcap_dir = pkt_ini()['MAIN']['pcap_dir']
    print('    PCAP directory reported as "{}"'.format(pcap_dir))

    '''
    perform continuous capture for files up to size 100M (100,000 Kb)
    Once the file gets to 100M rotate to a new pcap
    '''
    print('[*] PCAPs are being written to {} folder!'.format(pcap_dir))
    
    if ( ( tool_choice == 1 ) and ( capture_tool_info['tshark'][0] == True ) and ( capture_tool_info['tshark'][1] != "" ) ):
        tshark()
    elif ( ( tool_choice == 2 ) and ( capture_tool_info['tcpdump'][0] == True ) and ( capture_tool_info['tcpdump'][1] != "" ) ):
        tcpdump()
    elif ( ( tool_choice == 3 ) and ( capture_tool_info['dumpcap'][0] == True ) and ( capture_tool_info['dumpcap'][1] != "" ) ):
        dumpcap()
    
    else:
        print(f"\n[ERROR !] Sorry { tool_choice } is an invalid choice ")
        sys.exit(-1)


def main():
    sp.call('clear')
    print('--------------------------||' * 2)
    print(' checkTshark.py')
    print(' Tool used to perform threat intelligence against packet data')
    print(' Author: Nik Alleyne')
    print(' Author Blog: www.securitynik.com')
    print('--------------------------||' * 2)
    
   # Check permission. I need to be run as root or with UID=0
    print('[*] Checking your permission ...')
    time.sleep(2)
    if ( os.getuid() != 0):
        print('[*] Sorry you need to run me as root!')
        print('[*] Exiting ...')
        sys.exit(-1)

    print('[*] Running as {} with UID {} \n'.format(os.getlogin(), os.getuid()))

    # Check for main section
    if (pkt_ini().has_section('MAIN')):
        print('      Main section found!')
    else:
        print('      Error default section not found!')
        sys.exit(-1)
    
    verify_capture_tool_installed()
    start_capturing()
    
    sys.exit(0)

        
if __name__ == '__main__':
    main()
