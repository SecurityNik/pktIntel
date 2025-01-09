#!/usr/bin/env python3

import argparse
import configparser as cfgP
import glob
import ipaddress
import subprocess as sp
import os
import platform
import re
import sys
from signal import (signal, SIGINT)
import time
from urllib import request as url_request
from urllib.error import HTTPError, URLError

'''
Author: Nik Alleyne
Author Blog: www.securitynik.com
Date: 2020-05-08
File: pktIntel.py
'''

__author__ = 'Nik Alleyne - www.securitynik.com'
__contact__ = 'nikalleyne at gmail dot com'
__version__ = '1.0'
__status__ = 'Development'
__date__ = '2020-04-20'


# Configuration file path
config_file = './pktIntel.conf'

# Set HTTP Headers
http_header = {'User-Agent':'pktIntel.py - www.securitynik.com'}


# Catch CTRL+C
def handler(signal_received, frame): 
    print('[*] CTRL+C detected Exiting Gracefully.')
    sys.exit(0)


def check_tshark_installed():
    print('*' * 50)
    print('[*] TShark is needed for the analysis. Verifying it is installed  ... ')
    print('*' * 50)

    time.sleep(1)

    check_tshark = sp.run(['which', 'tshark'], stdout=sp.PIPE)
    if ( check_tshark.returncode == 0):
        print('   \\->> TShark found ...')
    
    else:
        print('\033[1;33;40m \\->> [!] Tshark NOT FOUND! Please install TShark and rerun this script \033[0m ')
        sys.exit(-1)
    

'''
This function deletes empty files and copies
previous files to a backup directory named pkt_backup
'''

def system_clean_up():
    # Folder to store backups
    pkt_backup = './pkt_backup'

    # Read the files in the directory for all that ends with .txt extension
    print('[*] Preparing to perform system cleanup')
    for txt_file in os.listdir():
        if (txt_file.endswith('.txt')):
            total_lines = sum(1 for line in open(txt_file, 'r'))
            if (total_lines == 1):
                # print('[-] Deleting empty files ....')
                try:
                    os.remove(txt_file)
                except OSError:
                    print('[!] Error removing files ')
                    pass
            else:
                sp.run(['mv', '--force', '--update',  txt_file, pkt_backup+'/'+txt_file])

    print('     System cleanup completed! ')
            

# Perform system checks
def system_checks():
    # Folder to store backups
    pkt_backup = './pkt_backup'

    print('[*] Checking system platform ...')
    if (platform.system() == 'Linux'):
        print('    Running on Linux. Good Start!')
    else:
        print('    WARNING! Not running on Linux. You may have to modify this code to suit your platform!')
    
    print('[*] Looking for backup directory \'pkt_backup\' in the current folder')
    if (os.path.exists(pkt_backup) and (os.path.isdir(pkt_backup))):
        print('     Found backup directory')
    else:
        print('[+] Backup directory not found creating it.')
        try:
            os.mkdir(pkt_backup)
            print('     [*] Directory successfuly created')
        except:
            print('     [!] Error occurred while creating backup directory.')
            print('     [*] Please create a directory named \'pkt_backup\' in the current directory.' )

    print('[*] Looking for config file ...')
    if (os.path.isfile(config_file)):
        print('    Config file "{}" found!'.format(config_file))
        time.sleep(2)
    else:
        print('    ERROR: Config file {} not found!'.format(config_file))
        print('    Exiting')
        sys.exit(0)

    time.sleep(2)


# Store the basic information for the config file
def pkt_ini():
    pkt_config = cfgP.ConfigParser()
    pkt_config.read(config_file)
    
    return pkt_config

# Validate config file has all the expected sections
def config_checks():
    print('[*] Validating configuration file ...')
    
    if (len(pkt_ini().sections()) != 6):
        print('    WARNING: Config does not seem to have the 6 sections expeected!')
        sys.exit(-1)

    # Check for default section
    if (pkt_ini().has_section('MAIN')):
        print('      Main section found!')
    else:
        print('      Error default section not found!')
        sys.exit(-1)

    # Checking for IP Section
    if (pkt_ini().has_section('IP')):
        print('      IP section found!')
    else:
        print('      ERROR: IP section not found! ')
        os.exit(-1)

    # Checking for domain Section
    if (pkt_ini().has_section('DOMAIN')):
        print('      DOMAIN section found!')
    else:
        print('      ERROR: Domain section not found! ')
        os.exit(-1)


    # Checking for monitored ports Section
    if (pkt_ini().has_section('URL')):
        print('      URL section found!')
    else:
        print('      ERROR: URL Section not found! ')
        os.exit(-1)


    # Checking for monitored ports Section
    if (pkt_ini().has_section('MONITORED_PORTS')):
        print('      Monitored Ports section found ...')
    else:
        print('      ERROR: Monitored Ports Section not found! ')
        os.exit(-1)


    print('    Configuration file successfully validated!')
    time.sleep(2)
    

# Verify the path of the PCAP directory
def verify_pcap_path():
    print('[*] Verifying PCAP directory exists in MAIN section...')
    pcap_dir = pkt_ini()['MAIN']['pcap_dir']
    print('    PCAP directory reported as "{}"'.format(pcap_dir))

    ''' 
    Count the number of PCAP files reported. 
    These files MUST have a .cap, .pcap or .pcapng extension
    '''
    time.sleep(2)
    print('    Counting the number of files with .cap, .pcap or .pcapng extension')
    print('      Number of PCAPs found: {}'.format(len(glob.glob(pcap_dir + '*.*cap*', recursive=True))))
    

# Download IP Threat Intelligence Information
def ip_intel_download():
    time.sleep(2)
    #ip_list = []
    tshark_dst_ips = []
    suspicious_ips = []
    malicious_ips = []
    malicious_ips_file = 'malicious_ips.csv'
    ipv4_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_threat_fp = open('./ip_threat_intel_'+time.strftime('%Y-%m-%dT%H-%M-%S')+'.txt', 'a')
    ip_threat_fp.write('IP Address              PCAP File \n')
    ipv4_threat_session = open('./IPv4_session_'+time.strftime('%Y-%m-%dT%H-%M-%S')+'.txt', 'a')
    ipv4_threat_session.write('frame.number \t\t frame.time \t\t ip.src   tcp.srcport    ip.dst   tcp.dstport   frame.len  ip.len \n')
    # Because subprocess will write above the previous line, I need to perform a flush
    ipv4_threat_session.flush()

    ipv6_threat_session = open('./IPv6_session_'+time.strftime('%Y-%m-%dT%H-%M-%S')+'.txt', 'a') 
    ipv6_threat_session.write('frame.number        frame.time          ipv6.src          tcp.srcport         ipv6.dst      tcp.dstport   frame.len    ip6.plen \n')
    ipv6_threat_session.flush()
    
    # Regex pattern for IPv6 borrowed :-) from https://www.regextester.com/25
    ipv6_pattern = re.compile(r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')

    pcap_dir = pkt_ini()['MAIN']['pcap_dir']
    
    print('[*] Beginning IP Threat Intelligence ...')
    for ip_url in pkt_ini().get('IP', 'ip_urls').split('\n'):
        ip_request = url_request.Request(ip_url, headers=http_header, method='GET')
        print('    Downloading IP blocklist from: {}'.format(ip_url))
        
        try:
        
            with url_request.urlopen(ip_request) as url_response:
                blacklisted_ips = list(str(url_response.read()).split('\\n'))
                malicious_ips.append(blacklisted_ips)
        except HTTPError as e:
            pass
 
        except (HTTPError, URLError) as e:
            print('     Looks like an issues was encountered. \n       {}'.format(e.reason))
        
        else:
            print('     Successfully downloaded IP Threat Intelligence')
    
    
    # Since the data came in as list of list, flatten to a single list
    malicious_ips = [ips for item in malicious_ips for ips in item]

    
    # Remove duplicates from the list
    print('[*] Removing duplicates from the downloaded IPs ...')
    malicious_ips = list(set(malicious_ips))

    # Remove some unwanted characters
    malicious_ips = [ips.strip('\\r') for ips in malicious_ips]
    #print('[*] Here is your list of malicious IPs \n{}'.format(malicious_ips))
    print('[*] There are currently \033[1;31;40m [{}] unique suspicious IPs \033[0m downloaded!'.format(len(malicious_ips)))

    print(f'[*] Writing all malicious IPs to {malicious_ips_file} file ')
    tmp_ips = re.findall(pattern=r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', string= f'{malicious_ips}\n')
    with open(file=malicious_ips_file, mode='w') as malicious_ips_fp:
        malicious_ips_fp.write('IP Address \n')
        for ip in tmp_ips:
            malicious_ips_fp.write(ip+'\n')    

    # Run TShark against each of the PCAPS found
    print('[*] Reading PCAP files ...')
    print('     Looking for TCP packets where ONLY the SYN flag is set.')
    print('     Also looking at UDP and ICMP packets')
    print('     By looking at the SYN flag, we are assuming the the 3-way handshake has started')
    
    print('\n[*] Note I may take a while so work with me on this ...')
    '''
        Note to reduce the noise you may instead choose to track the PUSH flag. To do so use:
        tcp.flags.push == 1"
    '''
    for pcap_file in glob.glob(pcap_dir + '*.*cap*'):
        if ( os.access(pcap_file, os.R_OK)): 
            check_tshark_output = sp.check_output(['tshark', '-n', '-r', pcap_file, '-Y', "(((tcp.flags.syn == 1) && !(tcp.flags.ack == 1)) || (udp) || (icmp))"'', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst'], stderr=sp.PIPE)
            check_tshark_output_ip6 = sp.check_output(['tshark', '-n', '-r', pcap_file, '-Y', "(((tcp.flags.syn == 1) && !(tcp.flags.ack == 1)) || (udp) || (icmpv6))"'', '-T', 'fields', '-e', 'ipv6.src', '-e', 'ipv6.dst'], stderr=sp.PIPE)
            # For each destination IPv4, append it to the list
            for dst_ip in str(check_tshark_output).split('\\n'):
                tshark_dst_ips.append(dst_ip)

        # For each destination IPv6, append it to the list
            for dst_ip6 in str(check_tshark_output_ip6).split('\\n'):
                tshark_dst_ips.append(dst_ip6)
        else:
            print('    \033[1;33m;40m [*] Unable to read the file: {}'.format(pcap_file))
            print('   [*] Check the file permission. \033[1;33m;0m')
    
    # print('[*] Clearning up the TShark destination IPs, removing unwanted characters ...')
    tshark_dst_ips = [ip.strip("b'") for ip in tshark_dst_ips]
    tshark_dst_ips = [ip.split('\\t') for ip in tshark_dst_ips]
    
    #print('[*] Flattening the list of lists ...')
    tshark_dst_ips = [ips for item in tshark_dst_ips for ips in item]

    # Remove empty strings
    tshark_dst_ips = ' '.join(tshark_dst_ips).split()

    #print('[*] TShark Destination IPs with PUSH flag set \n{}'.format(tshark_dst_ips))
    print('[*] Comparing downloaded IPs with those in your PCAPs ...')

    time.sleep(2)
    suspicious_ips = set(tshark_dst_ips) & set(malicious_ips)

    # Remove those entries from the list that are empty
    suspicious_ips = ' '.join(suspicious_ips).split()
    if (len(suspicious_ips) == 0):
        print('  \033[0;32;40m [*] Lucky you! Nothing malicious being reported at this time!')
        print('   [*] Do try me again soon. I may have one or more interesting IPs next time.') 
        print('       I promise :-) \033[0m')
    else:
        print('\n\033[1;31;40m----- {} SUSPICIOUS IPs DETECTED --------- \n{}\033[1;31;0m \n'.format(len(suspicious_ips), suspicious_ips))

        print('[*] Writing IP information to: \n   [./ip_threat_intel_2020-04-25T10:[{}|{}|{}]'.format(ip_threat_fp.name, ipv6_threat_session.name, ipv6_threat_session.name))
        
        # Read the pcap again, this time, matching on the particular communications and ports
        for pcap_file in glob.glob(pcap_dir + '*.*cap*'):
            print('[*] Reading PCAP File to extract session information: {}'.format(pcap_file))
            for ip in suspicious_ips:
                ipv4_address = re.findall(ipv4_pattern, ip)
                ipv6_address = re.findall(ipv6_pattern, ip)

                # Write IP information to text file
                ip_threat_fp.write(ip+'       {} \n'.format(pcap_file))
                
                # Check to see if the IP is an IPv4 address
                if ipv4_address:
                    #print('[*] Working with IPv4 addresses \n')
                    sp.call(['tshark', '-n', '-r', pcap_file, '-Y', 'ip.addr == '+ ip + '', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'tcp.srcport', '-e', 'ip.dst', '-e', 'tcp.dstport', '-e', 'frame.len', '-e', 'ip.len'], stdout=ipv4_threat_session, stderr=sp.PIPE)


                # Check to see if the IP is an IPv6 address
                elif ipv6_address: 
                    #print('[*] Working with IPv6 addresses \n')
                    sp.call(['tshark', '-n', '-r', pcap_file, '-Y', 'ipv6.addr == '+ ip + '', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ipv6.src', '-e', 'tcp.srcport', '-e', 'ipv6.dst', '-e', 'tcp.dstport', '-e', 'frame.len'], stdout=ipv6_threat_session, stderr=sp.PIPE)

                # Check here for any other strings
                else:
                    # Not sure what the hell this is
                    pass

    # close the file which contains the IP and session information
    print('\n[*] Closing the file {}'.format(ip_threat_fp.name))
    ip_threat_fp.close()

    print('[*] Closing the file {}'.format(ipv4_threat_session.name))
    ipv4_threat_session.close()
    
    print('[*] Closing the file {}'.format(ipv6_threat_session.name))
    ipv6_threat_session.close()

    print('[*] Completed IP Threat Intelligence Lookup!')

    print('[*] Happy Hunting! ...')
    sys.exit(0)


# Download Domain Threat Intelligence Information
def domain_intel_download():
    time.sleep(2)
    temp_list= []
    tshark_domains = []
    suspicious_domains = []
    malicious_domains = []
    dns_threat_fp = open('./dns_threat_intel_'+time.strftime('%Y-%m-%dT%H-%M-%S')+'.txt', 'a')
    dns_threat_fp.write('frame.number	frame.time	ip.src   srcport    ip.dst   dstport	dns.id   frame.len	ip.len	Name Information ')
    
    # Because subprocess will write above the previous line, I need to perform a flush
    dns_threat_fp.flush()

    # Regex courtesy of regexr.com/3au3g
    dns_pattern = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
    
    pcap_dir = pkt_ini()['MAIN']['pcap_dir']
    
    print('[*] Beginning DNS Threat Intelligence ...')
    
    for dns_url in pkt_ini().get('DOMAIN', 'blacklisted_domains').split('\n'):
        dns_request = url_request.Request(dns_url, headers=http_header, method='GET')
        print('    Downloading Domain blocklist from: {}'.format(dns_url))
        
        try:
            with url_request.urlopen(dns_request) as url_response:
                blacklisted_dns = list(str(url_response.read()).split('\\n'))
                malicious_domains.append(blacklisted_dns)
        except HTTPError as e:
            pass
 
        except (HTTPError, URLError) as e:
            print('     Looks like an issues was encountered. \n       {}'.format(e.reason))
        
        else:
            print('     Successfully downloaded DNS Threat Intelligence')

    # Flattening the list from a list of lists to a single list
    malicious_domains = [i for domain in malicious_domains for i in domain]
    
    # Look for the DNS patten
    for domain in malicious_domains:
        dns_domain = re.findall(dns_pattern, domain)
        temp_list.append(dns_domain)
    
    # Remove duplicates and create a new malicious_domains list
    malicious_domains = temp_list

    # Flattening the list from a list of lists to a single list
    malicious_domains = [i for domain in malicious_domains for i in domain]

    # Clear the temp list
    temp_list = []

    print('[*] Removing Duplicates from the downloaded domains ... ')
    malicious_domains = set(malicious_domains)
    # print('Here are the malicious domains downloaded: {}'.format(malicious_domains))
    print('[*] There are \033[1;31;40m {} domains \033[0m reported as malicious'.format(len(malicious_domains)))
    
       
    # Run TShark against each of the PCAPS found
    print('\n[*] Reading PCAP files ...')
    print('     Reading UDP|TCP destination port 53 query | http.host | tls.handshake.extensions_server_name ...')
    print('[*] Work with me here! This may take a while ...')
    for pcap_file in glob.glob(pcap_dir + '*.pcap*'):
        if ( os.access(pcap_file, os.R_OK)):
            '''
            Attackers cannot hide all their activities behind encryption
            Here we are reading the Server Name Information (SNI) Extension from
            the TLS Client Hello record
            '''

            check_tshark_output = sp.check_output(['tshark', '-n', '-r', pcap_file, '-Y', "((udp.dstport == 53) || (tcp.dstport == 53) && (dns.qry.type == 1)) || ((tcp.dstport == 80) && (http.request.method == 'GET') || (http.request.method == 'POST'))  || ((tcp.dstport == 443) && (tls.handshake.type == 1))"'', '-T', 'fields', '-e', 'dns.qry.name', '-e', 'http.host', '-e', 'tls.handshake.extensions_server_name'], stderr=sp.PIPE)
            
            tshark_domains.append(check_tshark_output)

        else:
            print(' \033[1;33m;40m [!] Unable to read the file: {}'.format(pcap_file))
            print('    [!] Please check the file permission. \033[0m')
    
    '''
    Tidying up the mess which was returned from reading the PCAP
    such as \\t\\t\\n, etc
    '''
    tshark_domains = [str(qry).replace('\\t\\t', '') for qry in tshark_domains]
    tshark_domains = [qry.split("\\n") for qry in tshark_domains if qry]
    tshark_domains = [name for query in tshark_domains for name in query]
    #print('[*] Here are the tshark domains {}'.format(tshark_domains))

    print('[*] Removing Duplicate entries from the list ... \n')
    
    # Check to see if malicious domains which were downloaded are part of the PCAPS
    suspicious_domains = set(malicious_domains) & set(tshark_domains)
    
    # Check the length of sucpicious domains to determine the response
    if (len(suspicious_domains) == 0):
        print('  \033[0;32;40m [*] Lucky you! Nothing malicious being reported at this time!')
        print('   [*] Do try me again soon. I may have one or more interesting Domains next time.') 
        print('       I promise :-) \033[0m')
    else:
        print('  \033[1;31;40m----- {} SUSPICIOUS DOMAINS DETECTED --------- \n{}\033[1;31;0m \n'.format(len(suspicious_domains), suspicious_domains))
        print('[*] Writing DNS Threat Intel information to {} files'.format(dns_threat_fp.name))
        
        # Read the suspicious_domains list and look for that name in the PCAP
        for domain in suspicious_domains:
            # print('[*] Suspicious Domain: {}'.format(domain))
            # Read the pcap again, this time, matching on the particular DNS communication
            for pcap_file in glob.glob(pcap_dir + '*.pcap*'):
                # Read the PCAPs again, looking for the information to fill out the session
                print('[*] Reading PCAP: {}'.format(pcap_file))
                sp.call(['tshark', '-r', pcap_file, '-Y', '((udp.dstport == 53) || (tcp.dstport == 53) && (dns.qry.name =="' + domain + '")) || http.host == "' + domain + '" || tls.handshake.extensions_server_name == "' + domain + '"', '-T', 'fields', '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'udp.srcport', '-e', 'tcp.srcport',  '-e', 'ip.dst', '-e', 'ipv6.dst', '-e', 'udp.dstport', '-e', 'tcp.dstport', '-e', 'dns.qry.name', '-e', 'http.host', '-e', 'tls.handshake.extensions_server_name'], stdout=dns_threat_fp, stderr=sp.PIPE)
    
    # close the file which contains the domain and session information
    print('[*] Closing the file {}'.format(dns_threat_fp.name))
    dns_threat_fp.close()
    print('[*] Completed DNS Threat Intelligence Lookup!')
    
    # Call system cleanup function

    print('[*] Happy Hunting...')
    sys.exit(0)


# Download URL Threat Intelligence Information
def url_intel_download():
    time.sleep(2)
    temp_list= []
    tshark_urls = []
    suspicious_urls = []
    malicious_urls = []
    url_threat_fp = open('./url_threat_intel_'+time.strftime('%Y-%m-%dT%H-%M-%S')+'.txt', 'a')
    url_threat_fp.write('frame.number	frame.time	ip.src	tcp.srcport  ip.dst	  tcp.dstport   http.request.full_uri        ip.len     tcp.len       \n')
    
    # Because subprocess will write above the previous line, I need to perform a flush
    url_threat_fp.flush()

    # Regex courtesy of https://regexr.com/3dm7s
    url_pattern = re.compile(r'http[s]?:\/\/(?:[a-z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-f][0-9a-f]))+')
    
    pcap_dir = pkt_ini()['MAIN']['pcap_dir']
    
    print('[*] Beginning URL Threat Intelligence ...')

    for url in pkt_ini().get('URL', 'urls').split('\n'):
        url_intel_request = url_request.Request(url, headers=http_header, method='GET')
        print('    Downloading URL blocklist from: {}'.format(url))
        
        try:
            with url_request.urlopen(url) as url_response:
                blacklisted_urls = list(str(url_response.read()).split('\\n'))
                malicious_urls.append(blacklisted_urls)
        except HTTPError as e:
            pass
 
        except (HTTPError, URLError) as e:
            print('     Looks like an issues was encountered. \n       {}'.format(e.reason))
        
        else:
            print('     Successfully downloaded DNS Threat Intelligence')

    # Flattening the list from a list of lists to a single list
    malicious_urls = [i for url in malicious_urls for i in url]
    
    for url_tmp in malicious_urls:
        url = re.findall(url_pattern, url_tmp)
        temp_list.append(url)

    # print('[*] Downloaded malicious URLs {}'.format(malicious_urls))
    # print('[*] Downloaded Temp List URLs {}'.format(temp_list))

    # Remove duplicates and create a new malicious_domains list
    malicious_urls = temp_list

    # Flattening the list from a list of lists to a single list
    malicious_urls = [i for urls in malicious_urls for i in urls]

    # Clear the temp list
    temp_list = []

    print('[*] Removing Duplicates from the downloaded URLs ... ')
    malicious_urls = set(malicious_urls)
    # print('{}'.format(malicious_urls))
    print('[*] There here are \033[1;31;40m {} unique URLs \033[0m reported as malicious '.format(len(malicious_urls)))
    
    # Run TShark against each of the PCAPS found
    print('\n[*] Reading PCAP files ...')
    print('[*] Looking for URLs ...')
    print('[*] Work with me here! This may take a while ...')
    for pcap_file in glob.glob(pcap_dir + '*.pcap*'):
        print('[*] Reading file: {}'.format(pcap_file))
        if ( os.access(pcap_file, os.R_OK)):
            check_tshark_output = sp.check_output(['tshark', '-n', '-r', pcap_file, '-Y', "(http)"'', '-T', 'fields', '-e', 'http.request.full_uri'], stderr=sp.PIPE)
            # print('[*] Here is the result from check_output \n{}'.format(check_tshark_output))
            tshark_urls.append(check_tshark_output)
        else:
            print('     \033[1;33;40m [!] Unable to read the file: {} \033[0m' .format(pcap_file))
            print('     \033[1;33;40m [!] Please check the file permission. \033[0m ')



    tshark_urls = tshark_urls
    # print('[*] Here are the TShark URIs found \n{}'.format(tshark_urls))
 
    # Remove empty items from the tshark_url list
    tshark_urls = [url for url in tshark_urls if url]
    # print('[*] Results from TShark urls \n{}'.format(tshark_urls))
    
    # Thanks to Vinamra Bhatnagar for help on this for loop to help with the flatten of this list of lists
    for url in tshark_urls:
        # Decode as UTF-8 and remove the '\n' character
        tmp = url.decode('utf-8').split('\n')
        # remote empty items 
        tmp = [url for url in tmp if url]
        temp_list.extend(tmp)

    url_domains = temp_list
    print('[*] Removing Duplicate entries from the list ...')
    # print('[*] Length of TShark URLs before duplication is: {}'.format(len(tshark_domains)))
    tshark_urls = set(temp_list)
    #print('[*] Here is the results from tshark_urls \n{}'.format(tshark_urls))
    
    # Check to see if malicious domains which were downloaded are part of the PCAPS
    suspicious_urls = malicious_urls & tshark_urls

    # Check the length of sucpicious domains to determine the response
    if (len(suspicious_urls) == 0):
        print('  \033[0;32;40m [*] Lucky you! Nothing malicious being reported at this time!')
        print('   [*] Do try me again soon. I may have one or more interesting URLs next time.') 
        print('       I promise :-) \033[0m')
    else:
        print('\n   \033[1;31;40m----- {} SUSPICIOUS URLS S DETECTED --------- \n{} \033[0m \n'.format(len(suspicious_urls), suspicious_urls))
        print('[*] Writing URL information to {} files'.format(url_threat_fp.name))
        
        # Read the suspicious_domains list and look for that name in the PCAP
        for url in suspicious_urls:
            # print('URL for you: {}'.format(url))

            # Read the pcap again, this time, matching on the particular DNS communication     
            for pcap_file in glob.glob(pcap_dir + '*.pcap*'):
#               print('[*] Reading PCAP File to extract session information: {}'.format(pcap_file))12.61.
                sp.call(['tshark', '-n', '-r', pcap_file, '-Y', '(http.request.full_uri == "'+ url + '")', '-T', 'fields', '-e', 'frame.number', '-e', 'frame.time', '-e', 'ip.src', '-e', 'tcp.srcport', '-e', 'ip.dst', '-e', 'tcp.dstport', '-e', 'http.request.full_uri', '-e', 'ip.len', '-e', 'tcp.len'], stdout=url_threat_fp, stderr=sp.PIPE)

    
    # close the file which contains the domain and session information
    print('[*] Closing the file {}'.format(url_threat_fp.name))
    url_threat_fp.close()
    print('[*] Completed URL Threat Intelligence Lookup!')
    print('[*] Happy Hunting...')
    sys.exit(0)


def main():
    '''   
    sp.call('clear')
    print('--------------------------||' * 2)
    print(' pktIntel.py')
    print(' Tool used to perform threat intelligence against packet data')
    print(' Author: Nik Alleyne')
    print(' Author Blog: www.securitynik.com')
    print('--------------------------||' * 2)

    print()
    '''
    # Add the various arguments for the command line
    argument_parser = argparse.ArgumentParser(usage='./pktIntel.py [ --ip | --dns | --url ]')
    argument_parser.add_argument('--ip', help='Download IP addresses based on information in the config file.', action='store_true')
    argument_parser.add_argument('--dns', help='Download domain addresses based on information in the config file.', action='store_true')
    argument_parser.add_argument('--url', help='Download URL addresses based on information in the config file.', action='store_true')
    argument_parser = argument_parser.parse_args()

    system_checks()
    config_checks()
    verify_pcap_path()
    system_clean_up()
    
    
    # Check if the argument entered is IP
    if (argument_parser.ip):
        ip_intel_download()

    # Check if the argument entered is domain
    elif (argument_parser.dns):
        domain_intel_download()

    # Check if the argument entered is URL
    elif (argument_parser.url):
        url_intel_download()

    else:
        print('[!] Error! Unknown Option. Usage \033[1;37;40m ./pktIntel.py [ --ip | --dns | --url] \033[0m')

    sys.exit()


if __name__ == '__main__':
    sp.call('clear')
    print('--------------------------||' * 2)
    print(' pktIntel.py')
    print(' Tool used to perform threat intelligence against packet data')
    print(' Author: Nik Alleyne')
    print(' Author Blog: www.securitynik.com')
    print('--------------------------||' * 2)

    # Check permission. 
    print('[*] Checking your permission ...')
    time.sleep(2)
    if ( os.getuid() != 0):
        print(' \033[1;37;40m   I don\'t need root permissions to read PCAPS ')
        print('    However, if you have PCAPs created by root or other users')
        print('    You should instead run me with root permission via sudo')

    print('[*] Running as {} with UID {} \033[0m \n'.format(os.getlogin(), os.getuid()))

    check_tshark_installed()

    print('\033[1;33;40m [*] Press CTRL+C to exit \033[0m ')
    signal(SIGINT, handler)
    while True:
        main()
