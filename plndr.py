#!/usr/bin/python3.8


# PLNDR provides identification of web and tty endpoints in the local LAN
# and captures screenshots and source code of web pages and banner grabs 
# of tty services.  Interfaces and ports searched for are configurable by
# editing plndr.config file.
#
# PLNDR wraps and depends upon the following tools
# 1. nmap
# 2. arp-scan
# 3. wkhtmltopdf
#
# Collected data is stored in a directory that is created at run-time and 
# named after the timestamp the script is run.

from ipaddress import IPv4Interface, IPv4Network, IPv4Address
import time
import os
import sys
import subprocess
import argparse
from datetime import datetime
from configparser import ConfigParser

def main():
    
    # startup
    print('''
          _             _       
         | |           | |      
   _ __  | | _ __    __| | _ __ 
  | '_ \ | || '_ \  / _` || '__|
  | |_) || || | | || (_| || |   
  | .__/ |_||_| |_| \__,_||_|   
  | |                          
  |_|           by: procre8or
=================================
v 0.2

''')
    
    # get default settings
    output_directory, web_ports, tty_ports, rdp_ports, smb_ports, interface_name, user_agent, timeout = get_settings()
 
    # get command line args; interface name overrides interface in default settings
    args = get_args()
    if args['interface_name']:
        interface_name = args['interface_name']


    # make sure directory exists
    if not os.path.isdir(output_directory):
        sys.exit(f"Exiting - output directory {output_directory} doesn't exist")
    
    # make sure interface exists
    if not get_interface_exists(interface_name):
        sys.exit(f"Exiting -interface {interface_name} doesn't exist")


    # directory to save results
    session_directory = create_session_directory(output_directory)
    
    # if target not specified on command line, use arp-scan to generate list of target IPs
    if args['target']:
        print(f"[+] beginning PLNDR of {args['target']} on interface {interface_name} with timeout of {int(timeout)} seconds")
        print(f'[+] output saved to {session_directory}')
        print(f'[+] identifying target ip addresses...')    

        target_ips = get_target_ips(args['target'])
    else:
        # get network cidr
        cidr = get_network_cidr(interface_name)

        # output initial 
        print(f'[+] beginning PLNDR of {cidr} on interface {interface_name} with timeout of {int(timeout)} seconds')
        print(f'[+] output saved to {session_directory}')
        print(f'[+] identifying local ip addresses...')

        #run arp scan to identify IP's on the LAN
        target_ips, arp_scan = get_local_ips(interface_name, cidr)
        save_collection('arp_scan.txt', arp_scan, session_directory)
    
    print(f'[+] ip addresses identified')
    
    for ip in target_ips:
        print(f'  |_ {ip}')
    save_collection('ip_addresses.txt', target_ips, session_directory)
    
    # detect web endpoints
    print(f'[+] identifying web endpoints...')
    web_endpoints = get_endpoints(target_ips, web_ports)
    print(f'[+] {len(web_endpoints)} web endpoints identified')
    for endpoint in web_endpoints:
        print(f'  |_ {endpoint[0]}:{endpoint[1]}')
    save_collection('web_endpoints.txt', web_endpoints, session_directory)

    # grab screenshots from web endpoints
    print(f'[+] grabbing screenshots from web endpoints...')
    get_web_screenshots(web_endpoints, session_directory, timeout)

    # grab page source from web endpoints
    print(f'[+] grabbing source code from web endpoints...')
    get_web_source(web_endpoints, session_directory, user_agent, timeout)

    # grab banner from web endpoints
    print(f'[+] grabbing banners from web endpoints...')
    get_web_banners(web_endpoints, session_directory, user_agent, timeout)

    # detect tty endpoints
    print(f'[+] identifying tty endpoints...')
    tty_endpoints = get_endpoints(target_ips, tty_ports)
    print(f'[+] {len(tty_endpoints)} tty endpoints identified')
    for endpoint in tty_endpoints:
        print(f'  |_ {endpoint[0]}:{endpoint[1]}')
    save_collection('tty_endpoints.txt', tty_endpoints, session_directory)
    
    # getting banners from each tty endpoint
    print(f'[+] getting banners from tty endpoints...')
    get_tty_banners(tty_endpoints, session_directory, timeout)

    # detect rdp endpoints
    print(f'[+] identifying rdp endpoints...')
    rdp_endpoints = get_endpoints(target_ips, rdp_ports)
    print(f'[+] {len(rdp_endpoints)} rdp endpoints identified')
    for endpoint in rdp_endpoints:
        print(f'  |_ {endpoint[0]}:{endpoint[1]}')
    save_collection('rdp_endpoints.txt', rdp_endpoints, session_directory)
    
    # getting ntlm from each rdp endpoint
    print(f'[+] getting ntlm dtaa from rdp endpoints...')
    get_rdp_banners(rdp_endpoints, session_directory, timeout)

    # detect smb endpoints
    print(f'[+] identifying smb endpoints...')
    smb_endpoints = get_endpoints(target_ips, smb_ports)
    print(f'[+] {len(smb_endpoints)} smb endpoints identified')
    for endpoint in smb_endpoints:
        print(f'  |_ {endpoint[0]}:{endpoint[1]}')
    save_collection('smb_endpoints.txt', smb_endpoints, session_directory)
    
    # enumerate  smb endpoints
    print(f'[+] enumerating smb endpoints...')
    get_smb_enum(smb_endpoints, session_directory, timeout)


    print(f'[+] PLNDR complete')
    print(f'[+] output saved to {session_directory}\n')

    sys.exit()

def get_settings():
    # try to load from config file
    path = os.path.join(os.path.dirname(__file__), 'plndr.ini')
    parser = ConfigParser()
    parser.read(path)

    # output_directory
    try:
        output_directory = parser.get('default_values', 'output_directory')
    except:
        output_directory = os.getcwd()
    
    # web_ports
    try:
        web_ports = parser.get('default_values', 'web_ports').split(',')
    except:
        web_ports = ['80','8080','443']
    
    # tty_ports
    try:
        tty_ports = parser.get('default_values', 'tty_ports').split(',')
    except:
        tty_ports = ['21','22','23']
    
    # rdp_ports
    try:
        rdp_ports = parser.get('default_values', 'rdp_ports').split(',')
    except:
        tty_ports = ['3389']
    
    # smb_ports
    try:
        smb_ports = parser.get('default_values', 'smb_ports').split(',')
    except:
        smb_ports = ['445']

    # interface
    try:
        interface_name = parser.get('default_values', 'interface_name')
    except:
        interface_name = 'wlan0'
    
    # user_agent
    try:
        user_agent = parser.get('default_values', 'user_agent')
    except:
        user_agent = 'Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.88 Mobile Safari/537.36'
    
    # timeout
    try:
        timeout = float(parser.get('default_values', 'timeout'))
    except:
        timeout = 45.0

    return (output_directory, web_ports, tty_ports, rdp_ports, smb_ports, interface_name, user_agent, timeout)


def get_args():
    """
    Get and validate command line arguments and return dictionary of those key/values
    :return:
    """
    ap = argparse.ArgumentParser()

    ap.add_argument("-t", "--target", required=False,
                    help="target IP address or network cidr")

    ap.add_argument("-i", "--interface-name", required=False,
                    help="network interface to use")


    args = vars(ap.parse_args())

    # validate target 
    if args['target']:
        try:
            target = IPv4Network(args['target'])
        except:
            sys.exit(f"Exiting - Invalid target specified {args['target']}")

    return args

def get_interface_exists(interface_name):
        return True if os.path.isdir(f'/sys/class/net/{interface_name}') else False

def get_network_cidr(interface_name):
    try:
        addr = os.popen(f'ip addr show {interface_name}').read().split("inet ")[1].split()[0]
        ip_interface = IPv4Interface(addr)
        return ip_interface.network
    except:
        sys.exit(f"Exiting - no network CIDR found for interface {interface_name}")

def get_local_ips(interface_name, cidr):
    try:
        proc = subprocess.run(['arp-scan', f'--interface={interface_name}', f'{cidr}'], capture_output=True)
        results = proc.stdout.decode().splitlines()
        arp_scan = [x for x in results]
        local_ips = [x.split('\t')[0] for x in results if '\t' in x]

        return (local_ips, arp_scan)
    except Exception as err:
        sys.exit(f"Exiting - error getting local IP addresses - {err}")

def get_target_ips(target):
    # nmap -n -sP 10.0.0.0/24 -oG - | grep -i 'Status: Up'
    try:
        proc = subprocess.run(['nmap', '-n', '-sP', f'{target}', '-oG', '-'], capture_output=True)
        results = proc.stdout.decode().splitlines()
        target_ips = [x.split(' ')[1] for x in results if 'Status: Up' in x]
    
        return target_ips
    except Exception as err:
        sys.exit(f"Exiting - error getting target IP addresses - {err}")

def get_endpoints(target_ips, ports):
    endpoints = []
    for ip in target_ips:
        proc  = subprocess.run(['nmap', '-Pn', '--max-retries=5', f'{ip}', '-p', ','.join(str(x) for x in ports), '--open'], capture_output=True)
        results = proc.stdout.decode().splitlines()
        open_ports = [x.split('/')[0] for x in results if 'open' in x]
        endpoints.extend([(ip,x) for x in open_ports])
             
    return endpoints


def get_web_screenshots(endpoints, session_directory, timeout):
    for endpoint in endpoints:
        file_name = f"{endpoint[0].replace('.', '_')}_{endpoint[1]}_screenshot.png"
        try:
            subprocess.run(['wkhtmltoimage', f'{endpoint[0]}:{endpoint[1]}', f'{session_directory}/{file_name}'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print(f' |x timed out getting {endpoint[0]}:{endpoint[1]}')

def get_web_source(endpoints, session_directory, user_agent, timeout):
    for endpoint in endpoints:
        file_name = f"{endpoint[0].replace('.', '_')}_{endpoint[1]}_source.html"
        try:
            subprocess.run(['curl', '-kLA', user_agent, f'{endpoint[0]}:{endpoint[1]}', '-o', f'{session_directory}/{file_name}'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print(f' |x timed out getting {endpoint[0]}:{endpoint[1]}')

def get_web_banners(endpoints, session_directory, user_agent, timeout):
    for endpoint in endpoints:
        file_name = f"{endpoint[0].replace('.', '_')}_{endpoint[1]}_banner.txt"
        try:
            subprocess.run(['curl', '-kLsvIA', user_agent, f'{endpoint[0]}:{endpoint[1]}', '-o', f'{session_directory}/{file_name}'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print(f' |x timed out getting {endpoint[0]}:{endpoint[1]}')

def get_tty_banners(endpoints, session_directory, timeout):
    #nmap --script=banner 192.168.0.1 -p 22 -oN output.txt

    for endpoint in endpoints:
        file_name = f"{endpoint[0].replace('.', '_')}_{endpoint[1]}_banner.txt"
        try:
            subprocess.run(['nmap', '-sV', '--script-timeout=10s', '--script=banner', f'{endpoint[0]}', '-p', f'{endpoint[1]}', '-oN', f'{session_directory}/{file_name}'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print(f' |x timed out getting {endpoint[0]}:{endpoint[1]}')

def get_rdp_banners(endpoints, session_directory, timeout):
    #nmap -p 3389 --script rdp-ntlm-info target_ip
    for endpoint in endpoints:
        file_name = f"{endpoint[0].replace('.', '_')}_{endpoint[1]}_rdp.txt"
        try:
            subprocess.run(['nmap', '--script-timeout=10s', '--script=rdp-ntlm-info', f'{endpoint[0]}', '-p', f'{endpoint[1]}', '-oN', f'{session_directory}/{file_name}'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print(f' |x timed out getting {endpoint[0]}:{endpoint[1]}')

def get_smb_enum(endpoints, session_directory, timeout):
    #nmap -sV -Pn -vv -p445 --script smb-enum-shares.nse,smb-enum-users.nse 192.168.2.118
    
    for endpoint in endpoints:
        file_name = f"{endpoint[0].replace('.', '_')}_{endpoint[1]}_smb_enum.txt"
        try:
            subprocess.run(['nmap', '-sV', '-Pn', '--script-timeout=15s', '--script=smb-enum-shares.nse,smb-enum-users.nse,smb-os-discovery.nse', f'{endpoint[0]}', '-p', f'{endpoint[1]}', '-oN', f'{session_directory}/{file_name}'], timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            print(f' |x timed out getting {endpoint[0]}:{endpoint[1]}')

def create_session_directory(parent_directory):
    ts = datetime.utcnow()
    session_id = str(ts).replace('-', '').replace(' ', '_').replace(':', '').split('.')[0] + 'Z'
    session_path = os.path.join(parent_directory, session_id)
    os.mkdir(session_path)

    return session_path

def save_collection(file_name, collection, session_directory):
    path = os.path.join(session_directory, file_name)
    str_collection = [':'.join(x)  if isinstance(x,tuple) else x for x in collection]
    with open(path, 'w') as f:
        f.write('\n'.join(str_collection))
        f.write('\n')

if __name__ == "__main__":
    main()
    #https://patorjk.com/software/taag/#p=display&h=0&v=0&f=Doom&t=plndr

