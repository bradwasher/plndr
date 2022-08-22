#!/usr/bin/python3.8


# PLNDR executes and stores the results of network enumeration commands (nmap, wkhtmltopdf, etc) to a
# folder generated at run-time into a directory specified in the plndr.yaml file.
# Commands are organized into scan-groups
# and typically target the same ports (web source grabs, web banner grabs, web screenshots),
# but can be organized as the user sees fit and enabled or disabled as necessary.
# Scans can be added to the scan section of scan groups will have the following variables
# available to them at execution time: ip, port, output directory, formatted ip, and filename extension.

# An example of an nmap scan is as follows:
# "nmap -sV -Pn -vv -p {PORT} --script smb-enum-shares.nse,smb-enum-users.nse {IP} -oN {OUTPUT_DIRECTORY}/{FORMATTED_IP}_{PORT}{FILENAME_EXTENSION}"

# Scans have timeout settings that will kill the process tied to the scan if it is taking too long.
# These are set in the scan config as well

import plndr_config
import os
import sys
import subprocess
import argparse
import yaml
import signal
from datetime import datetime
from yaml.loader import SafeLoader
from ipaddress import IPv4Interface, IPv4Network


def main():

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
v 0.3.0

''')
    # get command line args and override settings if necessary
    args = get_args()

    # get default settings, overwrite where necessary from command-line, and validate inputs
    settings = get_settings(args)

    # directory to save results
    session_directory = create_session_directory(settings.output_directory)

    # if target not specified on command line, use arp-scan to generate list of target IPs
    if args['target']:
        print(f"[+] beginning PLNDR of {args['target']} on interface {settings.interface_name}")
        print(f'[+] output saved to {session_directory}')
        print(f'[+] identifying target ip addresses...')

        command = settings.network_target_scan_command(ip=args['target'])
        target_ips = get_network_ips(command)
    elif args['local']:
        # get network cidr
        cidr = get_network_cidr(settings.interface_name)

        # output initial 
        print(f'[+] beginning PLNDR of {cidr} on interface {settings.interface_name}')
        print(f'[+] output saved to {session_directory}')
        print(f'[+] identifying local ip addresses...')

        # run arp scan to identify IP's on the LAN
        command = settings.lan_target_scan_command(interface_name=settings.interface_name, cidr=str(cidr))

        target_ips, arp_scan = get_lan_ips(command)
        save_collection('arp_scan.txt', arp_scan, session_directory)
    elif args['print_scans']:
        # print out scans available in the plndr.yaml file ane exit
        for scan_group in settings.scan_groups:
            print_scan(scan_group)

        sys.exit()

    print(f'[+] ip addresses identified')

    for ip in target_ips:
        print(f'  |_ {ip}')
    save_collection('ip_addresses.txt', target_ips, session_directory)

    # process enabled scan groups
    for scan_group in [x for x in settings.scan_groups if x.enabled]:
        run_scan(target_ips, scan_group, session_directory, settings)

    print(f'[+] PLNDR complete')
    print(f'[+] output saved to {session_directory}\n')


def get_settings(args):
    settings_path = os.path.join(os.path.dirname(__file__), 'plndr.yaml')
    with open(settings_path) as f:
        yaml_settings = yaml.load(f, Loader=SafeLoader)
    try:
        settings = plndr_config.load_config(yaml_settings)
    except KeyError as ke:
        sys.exit(f'[!] Exiting - config file not formatted correctly: {ke}')
    except FileNotFoundError as fe:
        sys.exit(f'[!]  Exiting - config file {settings_path} not found')

    # overwrite from command line where necessary
    if args['interface_name']:
        settings.interface_name = args['interface_name']

    # make sure directory exists
    if not os.path.isdir(settings.output_directory):
        sys.exit(f"[!] Exiting - output directory {settings.output_directory} doesn't exist")

    # make sure interface exists
    if not get_interface_exists(settings.interface_name):
        sys.exit(f"[!] Exiting -interface {settings.interface_name} doesn't exist")

    return settings


def get_args():
    ap = argparse.ArgumentParser(prog='./plndr.py',
                                 usage='%(prog)s [options]',
                                 description='PLNDR executes a collection of commands against target networks or '
                                             'individual IP addresses.  Reference the included \'plndr.yaml\' file '
                                             'for specific commands to run and what packages are required.',
                                 epilog='Happy plndr-ing!')

    ap.add_argument('-i',
                    '--interface-name',
                    required=False,
                    help="network interface to use")

    ag = ap.add_mutually_exclusive_group(required=True)

    ag.add_argument('-t',
                    '--target',
                    action='store',
                    help="plndr the target IP address or network cidr")

    ag.add_argument('-l',
                    '--local',
                    action='store_true',
                    help='plndr on the local LAN')

    ag.add_argument('-p',
                    '--print-scans',
                    action='store_true',
                    help='display scans in the plndr.yaml configuration')

    args = vars(ap.parse_args())

    # validate target 
    if args['target']:
        try:
            target = IPv4Network(args['target'])
        except ValueError as ex:
            sys.exit(f"[!] Exiting - Invalid target specified {args['target']}")

    return args


def get_interface_exists(interface_name):
    return True if os.path.isdir(f'/sys/class/net/{interface_name}') else False


def get_network_cidr(interface_name):
    try:
        addr = os.popen(f'ip addr show {interface_name}').read().split("inet ")[1].split()[0]
        ip_interface = IPv4Interface(addr)
        return ip_interface.network
    except Exception as err:
        sys.exit(f"[!] Exiting - no network CIDR found for interface {interface_name}")


def get_lan_ips(lan_scan):
    try:
        proc = subprocess.run(lan_scan.split(), capture_output=True)
        results = proc.stdout.decode().splitlines()
        arp_scan = [x for x in results]
        local_ips = [x.split('\t')[0] for x in results if '\t' in x]

        return local_ips, arp_scan
    except Exception as err:
        sys.exit(f"[!] Exiting - error getting local IP addresses - {err}")


def get_network_ips(network_scan):
    try:
        proc = subprocess.run(network_scan.split(), capture_output=True)
        results = proc.stdout.decode().splitlines()
        target_ips = [x.split(' ')[1] for x in results if 'Status: Up' in x]

        return target_ips
    except Exception as err:
        sys.exit(f"[!] Exiting - error getting target IP addresses - {err}")


def get_open_ports(target_ips, ports, settings):
    endpoints = []
    for ip in target_ips:
        command = settings.port_scan_command(ip=ip, ports=','.join(str(x) for x in ports))
        proc = subprocess.run(command.split(), capture_output=True)
        results = proc.stdout.decode().splitlines()
        open_ports = [x.split('/')[0] for x in results if 'open' in x]
        endpoints.extend([(ip, x) for x in open_ports])

    return endpoints


def create_session_directory(parent_directory):
    ts = datetime.utcnow()
    session_id = str(ts).replace('-', '').replace(' ', '_').replace(':', '').split('.')[0] + 'Z'
    session_path = os.path.join(parent_directory, session_id)
    os.mkdir(session_path)

    return session_path


def save_collection(file_name, collection, session_directory):
    path = os.path.join(session_directory, file_name)
    str_collection = [':'.join(x) if isinstance(x, tuple) else x for x in collection]
    with open(path, 'w') as f:
        f.write('\n'.join(str_collection))
        f.write('\n')


def split_string(value, split_char, ignore_char):
    result = []
    string = ""
    ignore = False
    for c in value:
        if c == ignore_char:
            ignore = True if ignore == False else False
        elif c == split_char and not ignore:
            result.append(string)
            string = ""
        else:
            string += c
    result.append(string)
    return result


def get_label(single_descriptor, plural_descriptor, values):
    if len(values) == 1:
        return f'{single_descriptor} {str(values[0])}'
    else:
        return f'{plural_descriptor} {", ".join([str(x) for x in values[:-1]])} and {str(values[len(values) - 1])}'


def run_scan(target_ips, scan_group, session_directory, settings):
    # set ports label
    print(f'[+] identifying {scan_group.description} on {get_label("port", "ports", scan_group.ports)}')

    # get end-points with open ports
    end_points = get_open_ports(target_ips, scan_group.ports, settings)
    print(f'[+] {len(end_points)} {scan_group.description} identified')
    for endpoint in end_points:
        print(f'  |_ {endpoint[0]}:{endpoint[1]}')

    save_collection(scan_group.filename, end_points, session_directory)

    # conduct enabled scans
    for scan in [x for x in scan_group.scans if x.enabled]:

        print(f'[+] Running {scan.description}')

        # run scan for each endpoint
        for endpoint in end_points:
            ip = endpoint[0]
            port = endpoint[1]

            # set default values
            command = scan.scan_command(ip=ip,
                                        formatted_ip=ip.replace('.', '_'),
                                        port=port,
                                        output_directory=session_directory)
            if command is None:
                print(f'[!] Invalid conditional type in scan; aborting scan')
                break

            # run command
            try:
                split_command = split_string(command, ' ', '"')
                p = subprocess.Popen(split_command,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL,
                                     start_new_session=True)
                p.wait(timeout=scan.timeout)
            except subprocess.TimeoutExpired:
                print(f' |x timed out getting {ip}:{port}')
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)


def print_scan(scan_group):
    print(f'Scan Group: {scan_group.description}')
    print(f'Ports: {scan_group.ports}')
    print(f'Enabled: {scan_group.enabled}')
    print(f'Scans:')
    for scan in scan_group.scans:
        print(f'\tDescription: {scan.description}')
        print(f'\tEnabled: {scan.enabled}')
        print(f'\tCommand: {scan.command}')
        print()
    print('\n')


if __name__ == "__main__":
    main()
