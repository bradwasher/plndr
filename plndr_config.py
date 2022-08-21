from dataclasses import dataclass, field
import yaml
from yaml.loader import SafeLoader
from typing import List
from pprint import pp


def load_config(settings):

    # create config object from settings YAML
    config = PlndrConfig(settings['output-directory'],
                         settings['interface-name'],
                         settings['lan-target-scan'],
                         settings['network-target-scan'],
                         settings['port-scan'],
                         [])

    # get scan groups
    for group_setting in settings['scan-groups']:
        scan_group = ScanGroup(group_setting['description'],
                               group_setting['enabled'],
                               group_setting['filename'],
                               group_setting['ports'],
                               [])
        # get scans
        for scan_setting in group_setting['scans']:
            scan = Scan(scan_setting['description'],
                        scan_setting['enabled'],
                        scan_setting['command'],
                        scan_setting['timeout'],
                        [])

            # get variables
            for variable_setting in scan_setting['variables']:
                if 'type' in variable_setting:
                    if variable_setting['type'] == 'port-match':
                        variable = PortMatchVariable(variable_setting['name'], [], variable_setting['default'])
                        # get condition matches
                        for condition in variable_setting['conditions']:
                            match = PortMatchCondition(condition['match'], condition['value'])
                            variable.conditions.append(match)
                else:
                    variable = Variable(variable_setting['name'], variable_setting['value'])
                # append variable to scan
                scan.variables.append(variable)

            # append scan to scan group
            scan_group.scans.append(scan)

        config.scan_groups.append(scan_group)

    #pp(config)

    return config


@dataclass
class PlndrConfig:
    output_directory: str
    interface_name: str
    lan_target_scan: str
    network_target_scan: str
    port_scan: str
    scan_groups: []

    def lan_target_scan_command(self, **kwargs):
        command = self.lan_target_scan
        for key, value in kwargs.items():
            variable = '{' + key.upper() + '}'
            command = command.replace(variable, value)

        return command

    def network_target_scan_command(self, **kwargs):
        command = self.network_target_scan
        for key, value in kwargs.items():
            variable = '{' + key.upper() + '}'
            command = command.replace(variable, value)

        return command

    def port_scan_command(self, **kwargs):
        command = self.port_scan
        for key, value in kwargs.items():
            variable = '{' + key.upper() + '}'
            command = command.replace(variable, value)

        return command


@dataclass
class ScanGroup:
    description: str
    enabled: bool
    filename: str
    ports: []
    scans: []


@dataclass
class Scan:
    description: str
    enabled: bool
    command: str
    timeout: int
    variables: []

    def scan_command(self, **kwargs):
        command = self.command

        # set default commands
        for key, value in kwargs.items():
            variable = '{' + key.upper() + '}'
            command = command.replace(variable, value)

        # set variables
        for variable in self.variables:
            if type(variable) is Variable:
                command = command.replace('{' + variable.name.upper() + '}', variable.value)
            elif type(variable is PortMatchVariable):
                found_match = False
                for condition in variable.conditions:
                    if kwargs['port'] in condition.match:
                        found_match = True
                        command = command.replace('{' + variable.name.upper() + '}', condition.value)
                        break
                if not found_match:
                    command = command.replace('{' + variable.name.upper() + '}', variable.default)
            else:
                # unsupported variable type; exit
                return None

        return command


@dataclass
class Variable:
    name: str
    value: str


@dataclass
class PortMatchVariable:
    name: str
    conditions: []
    default: str


@dataclass
class PortMatchCondition:
    match: []
    value: str


if __name__ == "__main__":
    with open('plndr.yaml') as f:
        settings = yaml.load(f, Loader=SafeLoader)
    load_config(settings)
