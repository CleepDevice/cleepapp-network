# !/usr/bin/env python
#  -*- coding: utf-8 -*-

import time
from cleep.exception import InvalidParameter, MissingParameter, CommandError
from cleep.core import CleepModule
from cleep.libs.configs.wpasupplicantconf import WpaSupplicantConf
from cleep.libs.configs.dhcpcdconf import DhcpcdConf
from cleep.libs.configs.etcnetworkinterfaces import EtcNetworkInterfaces
from cleep.libs.commands.ifconfig import Ifconfig
from cleep.libs.commands.iw import Iw
from cleep.libs.commands.iwlist import Iwlist
from cleep.libs.commands.iwconfig import Iwconfig
from cleep.libs.commands.ifupdown import Ifupdown
from cleep.libs.commands.wpacli import Wpacli
from cleep.libs.configs.cleepwificonf import CleepWifiConf
from cleep.libs.internals.task import Task
import netifaces

__all__ = ['Network']


class Network(CleepModule):
    """
    Network module allows user to configure wired and wifi connection

    Notes:

        * iw versus iwconfig (which is deprecated)
        https://donnutcompute.wordpress.com/2014/04/20/connect-to-wi-fi-via-command-line/
        * official raspberry pi foundation configuration guide
        https://www.raspberrypi.org/documentation/configuration/
        https://www.raspberrypi.org/documentation/configuration/wireless/wireless-cli.md
        * guide from ubuntu forum
        https://askubuntu.com/a/16588
        * another super guide ;)
        https://www.blackmoreops.com/2014/09/18/connect-to-wifi-network-from-command-line-in-linux/
        * nodejs wireless-tools lib
        https://github.com/bakerface/wireless-tools

    """
    MODULE_AUTHOR = 'Cleep'
    MODULE_VERSION = '1.1.0'
    MODULE_CATEGORY = 'APPLICATION'
    MODULE_PRICE = 0
    MODULE_DEPS = []
    MODULE_DESCRIPTION = 'Configure how your device connect to your network'
    MODULE_LONGDESCRIPTION = 'Application that helps you to configure device network connection'
    MODULE_URL = None
    MODULE_TAGS = ['wireless', 'wifi', 'ethernet']
    MODULE_COUNTRY = None
    MODULE_URLINFO = 'https://github.com/tangb/cleepmod-network/wiki'
    MODULE_URLHELP = 'https://github.com/tangb/cleepmod-network/wiki/Help'
    MODULE_URLSITE = None
    MODULE_URLBUGS = 'https://github.com/tangb/cleepmod-network/issues'

    STATUS_DISCONNECTED = 0
    STATUS_CONNECTING = 1
    STATUS_CONNECTED = 2
    STATUS_WIFI_INVALID_PASSWORD = 3

    def __init__(self, bus, debug_enabled):
        """
        Constructor

        Args:
            bus (MessageBus): bus instance
            debug_enabled (bool): debug status
        """
        # init
        CleepModule.__init__(self, bus, debug_enabled)

        # tools
        self.etcnetworkinterfaces = EtcNetworkInterfaces(self.cleep_filesystem)
        self.dhcpcd = DhcpcdConf(self.cleep_filesystem)
        self.wpasupplicant = WpaSupplicantConf(self.cleep_filesystem)
        self.iw = Iw()
        self.iwlist = Iwlist()
        self.ifconfig = Ifconfig()
        self.iwconfig = Iwconfig()
        self.ifupdown = Ifupdown()
        self.wpacli = Wpacli()
        self.cleepwifi = CleepWifiConf()

        # members
        self.wifi_networks = {}
        self.wifi_network_names = []
        self.wifi_interfaces = {}
        self.wifi_adapters = {}
        self.network_status = {}
        self.last_wifi_networks_scan = 0
        self.__network_watchdog_task = None
        self.__network_is_down = True

        # events
        self.network_up_event = self._get_event('network.status.up')
        self.network_down_event = self._get_event('network.status.down')
        self.network_status_update = self._get_event('network.status.update')

    def _configure(self):
        """
        Module start
        """
        # refresh list of wifi networks
        try:
            self.refresh_wifi_networks()
        except Exception:
            self.logger.exception('Exception occured when refreshing wifi networks:')
            self.crash_report.report_exception()

        # handle startup config if cleep wifi conf exists
        if self.cleepwifi.exists():
            self.logger.debug('Cleepwifi config file exists. Load wifi config')
            try:
                self._load_cleep_wifi_conf()
            except Exception:
                self.logger.exception('Error loading cleepwifi.conf file:')
                self.crash_report.report_exception()
            finally:
                self.cleepwifi.delete(self.cleep_filesystem)

    def _on_start(self):
        """
        Module is started
        """
        # launch network watchdog
        self.__network_watchdog_task = Task(1.0, self._check_network_connection, self.logger)
        self.__network_watchdog_task.start()

    def _on_stop(self):
        """
        Stop module
        """
        if self.__network_watchdog_task:
            self.__network_watchdog_task.stop()

    def _load_cleep_wifi_conf(self):
        """
        Load cleepwifi.conf

        Note:
            This function does not check file existence
        """
        # read file content
        cleep_conf = self.cleepwifi.get_configuration()
        self.logger.debug('cleep_conf: %s' % cleep_conf)
        if not cleep_conf:
            self.logger.warning('cleepwifi.conf file content is empty')
            return

        # search for network in interface
        found_interface = None
        found_encryption = cleep_conf['encryption']
        self.logger.debug('Wifi networks: %s' % self.wifi_networks)
        for interface_name, networks in self.wifi_networks.items():
            if cleep_conf['network'] in networks and not networks[cleep_conf['network']]['configured']:
                self.logger.debug('Interface "%s" found' % interface_name)
                found_interface = interface_name
                found_encryption = networks[cleep_conf['network']]['encryption']
                break
        if cleep_conf['hidden'] and not found_interface and self.wifi_networks:
            # network is declared as hidden, save hidden network in first available interface
            found_interface = list(self.wifi_networks.keys())[0]

        # add config if not already exists
        if found_interface or cleep_conf['hidden']:
            if not self.wpasupplicant.add_network(
                    cleep_conf['network'],
                    found_encryption,
                    cleep_conf['password'],
                    hidden=cleep_conf['hidden'],
                    interface=found_interface,
                    encrypt_password=False
                ):
                self.logger.error('Unable to use config from cleepwifi.conf')
            else:
                if found_interface:
                    self.reconfigure_wifi_interface(found_interface)
                self.logger.info('Wifi config from cleepwifi.conf loaded successfully')
        else:
            self.logger.warning(
                'Interface was not found for network "%s" or network is already configured' % cleep_conf['network']
            )

    def get_module_config(self):
        """
        Return module configuration (wifi networks, ip address, ...)

        Returns:
            dict: module configuration::

                {
                    lastwifiscan (int): timestamp of last wifi scan
                    networks (list): list of networks (wireless and wired)
                    wifiinterfaces (list): list of wifi interfaces
                    wifistatus (dict): dict of wifi status
                }

        """
        output = {}

        # get current network status
        current_status = self.ifconfig.get_configurations()
        self.logger.trace('Current_status: %s' % current_status)
        self.logger.debug('wifi_interfaces: %s' % self.wifi_interfaces)

        # gather network data
        if self.dhcpcd.is_installed():
            # dhcpcd is installed (>=stretch), use dhcpcd.conf infos
            configured_interfaces = self._get_network_config_from_dhcpcd(current_status.keys())
        else:
            # dhcpcd is not installed (<=jessie), use /etc/network/interfaces conf file
            configured_interfaces = self._get_network_config_from_network_interfaces()
        self.logger.trace('Configured_interfaces: %s' % configured_interfaces)

        # prepare networks list
        all_networks = []

        # add wired interface as network
        for interface_name, configured_interface in configured_interfaces.items():
            if not configured_interface['wifi']:
                # save entry
                all_networks.append({
                    'network': interface_name,
                    'interface': interface_name,
                    'wifi': False,
                    'config': configured_interface,
                    'status': current_status[interface_name] if interface_name in current_status else None
                })

        # add all wifi networks on range
        for interface_name, networks in self.wifi_networks.items():
            self.logger.trace('interface %s: %s' % (interface_name, networks))
            for network_name, network in networks.items():
                # save entry
                all_networks.append({
                    'network': network_name,
                    'interface': interface_name,
                    'wifi': True,
                    'config': network,
                    'status': current_status[interface_name] if interface_name in current_status else None
                })

        # prepare output
        output['networks'] = all_networks
        output['wifiinterfaces'] = list(self.wifi_interfaces.keys())
        output['lastwifiscan'] = self.last_wifi_networks_scan
        output['networkstatus'] = self.network_status

        return output

    def _get_network_config_from_dhcpcd(self, interfaces_names):
        """
        Get module config from dhcpcd.conf.

        dhcpcd.conf is the default network manager on raspbian stretch and above

        Notes:
            See notes about network configuration in stretch and above:
            https://raspberrypi.stackexchange.com/questions/37920/how-do-i-set-up-networking-wifi-static-ip-address/37921# 37921

        Args:
            interfaces_names (list): list of all existing interfaces names

        Returns:
            dict: configured interfaces::
            
            {
                interface name (string): {
                    interface (string): interface name,
                    mode (string): interface mode (see etcnetworkinterface MODE_XXX)
                    address (string): ip address
                    netmask (string): netmask address
                    gateway (string): gateway address
                    dnsnameservers (string): dns nameservers
                },
                ...
            }

        """
        # get wired configuration from dhcpcd
        configured_interfaces = {}
        dhcpcd_config = self.dhcpcd.get_configurations()
        self.logger.debug('dhcpcd_config: %s' % dhcpcd_config)

        # add more infos (iterates over current status because with dhcpcd does not return dhcp configured interfaces)
        for interface_name in interfaces_names:
            # add new entry. Dict entry content is imitating output of etcnetworkinterfaces library.
            configured_interfaces[interface_name] = {
                'interface': interface_name,
                'mode': None,
                'address': None,
                'netmask': None,
                'gateway': None,
                'dnsnameservers': None,
                'wifi': None,
                'wifinetwork': None,
            }

            # fill config with dhcpcd data
            if interface_name in dhcpcd_config:
                # interface is configured
                configured_interfaces[interface_name].update({
                    'mode': self.etcnetworkinterfaces.MODE_STATIC,
                    'address': dhcpcd_config[interface_name]['ip_address'],
                    'netmask': dhcpcd_config[interface_name]['netmask'],
                    'gateway': dhcpcd_config[interface_name]['gateway'],
                    'dnsnameservers': dhcpcd_config[interface_name]['dns_address'],
                })
            else:
                # interface has no configuration, set mode has dhcp
                configured_interfaces[interface_name].update({
                    'mode': self.etcnetworkinterfaces.MODE_DHCP
                })

            # fill config with wifi config
            if interface_name in self.wifi_interfaces:
                # wifi interface
                configured_interfaces[interface_name].update({
                    'wifi': True,
                    'wifinetwork': self.wifi_interfaces[interface_name]['network'],
                })
            else:
                # interface is not wifi
                configured_interfaces[interface_name].update({
                    'wifi': False,
                    'wifinetwork': None,
                })

        return configured_interfaces

    def _get_network_config_from_network_interfaces(self):
        """
        Get network configuration from /etc/network/interfaces

        This is the default place where network configuration is stored before raspbian stretch

        Returns:
            dict: configured interfaces::

            {
                interface name (string): {
                    interface (string): interface name,
                    mode (string): iface mode,
                    address (string): ip address,
                    netmask (string): netmask address,
                    broadcast (string): broadcast address,
                    gateway (string): gateway address,
                    dns_nameservers (string): dns nameservers address,
                    dns_domain (string): dns domain address,
                    hotplug (bool): True if hotplug interface,
                    auto (bool): True if auto option enabled,
                    wpa_conf (string): wpa profile name
                    wifi (bool): True if interface is wifi
                    wifinetwork (string): connected wifi network name
                },
                ...
            }

        """
        # get configuration
        configured_interfaces = self.etcnetworkinterfaces.get_configurations()

        # remove lo interface from configured interfaces list
        if 'lo' in configured_interfaces.keys():
            del configured_interfaces['lo']

        # add more infos
        for interface_name, configured_interface in configured_interfaces.items():
            # add wifi infos
            if interface_name in self.wifi_interfaces.keys():
                # interface is wifi and connected
                configured_interface['wifi'] = True
                configured_interface['wifinetwork'] = self.wifi_interfaces[interface]['network']
            elif configured_interface['wpa_conf'] is not None:
                # interface is wifi but not connected
                configured_interface['wifi'] = True
                configured_interface['wifinetwork'] = None
            else:
                # interface is not wifi
                configured_interface['wifi'] = False
                configured_interface['wifinetwork'] = None

        return configured_interfaces

    def event_received(self, event):
        """
        Event received on bus

        Args:
            event (dist): event data
        """
        if event['event'] == 'system.country.update':
            # update wpa_supplicant country code
            self.logger.debug('Received country update event: %s' % event)
            self.wpasupplicant.set_country(event['params']['country'])

    def _check_network_connection(self):
        """
        Check network connection
        Send event when network is up and when it is down
        Monitor wifi network status (disconnected/connected/invalid password)
        """
        # init
        wifi_interfaces = self.iwconfig.get_interfaces()
        connected = False
        interfaces = netifaces.interfaces()

        # check interfaces
        for interface in interfaces:
            # drop local interface
            if interface == 'lo':
                continue

            # check if at least one interface is connected
            addresses = netifaces.ifaddresses(interface)
            if (netifaces.AF_INET in addresses
                    and len(addresses[netifaces.AF_INET]) == 1
                    and addresses[netifaces.AF_INET][0]['addr'].strip()):
                connected = True

            # update interface status
            if interface in wifi_interfaces:
                # wifi interface
                self.__check_wifi_interface(interface, addresses)
            else:
                # ethernet interface
                self.__check_wired_interface(interface, addresses)

        # handle network connection status
        if connected and self.__network_is_down:
            self.__network_is_down = False
            self.network_up_event.send()
        elif not connected and not self.__network_is_down:
            self.__network_is_down = True
            self.network_down_event.send()

    # ----------
    # WIRED AREA
    # ----------

    def __check_wired_interface(self, interface, netifaces_infos):
        """
        Check wired interface

        Args:
            interface (string): name of wired interface
            netifaces_infos (dict): infos from netifaces request
        """
        old_status = None
        if interface not in self.network_status:
            self.network_status[interface] = {}
            self.network_status[interface]['network'] = 'wired'
            self.network_status[interface]['status'] = None
            self.network_status[interface]['ipaddress'] = None

        try:
            # get old status to send update event after update if necessary
            old_status = self.network_status[interface]['status']

            # update status
            if netifaces.AF_INET in netifaces_infos:
                self.network_status[interface]['status'] = self.STATUS_CONNECTED
                self.network_status[interface]['ipaddress'] = netifaces_infos[netifaces.AF_INET][0]['addr']
            # TODO ipv6 appears more quickly than ipv4 so event sends status with ipv6.
            # We need to find a way to handle both ipv4 and ipv6
            # elif netifaces.AF_INET6 in netifaces_infos:
            #     self.network_status[interface]['status'] = self.STATUS_CONNECTED
            #     self.network_status[interface]['ipaddress'] = netifaces_infos[netifaces.AF_INET6][0]['addr']
            else:
                self.network_status[interface]['status'] = self.STATUS_DISCONNECTED
                self.network_status[interface]['ipaddress'] = None

            # send event
            if old_status is not None and old_status != self.network_status[interface]['status']:
                self.logger.debug('Wired interface "%s" status %s with ip "%s"' % (
                    interface,
                    self.network_status[interface]['status'],
                    self.network_status[interface]['ipaddress'],
                ))
                self.network_status_update.send(params={
                    'interface':interface,
                    'network': self.network_status[interface]['network'],
                    'status': self.network_status[interface]['status'],
                    'ipaddress': self.network_status[interface]['ipaddress'],
                })

        except Exception:
            self.logger.exception('Exception occured when trying to get wired interface "%s" status' % interface)

    def reconfigure_wired_interface(self, interface):
        """
        Restart network interface

        Args:
            interface (string): network interface name
        """
        self.ifupdown.restart_interface(interface)

    def save_wired_static_configuration(self, interface, ip_address, gateway, netmask, fallback):
        """
        Save wired static configuration

        Args:
            interface (string): interface to configure
            ip_address (string): desired ip address
            gateway (string): gateway address
            netmask (string): netmask
            fallback (bool): is configuration used as fallback
        """
        # then add new one
        if self.dhcpcd.is_installed():
            # use dhcpcd

            # delete existing configuration for specified interface
            if not self.dhcpcd.delete_interface(interface):
                self.logger.error(
                    'Unable to save wired static configuration (dhcpcd): unable to delete interface %s' % interface
                )
                raise CommandError('Unable to save data')

            # finally add new configuration
            if fallback:
                if not self.dhcpcd.add_static_interface(interface, ip_address, gateway, netmask):
                    self.logger.error(
                        'Unable to save wired static configuration (dhcpcd): unable to add interface %s' % interface
                    )
                    raise CommandError('Unable to save data')
            else:
                if not self.dhcpcd.add_fallback_interface(interface, ip_address, gateway, netmask):
                    self.logger.error(
                        'Unable to save wired fallback configuration (dhcpcd): unable to add interface %s' % interface
                    )
                    raise CommandError('Unable to save data')

        else:
            # use /etc/network/interfaces file

            # delete existing configuration for specified interface
            if not self.etcnetworkinterfaces.delete_interface(interface):
                self.logger.error(
                    'Unable to save wired static configuration (network/interfaces): unable to delete interface %s' % interface
                )
                raise CommandError('Unable to save data')

            # finally add new configuration
            if not self.etcnetworkinterfaces.add_static_interface(
                    interface,
                    EtcNetworkInterfaces.OPTION_HOTPLUG,
                    ip_address,
                    gateway, netmask):
                self.logger.error(
                    'Unable to save wired static configuration (network/interfaces): unable to add interface %s' % interface
                )
                raise CommandError('Unable to save data')

        # restart interface
        self.reconfigure_wired_interface(interface)

    def save_wired_dhcp_configuration(self, interface):
        """
        Save wired dhcp configuration

        Args:
            interface (string): interface name
        """
        if self.dhcpcd.is_installed():
            # save config using dhcpcd

            # delete configuration for specified interface (unconfigured interface in dhcpcd is considered as DHCP)
            if not self.dhcpcd.delete_interface(interface):
                self.logger.error('Unable to save wired dhcp configuration (dhcpcd): unable to delete interface %s' % interface)
                raise CommandError('Unable to save data')

        else:
            # save config using /etc/network/interface file

            # get interface config
            config = self.etcnetworkinterfaces.get_configuration(interface)
            self.logger.debug('Interface config in /etc/network/interfaces: %s' % config)
            if config is None:
                raise CommandError('Interface %s is not configured' % interface)

            # delete existing configuration for specified interface
            if not self.etcnetworkinterfaces.delete_interface(interface):
                self.logger.error(
                    'Unable to save wired dhcp configuration (network/interfaces): unable to delete interface %s' % interface
                )
                raise CommandError('Unable to save data')

            # finally add new configuration
            if not self.etcnetworkinterfaces.add_dhcp_interface(
                    interface,
                    EtcNetworkInterfaces.OPTION_AUTO + EtcNetworkInterfaces.OPTION_HOTPLUG):
                self.logger.error(
                    'Unable to save wired dhcp configuration (network/interfaces): unable to add interface %s' % interface
                )
                raise CommandError('Unable to save data')

        # restart interface
        self.reconfigure_wired_interface(interface)

        return True


    # -------------
    # WIRELESS AREA
    # -------------

    def __check_wifi_interface(self, interface, netifaces_infos):
        """
        Check wifi interface

        Args:
            interface (string): name of wired interface
            netifaces_infos (dict): infos from netifaces request
        """
        # get current status
        network, status, ip_address = self.wpacli.get_status(interface)
        # self.logger.debug('Wifi interface status: network:%s status:%s ip_address:%s' % (network, status, ip_address))

        # convert to network status
        if status == self.wpacli.STATE_COMPLETED and ip_address is not None:
            # wait before setting connected status while ip is not attributed (can take sometime to get ip)
            wifi_status = self.STATUS_CONNECTED
        elif status in (self.wpacli.STATE_4WAY_HANDSHAKE, self.wpacli.STATE_GROUP_HANDSHAKE):
            wifi_status = self.STATUS_WIFI_INVALID_PASSWORD
        elif status in (
                self.wpacli.STATE_SCANNING,
                self.wpacli.STATE_AUTHENTICATING,
                self.wpacli.STATE_ASSOCIATING,
                self.wpacli.STATE_ASSOCIATED):
            wifi_status = self.STATUS_CONNECTING
        else:
            wifi_status = self.STATUS_DISCONNECTED

        # no previous status, store it
        if interface not in self.network_status:
            self.logger.debug('Wifi interface "%s" status %s on network "%s"' % (interface, wifi_status, network))
            self.network_status[interface] = {
                'network': network,
                'status': wifi_status,
                'ipaddress': ip_address
            }
            return

        # drop status update of interface that have already been detected with invalid password
        if (self.network_status[interface]['status'] == self.STATUS_WIFI_INVALID_PASSWORD and
                status != self.wpacli.STATE_COMPLETED):
            return

        # update wifi_status and send event if necessary
        if wifi_status != self.network_status[interface]['status']:
            # send event for current status
            self.network_status_update.send(params={
                'interface': interface,
                'network': network,
                'status': wifi_status,
                'ipaddress': ip_address
            })

            # save new status
            self.logger.debug('Wifi interface "%s" status %s on network "%s"' % (interface, wifi_status, network))
            self.network_status[interface]['network'] = network
            self.network_status[interface]['status'] = wifi_status
            self.network_status[interface]['ipaddress'] = ip_address

    def __scan_wifi_networks(self, interface):
        """
        Scan wifi networks and store them in class member wifi_networks

        TODO:
            iwconfig/iwlist seems to be deprecated, we need to replace it with iw command
            https://dougvitale.wordpress.com/2011/12/21/deprecated-linux-networking-commands-and-their-replacements/

        Note:
            https://ubuntuforums.org/showthread.php?t=1402284 for different iwlist samples

        Args:
            interface (string): interface to use to scan networks

        Returns:
            dict: list of found wifi networks::

                {
                    network name (string): {
                        interface (string): interface on which wifi network was found
                        network (string): network name (essid)
                        encryption (string): network encryption (wpa|wpa2|wep|unsecured|unknown)
                        signallevel (float): signal level (in %)
                    },
                    ...
                }

        """
        # check params
        if interface is None or len(interface) == 0:
            raise MissingParameter('Interface parameter is missing')

        # get wireless configuration
        wifi_config = self.wpasupplicant.get_configurations()
        if interface in wifi_config:
            wifi_config = wifi_config[interface]
        else:
            # no config found for interface
            wifi_config = {}
        self.logger.debug('Wifi config for interface "%s": %s' % (interface, wifi_config))

        # get networks
        networks = self.iwlist.get_networks(interface)
        self.logger.debug('Wifi networks: %s' % networks)

        # set some configuration flags
        for network in networks.keys():
            networks[network]['hidden'] = False
            if network in wifi_config.keys():
                networks[network]['configured'] = True
                networks[network]['disabled'] = wifi_config[network]['disabled']
            else:
                networks[network]['configured'] = False
                networks[network]['disabled'] = False

        # add hidden network
        count = 0
        for network in wifi_config.keys():
            if wifi_config[network]['hidden']:
                networks[wifi_config[network]['network']] = {
                    'encryption': wifi_config[network]['encryption'],
                    'interface': None,
                    'network': wifi_config[network]['network'],
                    'configured': True,
                    'disabled': wifi_config[network]['disabled'],
                    'hidden': True
                }
                count += 1

        # refresh cache
        self.wifi_networks[interface] = networks

        return networks

    def refresh_wifi_networks(self):
        """
        Scan wifi networks for all connected interfaces

        Returns:
            dict: found wifi networks::

            {
                interface name (string): {
                    network name (string): {
                        interface (string): interface on which wifi network was found
                        network (string): network name (essid)
                        encryption (string): network encryption (wpa|wpa2|wep|unsecured|unknown)
                        signallevel (float): signal level (in %)
                        configured (bool): True if network has configuration
                        hidden (bool): True if network is hidden
                        disabled (bool): True if network disabled in configuration
                    },
                    ...
                },
                ...
            }

        """
        self.wifi_networks = {}
        self.wifi_network_names = []

        # get wifi adapters
        self.wifi_adapters = self.iw.get_adapters()
        self.logger.debug('Wifi adapters: %s' % self.wifi_adapters)

        # get wifi interfaces and connected network
        self.wifi_interfaces = self.iwconfig.get_interfaces()

        # scan networks for each interfaces
        for interface in self.wifi_interfaces.keys():
            # scan interface (update wifi_networks member)
            networks = self.__scan_wifi_networks(interface)

            # save network names
            self.wifi_network_names = self.wifi_network_names + list(set(networks) - set(self.wifi_network_names))

        self.last_wifi_networks_scan = int(time.time())

        self.logger.debug('Wifi networks: %s' % self.wifi_networks)
        self.logger.debug('Wifi network names: %s' % self.wifi_network_names)

        return self.wifi_networks

    def __monitor_wifi_interface(self, interface):
        """
        Function implemented to be used in task. It is used to monitor wifi interface to
        detect status changes (invalid password, connection, disconnection) and return
        the status to ui only
        """

    def save_wifi_network(self, interface, network, encryption, password=None, hidden=False):
        """
        Save wifi network configuration

        Args:
            interface (string): interface
            network (string): network to connect interface to
            encryption (string): encryption type (wpa|wpa2|wep|unsecured)
            password (string): network connection password
            hidden (bool): True if network is hidden

        Returns:
            bool: True if connection succeed

        Raises:
            CommandError
        """
        # check prams
        if interface is None or len(interface) == 0:
            raise MissingParameter('Parameter interface is missing')
        if encryption is None or len(encryption) == 0:
            raise MissingParameter('Parameter interface is missing')

        # save config in wpa_supplicant.conf file
        if not self.wpasupplicant.add_network(network, encryption, password, hidden, interface=interface):
            raise CommandError('Unable to save configuration')

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def delete_wifi_network(self, interface, network):
        """
        Delete specified network

        Args:
            network (string): network config to delete

        Returns:
            bool: True if network deleted
        """
        if not self.wpasupplicant.delete_network(network, interface=interface):
            raise CommandError('Unable to delete network')

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def update_wifi_network_password(self, interface, network, password):
        """
        Update wifi network configuration

        Args:
            interface (string): interface name
            network (string): network to connect interface to
            password (string): network connection password

        Returns:
            bool: True if update succeed

        Raises:
            CommandError
        """
        if not self.wpasupplicant.update_network_password(network, password, interface=interface):
            raise CommandError('Unable to update password')

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def enable_wifi_network(self, interface, network):
        """
        Enable wifi network

        Args:
            interface (string): interface name
            network (string): network name

        Returns:
            bool: True if network updated

        Raises:
            CommandError
        """
        if not self.wpasupplicant.enable_network(network, interface=interface):
            raise CommandError('Unable to enable network')

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def disable_wifi_network(self, interface, network):
        """
        Disable wifi network

        Args:
            interface (string): interface name
            network (string): network name

        Returns:
            bool: True if network updated

        Raises:
            CommandError
        """
        if not self.wpasupplicant.disable_network(network, interface=interface):
            raise CommandError('Unable to enable network')

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def reconfigure_wifi_interface(self, interface):
        """
        Reconfigure specified interface

        Args:
            interface (string): interface to reconfigure

        Returns:
            bool: True if command succeed
        """
        if interface is None or len(interface) == 0:
            raise MissingParameter('Parameter interface is missing')
        if interface not in self.wifi_interfaces.keys():
            raise InvalidParameter('Interface %s does\t exist or is not configured' % interface)

        # restart network interface
        if not self.ifupdown.restart_interface(interface):
            return False

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

