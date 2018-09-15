#!/usr/bin/env python
# -*- coding: utf-8 -*-
    
import logging
from raspiot.utils import InvalidParameter, MissingParameter, CommandError, CommandInfo
from raspiot.raspiot import RaspIotModule
from raspiot.libs.configs.wpasupplicantconf import WpaSupplicantConf
from raspiot.libs.configs.dhcpcdconf import DhcpcdConf
from raspiot.libs.configs.etcnetworkinterfaces import EtcNetworkInterfaces
from raspiot.libs.internals.console import AdvancedConsole, Console
from raspiot.libs.commands.ifconfig import Ifconfig
from raspiot.libs.commands.iw import Iw
from raspiot.libs.commands.iwlist import Iwlist
from raspiot.libs.commands.iwconfig import Iwconfig
from raspiot.libs.commands.ifupdown import Ifupdown
from raspiot.libs.commands.wpacli import Wpacli
from raspiot.libs.configs.cleepwificonf import CleepWifiConf
from raspiot.libs.internals.task import Task
import re
import time
import os
import uuid
import netifaces

__all__ = ['Network']


class Network(RaspIotModule):
    """
    Network module allows user to configure wired and wifi connection

    Note:
        - iw versus iwconfig (which is deprecated)
            https://donnutcompute.wordpress.com/2014/04/20/connect-to-wi-fi-via-command-line/
        - official raspberry pi foundation configuration guide
            https://www.raspberrypi.org/documentation/configuration/
            https://www.raspberrypi.org/documentation/configuration/wireless/wireless-cli.md
        - guide from ubuntu forum
            https://askubuntu.com/a/16588
        - another super guide ;)
            https://www.blackmoreops.com/2014/09/18/connect-to-wifi-network-from-command-line-in-linux/ 
        - nodejs wireless-tools lib
            https://github.com/bakerface/wireless-tools
    """
    MODULE_AUTHOR = u'Cleep'
    MODULE_VERSION = u'1.0.0'
    MODULE_PRICE = 0
    MODULE_DEPS = []
    MODULE_DESCRIPTION = u'Configure how your device connect to your network'
    MODULE_LOCKED = True
    MODULE_URL = None
    MODULE_TAGS = ['wireless', 'wifi', 'ethernet']
    MODULE_COUNTRY = None
    MODULE_URLINFO = None
    MODULE_URLHELP = None
    MODULE_URLINFO = None
    MODULE_URLBUGS = None

    STATUS_DISCONNECTED = 0
    STATUS_CONNECTING = 1
    STATUS_CONNECTED = 2
    STATUS_WIFI_INVALID_PASSWORD = 3

    def __init__(self, bus, debug_enabled):
        """
        Constructor

        Params:
            bus (MessageBus): bus instance
            debug_enabled (bool): debug status
        """
        #init
        RaspIotModule.__init__(self, bus, debug_enabled)

        #tools
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

        #members
        self.wifi_networks = {}
        self.wifi_network_names = []
        self.wifi_interfaces = {}
        self.wifi_adapters = {}
        self.network_status = {}
        self.last_wifi_networks_scan = 0
        self.__network_watchdog_task = None
        self.__network_is_down = True

        #events
        self.network_up_event = self._get_event(u'system.network.up')
        self.network_down_event = self._get_event(u'system.network.down')
        self.network_status_update = self._get_event(u'network.status.update')

    def _configure(self):
        """
        Module start
        """
        #refresh list of wifi networks
        try:
            self.refresh_wifi_networks()
        except:
            self.logger.exception(u'Exception occured when refreshing wifi networks:')
            self.crash_report.report_exception()

        #handle startup config if cleep wifi conf exists
        if self.cleepwifi.exists():
            self.logger.debug(u'Cleepwifi config file exists. Load wifi config')
            #read file content
            cleep_conf = self.cleepwifi.get_configuration()
            self.logger.debug(u'cleep_conf: %s' % cleep_conf)
            if cleep_conf:
                #search for existing config
                interface_found = None
                self.logger.debug(u'Wifi networks: %s' % self.wifi_networks)
                for interface in self.wifi_networks.keys():
                    if cleep_conf[u'network'] in self.wifi_networks[interface].keys() and not self.wifi_networks[interface][cleep_conf[u'network']][u'configured']:
                        self.logger.debug(u'Interface %s found' % interface)
                        interface_found = interface
                        break

                #add config if not already exists
                if interface_found:
                    #TODO handle hidden network
                    if not self.wpasupplicant.add_network(cleep_conf[u'network'], cleep_conf[u'encryption'], cleep_conf[u'password'], hidden=False, interface=interface_found, encrypt_password=False):
                        self.logger.error(u'Unable to use config from %s' % self.CLEEP_WIFI_CONF)
                    else:
                        self.reconfigure_wifi_interface(interface_found)
                        self.logger.info(u'Wifi config from Cleep loaded successfully')
                else:
                    self.logger.debug(u'No interface found or network already configured')

                #finally delete file
                self.cleepwifi.delete(self.cleep_filesystem)

        #launch network watchdog
        self.__network_watchdog_task = Task(1.0, self.__check_network_connection, self.logger)
        self.__network_watchdog_task.start()

    def _stop(self):
        """
        Stop module
        """
        if self.__network_watchdog_task:
            self.__network_watchdog_task.stop()

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

        #gather network data
        if self.dhcpcd.is_installed():
            #dhcpcd is installed (>=stretch), use dhcpcd.conf infos

            #see notes about network configuration in stretch and above:
            #https://raspberrypi.stackexchange.com/questions/37920/how-do-i-set-up-networking-wifi-static-ip-address/37921#37921

            #get wired configuration from dhcpcd
            configured_interfaces = {}
            dhcpcd_config = self.dhcpcd.get_configurations()
            current_status = self.ifconfig.get_configurations()
            self.logger.debug(u'dhcpcd_config: %s' % dhcpcd_config)
            self.logger.debug(u'current_status: %s' % current_status)
            self.logger.debug(u'wifi_interfaces: %s' % self.wifi_interfaces)

            #add more infos (iterates over current status because with dhcpcd dhcp interfaces have no configuration)
            for interface in current_status.keys():
                #add new entry in dict. Dict entry content is imitating output of etcnetworkinterfaces library.
                configured_interfaces[interface] = {
                    u'interface': interface,
                    u'mode': None,
                    u'address': None,
                    u'netmask': None,
                    u'gateway': None,
                    u'dns_nameservers': None
                }

                #fill config with dhcpcd data
                if interface in dhcpcd_config.keys():
                    #interface is configured
                    configured_interfaces[interface][u'mode'] = self.etcnetworkinterfaces.MODE_STATIC
                    configured_interfaces[interface][u'address'] = dhcpcd_config[u'ip_address']
                    configured_interfaces[interface][u'netmask'] = dhcpcd_config[u'netmask']
                    configured_interfaces[interface][u'gateway'] = dhcpcd_config[u'gateway']
                    configured_interfaces[interface][u'dns_nameservers'] = dhcpcd_config[u'dns_address']

                else:
                    #interface has no configuration, set it has dhcp
                    configured_interfaces[interface][u'mode'] = self.etcnetworkinterfaces.MODE_DHCP

                #fill config with wifi config
                if interface in self.wifi_interfaces.keys():
                    #wifi interface
                    configured_interfaces[interface][u'wifi'] = True

                    if self.wifi_interfaces[interface][u'network'] is not None:
                        #interface is connected
                        configured_interfaces[interface][u'wifi_network'] = self.wifi_interfaces[interface][u'network']
                    else:
                        #interface is not connected
                        configured_interfaces[interface][u'wifi_network'] = None
                else:
                    #interface is not wifi
                    configured_interfaces[interface][u'wifi'] = False
                    configured_interfaces[interface][u'wifi_network'] = None

            self.logger.debug('Configured_interfaces: %s' % configured_interfaces)

        else:
            #dhcpcd is not installed (<=jessie), use /etc/network/interfaces conf file

            #get configuration
            configured_interfaces = self.etcnetworkinterfaces.get_configurations()
            current_status = self.ifconfig.get_configurations()
            self.logger.debug(u'configured_interfaces: %s' % configured_interfaces)
            self.logger.debug(u'current_status: %s' % current_status)

            #remove lo interface from configured interfaces list
            if u'lo' in configured_interfaces.keys():
                del configured_interfaces[u'lo']

            #add more infos
            for interface in configured_interfaces.keys():
                #add wifi infos
                if interface in self.wifi_interfaces.keys():
                    #interface is wifi and connected
                    configured_interfaces[interface][u'wifi'] = True
                    configured_interfaces[interface][u'wifi_network'] = self.wifi_interfaces[interface][u'network']
                elif interface in configured_interfaces.keys() and configured_interfaces[interface][u'wpa_conf'] is not None:
                    #interface is wifi but not connected
                    configured_interfaces[interface][u'wifi'] = True
                    configured_interfaces[interface][u'wifi_network'] = None
                else:
                    #interface is not wifi
                    configured_interfaces[interface][u'wifi'] = False
                    configured_interfaces[interface][u'wifi_network'] = None

        #check network status (will be sent at end of function)
        self.__check_network_connection()

        #prepare networks list
        networks = []

        #add wired interface as network
        for interface in configured_interfaces.keys():
            if not configured_interfaces[interface][u'wifi']:
                #get interface status
                network_status = None
                if interface in current_status.keys():
                    network_status = current_status[interface]

                #save entry
                networks.append({
                    u'network': interface,
                    u'interface': interface,
                    u'wifi': False,
                    u'config': configured_interfaces[interface],
                    u'status': network_status
                })

        #add all wifi networks on range
        for interface in self.wifi_networks:
            self.logger.debug(u'self.wifi_networks[%s]: %s' % (interface, self.wifi_networks[interface]))
            for network_name in self.wifi_networks[interface]:
                #get interface configuration
                #interface_config = None
                #if interface in configured_interfaces.keys():
                #    interface_config = configured_interfaces[interface]

                #get wifi config
                wifi_config = None
                if network_name in self.wifi_networks[interface].keys():
                    wifi_config = self.wifi_networks[interface][network_name]
                
                #get interface status
                network_status = None
                if interface in current_status.keys():
                    network_status = current_status[interface]

                #save entry
                networks.append({
                    u'network': network_name,
                    u'interface': interface,
                    u'wifi': True,
                    u'config': wifi_config,
                    u'status': network_status
                })

        #prepare output
        output[u'networks'] = networks
        output[u'wifiinterfaces'] = self.wifi_interfaces.keys()
        output[u'lastwifiscan'] = self.last_wifi_networks_scan
        output[u'networkstatus'] = self.network_status

        return output

    def event_received(self, event):
        """
        Event received on bus

        Args:
            event (dist): event data
        """
        if event[u'event']==u'system.country.update':
            #update wpa_supplicant country code
            self.logger.debug(u'Received country update event: %s' % event)
            self.wpasupplicant.set_country(event[u'params'][u'country'])

    def __check_network_connection(self):
        """
        Check network connection
        Send event when network is up and when it is down
        Monitor wifi network status (disconnected/connected/invalid password)
        """
        #init
        wifi_interfaces = self.iwconfig.get_interfaces()
        connected = False
        interfaces = netifaces.interfaces()

        #check interfaces
        for interface in interfaces:
            #drop local interface
            if interface==u'lo':
                continue
            
            #check if at least one interface is connected
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses and len(addresses[netifaces.AF_INET])==1 and addresses[netifaces.AF_INET][0]['addr'].strip():
                connected = True

            #update interface status
            if interface in wifi_interfaces:
                #wifi interface
                self.__check_wifi_interface(interface, addresses)
            else:
                #ethernet interface
                self.__check_wired_interface(interface, addresses)

        #handle network connection status
        if connected and self.__network_is_down:
            self.__network_is_down = False
            self.network_up_event.send()
        elif not connected and not self.__network_is_down:
            self.__network_is_down = True
            self.network_down_event.send()

    #----------
    #WIRED AREA
    #----------

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
            self.network_status[interface][u'network'] = 'wired'
            self.network_status[interface][u'status'] = None
            self.network_status[interface][u'ipaddress'] = None

        try:
            #get old status to send update event after update if necessary
            old_status = self.network_status[interface][u'status']

            #update status
            if netifaces.AF_INET in netifaces_infos:
                self.network_status[interface][u'status'] = self.STATUS_CONNECTED
                self.network_status[interface][u'ipaddress'] = netifaces_infos[netifaces.AF_INET][0][u'addr']
            #TODO ipv6 appears more quickly than ipv4 so event sends status with ipv6. We need to find a way to handle both ipv4 and ipv6
            #elif netifaces.AF_INET6 in netifaces_infos:
            #    self.network_status[interface][u'status'] = self.STATUS_CONNECTED
            #    self.network_status[interface][u'ipaddress'] = netifaces_infos[netifaces.AF_INET6][0][u'addr']
            else:
                self.network_status[interface][u'status'] = self.STATUS_DISCONNECTED
                self.network_status[interface][u'ipaddress'] = None

            #send event
            if old_status is not None and old_status!=self.network_status[interface][u'status']:
                self.logger.debug('Wired interface "%s" status %s with ip "%s"' % (interface, self.network_status[interface][u'status'], self.network_status[interface][u'ipaddress']))
                self.network_status_update.send(params={
                    u'interface':interface,
                    u'network': self.network_status[interface][u'network'],
                    u'status': self.network_status[interface][u'status'],
                    u'ipaddress': self.network_status[interface][u'ipaddress']
                })

        except:
            self.logger.exception(u'Exception occured when trying to get wired interface "%s" status' % interface)

    def reconfigure_wired_interface(self, interface):
        """
        Restart network interface

        Params:
            interface (string): network interface name
        """
        self.ifupdown.restart_interface(interface)

    def save_wired_static_configuration(self, interface, ip_address, gateway, netmask, fallback):
        """
        Save wired static configuration

        Params:
            interface (string): interface to configure
            ip_address (string): desired ip address
            gateway (string): gateway address
            netmask (string): netmask
            fallback (bool): is configuration used as fallback
        """
        res = False

        #then add new one
        if self.dhcpcd.is_installed():
            #use dhcpcd
            
            #delete existing configuration for specified interface
            if not self.dhcpcd.delete_interface(interface):
                self.logger.error('Unable to save wired static configuration (dhcpcd): unable to delete interface %s' % interface)
                raise CommandError(u'Unable to save data')
            
            #finally add new configuration
            if fallback:
                if not self.dhcpcd.add_static_interface(interface, ip_address, gateway, netmask):
                    self.logger.error('Unable to save wired static configuration (dhcpcd): unable to add interface %s' % interface)
                    raise CommandError(u'Unable to save data')
            else:
                if not self.dhcpcd.add_fallback_interface(interface, ip_address, gateway, netmask):
                    self.logger.error('Unable to save wired fallback configuration (dhcpcd): unable to add interface %s' % interface)
                    raise CommandError(u'Unable to save data')

        else:
            #use /etc/network/interfaces file

            #delete existing configuration for specified interface
            if not self.etcnetworkinterfaces.delete_interface(interface):
                self.logger.error('Unable to save wired static configuration (network/interfaces): unable to delete interface %s' % interface)
                raise CommandError(u'Unable to save data')
            
            #finally add new configuration
            if not self.etcnetworkinterfaces.add_static_interface(interface, EtcNetworkInterfaces.OPTION_HOTPLUG, ip_address, gateway, netmask):
                self.logger.error('Unable to save wired static configuration (networkÃ/interfaces): unable to add interface %s' % interface)
                raise CommandError(u'Unable to save data')

        #restart interface
        self.reconfigure_wired_interface(interface)

        return True

    def save_wired_dhcp_configuration(self, interface):
        """
        Save wired dhcp configuration

        Params:
            interface (string): interface name
        """
        if self.dhcpcd.is_installed():
            #save config using dhcpcd

            #delete configuration for specified interface (unconfigured interface in dhcpcd is considered as DHCP)
            if not self.dhcpcd.delete_interface(interface):
                self.logger.error('Unable to save wired dhcp configuration (dhcpcd): unable to delete interface %s' % interface)
                raise CommandError(u'Unable to save data')

        else:
            #save config using /etc/network/interface file
            
            #get interface config
            config = self.etcnetworkinterfaces.get_configuration(interface)
            self.logger.debug(u'Interface config in /etc/network/interfaces: %s' % config)
            if config is None:
                raise CommandError(u'Interface %s is not configured' % interface)

            #delete existing configuration for specified interface
            if not self.etcnetworkinterfaces.delete_interface(interface):
                self.logger.error('Unable to save wired dhcp configuration (network/interfaces): unable to delete interface %s' % interface)
                raise CommandError(u'Unable to save data')
            
            #finally add new configuration
            if not self.etcnetworkinterfaces.add_dhcp_interface(interface, EtcNetworkInterfaces.OPTION_AUTO + EtcNetworkInterfaces.OPTION_HOTPLUG):
                self.logger.error('Unable to save wired dhcp configuration (network/interfaces): unable to add interface %s' % interface)
                raise CommandError(u'Unable to save data')

        #restart interface
        self.reconfigure_wired_interface(interface)

        return True


    #-------------
    #WIRELESS AREA
    #-------------

    def __check_wifi_interface(self, interface, netifaces_infos):
        """
        Check wifi interface

        Args:
            interface (string): name of wired interface
            netifaces_infos (dict): infos from netifaces request
        """
        #get current status
        network, status, ip_address = self.wpacli.get_status(interface)
        #self.logger.debug('Wifi interface status: network:%s status:%s ip_address:%s' % (network, status, ip_address))

        #convert to network status
        if status==self.wpacli.STATE_COMPLETED and ip_address is not None:
            #wait before setting connected status while ip is not attributed (can take sometime to get ip)
            wifi_status = self.STATUS_CONNECTED
        elif status in (self.wpacli.STATE_4WAY_HANDSHAKE, self.wpacli.STATE_GROUP_HANDSHAKE):
            wifi_status = self.STATUS_WIFI_INVALID_PASSWORD
        elif status in (self.wpacli.STATE_SCANNING, self.wpacli.STATE_AUTHENTICATING, self.wpacli.STATE_ASSOCIATING, self.wpacli.STATE_ASSOCIATED):
            wifi_status = self.STATUS_CONNECTING
        else:
            wifi_status = self.STATUS_DISCONNECTED

        #no previous status, store it
        if interface not in self.network_status:
            self.logger.debug('Wifi interface "%s" status %s on network "%s"' % (interface, wifi_status, network))
            self.network_status[interface] = {
                u'network': network,
                u'status': wifi_status,
                u'ipaddress': ip_address
            }
            return

        #drop status update of interface that have already been detected with invalid password
        if self.network_status[interface][u'status']==self.STATUS_WIFI_INVALID_PASSWORD and status!=self.wpacli.STATE_COMPLETED:
            return
            
        #update wifi_status and send event if necessary
        if wifi_status!=self.network_status[interface][u'status']:
            #send event for current status
            self.network_status_update.send(params={u'interface':interface, u'network':network, u'status':wifi_status, u'ipaddress':ip_address})

            #save new status
            self.logger.debug('Wifi interface "%s" status %s on network "%s"' % (interface, wifi_status, network))
            self.network_status[interface][u'network'] = network
            self.network_status[interface][u'status'] = wifi_status
            self.network_status[interface][u'ipaddress'] = ip_address

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
        #check params
        if interface is None or len(interface)==0:
            raise MissingParameter('Interface parameter is missing')

        #get wireless configuration
        wifi_config = self.wpasupplicant.get_configurations()
        if interface in wifi_config:
            wifi_config = wifi_config[interface]
        else:
            #no config found for interface
            wifi_config = {}
        self.logger.debug('Wifi config for interface "%s": %s' % (interface, wifi_config))

        #get networks
        networks = self.iwlist.get_networks(interface)
        self.logger.debug('Wifi networks: %s' % networks)

        #set some configuration flags
        for network in networks.keys():
            networks[network][u'hidden'] = False
            if network in wifi_config.keys():
                networks[network][u'configured'] = True
                networks[network][u'disabled'] = wifi_config[network][u'disabled']
            else:
                networks[network][u'configured'] = False
                networks[network][u'disabled'] = False

        #add hidden network
        count = 0
        for network in wifi_config.keys():
            if wifi_config[network][u'hidden']:
                networks[wifi_config[network][u'network']] = {
                    u'encryption': wifi_config[network][u'encryption'],
                    u'interface': None,
                    u'network': wifi_config[network][u'network'],
                    u'configured': True,
                    u'disabled': wifi_config[network][u'disabled'],
                    u'hidden': True
                }
                count += 1

        #refresh cache
        self.wifi_networks[interface] = networks

        return networks

    def refresh_wifi_networks(self):
        """
        Scan wifi networks for all connected interfaces

        Return:
            dict: found wifi networks
        """
        self.wifi_networks = {}
        self.wifi_network_names = []

        #get wifi adapters
        self.wifi_adapters = self.iw.get_adapters()
        self.logger.debug('Wifi adapters: %s' % self.wifi_adapters)

        #get wifi interfaces and connected network
        self.wifi_interfaces = self.iwconfig.get_interfaces()

        #scan networks for each interfaces
        for interface in self.wifi_interfaces.keys():
            #scan interface (update wifi_networks member)
            networks = self.__scan_wifi_networks(interface)

            #save network names
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
        #check prams
        if interface is None or len(interface)==0:
            raise MissingParameter(u'Parameter interface is missing')
        if encryption is None or len(encryption)==0:
            raise MissingParameter(u'Parameter interface is missing')

        #save config in wpa_supplicant.conf file
        if not self.wpasupplicant.add_network(network, encryption, password, hidden, interface=interface):
            raise CommandError('Unable to save configuration')

        #reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def delete_wifi_network(self, interface, network):
        """
        Delete specified network

        Args:
            network (string): network config to delete

        Return:
            bool: True if network deleted
        """
        if not self.wpasupplicant.delete_network(network, interface=interface):
            raise CommandError(u'Unable to delete network')

        #reconfigure interface
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
            raise CommandError(u'Unable to update password')

        #reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def enable_wifi_network(self, interface, network):
        """
        Enable wifi network

        Args:
            interface (string): interface name
            network (string): network name

        Return:
            bool: True if network updated

        Raises:
            CommandError
        """
        if not self.wpasupplicant.enable_network(network, interface=interface):
            raise CommandError(u'Unable to enable network')

        #reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def disable_wifi_network(self, interface, network):
        """
        Disable wifi network

        Args:
            interface (string): interface name
            network (string): network name

        Return:
            bool: True if network updated

        Raises:
            CommandError
        """
        if not self.wpasupplicant.disable_network(network, interface=interface):
            raise CommandError(u'Unable to enable network')

        #reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

    def reconfigure_wifi_interface(self, interface):
        """
        Reconfigure specified interface
    
        Args:
            interface (string): interface to reconfigure
    
        Return:
            bool: True if command succeed
        """
        if interface is None or len(interface)==0:
            raise MissingParameter('Parameter interface is missing')
        if interface not in self.wifi_interfaces.keys():
            raise InvalidParameter('Interface %s does\t exist or is not configured' % interface)
    
        #restart network interface
        if not self.ifupdown.restart_interface(interface):
            return False
    
        #reconfigure interface
        return self.wpacli.reconfigure_interface(interface)

