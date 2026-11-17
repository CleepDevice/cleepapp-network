# !/usr/bin/env python
#  -*- coding: utf-8 -*-

import time
import copy
import os
import re
import netifaces
from cleep.exception import CommandError, InvalidParameter, MissingParameter
from cleep.core import CleepModule
from cleep.libs.configs.wpasupplicantconf import WpaSupplicantConf
from cleep.libs.configs.dhcpcdconf import DhcpcdConf
from cleep.libs.configs.etcnetworkinterfaces import EtcNetworkInterfaces
from cleep.libs.commands.ifconfig import Ifconfig
from cleep.libs.commands.iw import Iw
from cleep.libs.commands.ip import Ip
from cleep.libs.commands.iwlist import Iwlist
from cleep.libs.commands.iwconfig import Iwconfig
from cleep.libs.commands.ifupdown import Ifupdown
from cleep.libs.commands.rfkill import Rfkill
from cleep.libs.commands.wpacli import Wpacli
from cleep.libs.configs.cleepwificonf import CleepWifiConf

__all__ = ["Network"]


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

    MODULE_AUTHOR = "Cleep"
    MODULE_VERSION = "2.2.0"
    MODULE_CATEGORY = "APPLICATION"
    MODULE_DEPS = []
    MODULE_DESCRIPTION = "Configure how your device connect to your network"
    MODULE_LONGDESCRIPTION = (
        "Application that helps you to configure device network connection"
    )
    MODULE_URL = None
    MODULE_TAGS = ["wireless", "wifi", "ethernet"]
    MODULE_COUNTRY = None
    MODULE_URLINFO = "https://github.com/CleepDevice/cleepapp-network/wiki"
    MODULE_URLHELP = "https://github.com/CleepDevice/cleepapp-network/wiki/Help"
    MODULE_URLSITE = None
    MODULE_URLBUGS = "https://github.com/CleepDevice/cleepapp-network/issues"

    STATUS_DISCONNECTED = 0
    STATUS_CONNECTING = 1
    STATUS_CONNECTED = 2
    STATUS_WIFI_INVALID_PASSWORD = 3

    TYPE_WIRED = "wired"
    TYPE_WIFI = "wifi"

    # WPA3-Personal (SAE). Kept here until core WpaSupplicantConf exposes it.
    ENCRYPTION_TYPE_WPA3 = "wpa3"
    CLEEP_NETWORK_CONF = "/boot/cleep-network.json"
    WPASUPPLICANT_DIR = "/etc/wpa_supplicant"

    NETWORK_SCAN_DURATION = 60
    ACTIVE_SCAN_TIMEOUT = 10 * 60

    def __init__(self, bootstrap, debug_enabled):
        """
        Constructor

        Args:
            bootstrap (dict): bootstrap object
            debug_enabled (bool): debug status
        """
        # init
        CleepModule.__init__(self, bootstrap, debug_enabled)

        # tools
        self.etcnetworkinterfaces = EtcNetworkInterfaces(self.cleep_filesystem)
        self.dhcpcd = DhcpcdConf(self.cleep_filesystem)
        self.wpasupplicantconf = WpaSupplicantConf(self.cleep_filesystem)
        self.iw = Iw()
        self.iwlist = Iwlist()
        self.ifconfig = Ifconfig()
        self.iwconfig = Iwconfig()
        self.ifupdown = Ifupdown()
        self.ip = Ip()
        self.wpacli = Wpacli()
        self.rfkill = Rfkill()
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
        self.__network_scan_duration = Network.NETWORK_SCAN_DURATION
        self.__network_scan_duration_timer = None

        # events
        self.network_up_event = self._get_event("network.status.up")
        self.network_down_event = self._get_event("network.status.down")
        self.network_status_update_event = self._get_event("network.status.update")

    def _configure(self):
        """
        Module start
        """
        # create default wpa_supplicant.conf file if it does not exist
        if not self.wpasupplicantconf.has_config():
            self.wpasupplicantconf.save_default_config()

    def _on_start(self):
        """
        Module is started
        """
        # refresh list of wifi networks
        try:
            self.refresh_wifi_networks()
        except Exception:
            self.logger.exception("Exception occured when refreshing wifi networks:")
            self.crash_report.report_exception()

        # create default wpa_supplicant conf for all interfaces
        add_country_for_interfaces = []
        for interface_name in self.wifi_interfaces:
            if not self.wpasupplicantconf.has_config(interface=interface_name):
                self.wpasupplicantconf.save_default_config(interface=interface_name)

            if not self.wpasupplicantconf.has_country(interface=interface_name):
                add_country_for_interfaces.append(interface_name)

        # set wpasupplicant country code
        if add_country_for_interfaces:
            resp = self.send_command("get_country", "parameters")
            if not resp.error:
                self.logger.info(
                    'Set country "%s" to wpasupplicant files', resp.data["alpha2"]
                )
                self.wpasupplicantconf.set_country_alpha2(resp.data["alpha2"])

            for interface_name in add_country_for_interfaces:
                self.wpacli.reconfigure_interface(interface_name)

        # handle startup wifi config (cleep-network.json from desktop, legacy cleepwifi.conf)
        bootstrap = self._get_bootstrap_wifi_configuration()
        if bootstrap:
            source, conf, encrypt_password, cleanup = bootstrap
            self.logger.info("%s file found. Load wifi config", source)
            try:
                self._load_bootstrap_wifi_conf(
                    conf, encrypt_password=encrypt_password, source=source
                )
            except Exception:
                self.logger.exception("Error loading %s file:", source)
                self.crash_report.report_exception()
            finally:
                cleanup()

        # enable wifi with rfkill
        if self.rfkill.is_installed():
            self.rfkill.unblock_device(None)

        # launch network watchdog
        self.__network_watchdog_task = self.task_factory.create_task(1.0, self._check_network_connection)
        self.__network_watchdog_task.start()

    def _on_stop(self):
        """
        Stop module
        """
        if self.__network_watchdog_task:
            self.__network_watchdog_task.stop()
        if self.__network_scan_duration_timer:
            self.__network_scan_duration_timer.stop()

    def _get_allowed_encryptions(self):
        """
        Return encryption types accepted by this module (core types + WPA3).

        Returns:
            list: encryption type strings
        """
        encryptions = list(WpaSupplicantConf.ENCRYPTION_TYPES)
        if Network.ENCRYPTION_TYPE_WPA3 not in encryptions:
            encryptions.append(Network.ENCRYPTION_TYPE_WPA3)
        return encryptions

    def _wpa_supplicant_path(self, interface=None):
        """
        Return wpa_supplicant conf path for interface.

        Args:
            interface (str|None): interface name

        Returns:
            str: conf filepath
        """
        interface_prefix = "-%s" % interface if interface else ""
        return os.path.join(
            Network.WPASUPPLICANT_DIR,
            "wpa_supplicant%s.conf" % interface_prefix,
        )

    def _is_wpa3_network(self, network_name, interface=None):
        """
        Return True if network block uses SAE (WPA3-Personal).

        Args:
            network_name (str): SSID
            interface (str|None): interface name

        Returns:
            bool: True if WPA3/SAE network
        """
        lines = self.cleep_filesystem.read_data(self._wpa_supplicant_path(interface))
        if not lines or not isinstance(lines, (list, tuple)):
            return False
        content = "".join(lines)
        for match in re.finditer(r"network\s*=\s*\{([^}]*)\}", content, re.DOTALL):
            block = match.group(1)
            ssid_match = re.search(r'ssid\s*=\s*"([^"]*)"', block)
            if not ssid_match or ssid_match.group(1) != network_name:
                continue
            return bool(re.search(r"key_mgmt\s*=\s*SAE\b", block))
        return False

    def _add_wpa3_network(self, network_name, password, hidden=False, interface=None):
        """
        Append a WPA3-Personal (SAE) network block to wpa_supplicant.conf.

        Args:
            network_name (str): SSID
            password (str): plaintext passphrase (SAE requires quoted passphrase)
            hidden (bool): hidden network flag
            interface (str|None): interface name

        Returns:
            bool: True if network added

        Raises:
            MissingParameter, InvalidParameter
        """
        if network_name is None or len(network_name) == 0:
            raise MissingParameter('Parameter "network" is missing')
        if password is None or len(password) == 0:
            raise MissingParameter('Parameter "password" is missing')
        if self.wpasupplicantconf.get_configuration(network_name, interface) is not None:
            raise InvalidParameter('Network "%s" is already configured' % network_name)

        if not self.wpasupplicantconf.has_config(interface):
            self.wpasupplicantconf.save_default_config(interface)

        def escape_conf(value):
            return value.replace("\\", "\\\\").replace('"', '\\"')

        block = [
            "\nnetwork={\n",
            '\tssid="%s"\n' % escape_conf(network_name),
            "\tkey_mgmt=SAE\n",
            '\tpsk="%s"\n' % escape_conf(password),
        ]
        if hidden:
            block.append("\tscan_ssid=1\n")
        block.append("}\n")

        path = self._wpa_supplicant_path(interface)
        lines = self.cleep_filesystem.read_data(path)
        if lines is None:
            return False
        return self.cleep_filesystem.write_data(path, "".join(lines) + "".join(block))

    def _add_wifi_network(
        self,
        network_name,
        encryption,
        password,
        hidden=False,
        interface=None,
        encrypt_password=True,
    ):
        """
        Add wifi network to wpa_supplicant, with WPA3 fallback when core lacks it.

        Args:
            network_name (str): SSID
            encryption (str): encryption type
            password (str): password
            hidden (bool): hidden network flag
            interface (str|None): interface name
            encrypt_password (bool): encrypt WPA/WPA2 password via wpa_passphrase

        Returns:
            bool: True if network added
        """
        if (
            encryption == Network.ENCRYPTION_TYPE_WPA3
            and Network.ENCRYPTION_TYPE_WPA3
            not in WpaSupplicantConf.ENCRYPTION_TYPES
        ):
            return self._add_wpa3_network(
                network_name, password, hidden=hidden, interface=interface
            )

        return self.wpasupplicantconf.add_network(
            network_name,
            encryption,
            password,
            hidden=hidden,
            interface=interface,
            encrypt_password=encrypt_password,
        )

    def _get_bootstrap_wifi_configuration(self):
        """
        Return first available bootstrap wifi config from boot partition.

        Prefers cleep-network.json (CleepDesktop), falls back to legacy cleepwifi.conf.

        Returns:
            tuple|None: (source, conf, encrypt_password, cleanup) or None
        """
        if os.path.exists(Network.CLEEP_NETWORK_CONF):
            conf = self.cleep_filesystem.read_json(Network.CLEEP_NETWORK_CONF)
            return (
                "cleep-network.json",
                conf,
                True,
                lambda: self.cleep_filesystem.rm(Network.CLEEP_NETWORK_CONF),
            )

        if self.cleepwifi.exists():
            return (
                "cleepwifi.conf",
                self.cleepwifi.get_configuration(),
                False,
                lambda: self.cleepwifi.delete(self.cleep_filesystem),
            )

        return None

    def _load_cleep_wifi_conf(self):
        """
        Load cleepwifi.conf

        Notes:
            This function does not check file existence
        """
        self._load_bootstrap_wifi_conf(
            self.cleepwifi.get_configuration(),
            encrypt_password=False,
            source="cleepwifi.conf",
        )

    def _load_bootstrap_wifi_conf(self, cleep_conf, encrypt_password=False, source="cleepwifi.conf"):
        """
        Apply bootstrap wifi configuration to wpa_supplicant.

        Args:
            cleep_conf (dict): configuration (network, password, encryption, hidden)
            encrypt_password (bool): True when password is plaintext (cleep-network.json)
            source (str): filename used in log messages
        """
        self.logger.debug("cleep_conf (%s): %s", source, cleep_conf)
        if not cleep_conf:
            self.logger.warning("%s file content is empty or invalid", source)
            return

        # search for network in interface
        found_interface = None
        found_encryption = cleep_conf["encryption"]
        self.logger.debug("Wifi networks: %s", self.wifi_networks)
        for interface_name, networks in self.wifi_networks.items():
            if (
                cleep_conf["network"] in networks
                and not networks[cleep_conf["network"]]["configured"]
            ):
                self.logger.debug('Interface "%s" found', interface_name)
                found_interface = interface_name
                # Scan often reports WPA2 for WPA3 APs; keep file encryption for WPA3
                if cleep_conf["encryption"] != Network.ENCRYPTION_TYPE_WPA3:
                    found_encryption = networks[cleep_conf["network"]]["encryption"]
                break
        if cleep_conf["hidden"] and not found_interface and self.wifi_networks:
            # network is declared as hidden, save hidden network in first available interface
            found_interface = list(self.wifi_networks.keys())[0]

        # add config if not already exists
        if found_interface or cleep_conf["hidden"]:
            if not self._add_wifi_network(
                cleep_conf["network"],
                found_encryption,
                cleep_conf["password"],
                hidden=cleep_conf["hidden"],
                interface=found_interface,
                encrypt_password=encrypt_password,
            ):
                self.logger.error("Unable to use config from %s", source)
            else:
                if found_interface:
                    self.reconfigure_wifi_interface(found_interface)
                self.logger.info("Wifi config from %s loaded successfully", source)
        else:
            self.logger.warning(
                'Interface was not found for network "%s" or network is already configured',
                cleep_conf["network"],
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
        self.logger.trace("Current_status: %s", current_status)
        self.logger.debug("wifi_interfaces: %s", self.wifi_interfaces)

        # gather network data
        if self.dhcpcd.is_installed():
            # dhcpcd is installed (>=stretch), use dhcpcd.conf infos
            configured_interfaces = self._get_network_config_from_dhcpcd(
                current_status.keys()
            )
        else:
            # dhcpcd is not installed (<=jessie), use /etc/network/interfaces conf file
            configured_interfaces = self._get_network_config_from_network_interfaces()
        self.logger.trace("Configured_interfaces: %s", configured_interfaces)

        # prepare networks list
        all_networks = []

        # add wired interface as network
        for interface_name, configured_interface in configured_interfaces.items():
            if not configured_interface["wifi"]:
                # save entry
                all_networks.append(
                    {
                        "network": interface_name,
                        "interface": interface_name,
                        "wifi": False,
                        "config": configured_interface,
                        "status": current_status[interface_name]
                        if interface_name in current_status
                        else None,
                    }
                )

        # add all wifi networks on range
        for interface_name, networks in self.wifi_networks.items():
            self.logger.trace("interface %s: %s", interface_name, networks)
            for network_name, network in networks.items():
                # save entry
                all_networks.append(
                    {
                        "network": network_name,
                        "interface": interface_name,
                        "wifi": True,
                        "config": network,
                        "status": current_status[interface_name]
                        if interface_name in current_status
                        else None,
                    }
                )

        # prepare output
        output["networks"] = all_networks
        output["wifiinterfaces"] = list(self.wifi_interfaces.keys())
        output["lastwifiscan"] = self.last_wifi_networks_scan
        output["networkstatus"] = self.network_status

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
                    wifi (bool): True if interface is wifi
                    wifinetwork (string): name of network if device is connected via wifi
                },
                ...
            }

        """
        # get wired configuration from dhcpcd
        configured_interfaces = {}
        dhcpcd_config = self.dhcpcd.get_configurations()
        self.logger.debug("dhcpcd_config: %s", dhcpcd_config)

        # add more infos (iterates over current status because with dhcpcd does not return dhcp configured interfaces)
        for interface_name in interfaces_names:
            # add new entry. Dict entry content is imitating output of etcnetworkinterfaces library.
            configured_interfaces[interface_name] = {
                "interface": interface_name,
                "mode": None,
                "address": None,
                "netmask": None,
                "gateway": None,
                "dnsnameservers": None,
                "wifi": None,
                "wifinetwork": None,
            }

            # fill config with dhcpcd data
            if interface_name in dhcpcd_config:
                # interface is configured
                configured_interfaces[interface_name].update(
                    {
                        "mode": self.etcnetworkinterfaces.MODE_STATIC,
                        "address": dhcpcd_config[interface_name]["ip_address"],
                        "netmask": dhcpcd_config[interface_name]["netmask"],
                        "gateway": dhcpcd_config[interface_name]["gateway"],
                        "dnsnameservers": dhcpcd_config[interface_name]["dns_address"],
                    }
                )
            else:
                # interface has no configuration, set mode has dhcp
                configured_interfaces[interface_name].update(
                    {"mode": self.etcnetworkinterfaces.MODE_DHCP}
                )

            # fill config with wifi config
            if interface_name in self.wifi_interfaces:
                # wifi interface
                configured_interfaces[interface_name].update(
                    {
                        "wifi": True,
                        "wifinetwork": self.wifi_interfaces[interface_name]["network"],
                    }
                )
            else:
                # interface is not wifi
                configured_interfaces[interface_name].update(
                    {
                        "wifi": False,
                        "wifinetwork": None,
                    }
                )

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
                    mode (string): interface mode (see etcnetworkinterface MODE_XXX)
                    address (string): ip address
                    netmask (string): netmask address
                    gateway (string): gateway address
                    dnsnameservers (string): dns nameservers
                    wifi (bool): True if interface is wifi
                    wifinetwork (string): name of network if device is connected via wifi
                },
                ...
            }

        """
        # get configuration
        configured_interfaces = self.etcnetworkinterfaces.get_configurations()

        # remove useless lo interface
        if "lo" in configured_interfaces:
            configured_interfaces.pop("lo")

        # add more infos
        for interface_name, configured_interface in configured_interfaces.items():
            # add wifi infos
            if interface_name in self.wifi_interfaces:
                # interface is wifi and connected
                configured_interface.update(
                    {
                        "wifi": True,
                        "wifinetwork": self.wifi_interfaces[interface_name]["network"],
                    }
                )
            elif configured_interface["wpaconf"] is not None:
                # interface is wifi but not connected
                configured_interface.update(
                    {
                        "wifi": True,
                        "wifinetwork": None,
                    }
                )
            else:
                # interface is not wifi
                configured_interface.update(
                    {
                        "wifi": False,
                        "wifinetwork": None,
                    }
                )

        # fix returned config
        for configured_interface in configured_interfaces.values():
            if "auto" in configured_interface:
                configured_interface.pop("auto")
            if "broadcast" in configured_interface:
                configured_interface.pop("broadcast")
            if "hotplug" in configured_interface:
                configured_interface.pop("hotplug")
            if "dnsdomain" in configured_interface:
                configured_interface.pop("dnsdomain")
            if "wpaconf" in configured_interface:
                configured_interface.pop("wpaconf")

        return configured_interfaces

    def on_event(self, event):
        """
        Event received on bus

        Args:
            event (dist): event data
        """
        if event["event"] == "parameters.country.update":
            # update wpa_supplicant country code
            self.logger.debug("Received country update event: %s", event)
            self.wpasupplicantconf.set_country_alpha2(event["params"]["alpha2"])

    def enable_active_network_scan(self):
        """
        Enable active network scan. It means application will scan every seconds network
        connectivity.

        As it consumes device ressources, this feature will be automatically
        disabled after configured amount of time. It can be disabled manually calling
        disable_active_network_scan.
        """
        self.logger.debug("Enable active network scan")
        self.__network_scan_duration = 1

        if self.__network_scan_duration_timer:
            self.__network_scan_duration_timer.stop()

        self.__network_scan_duration_timer = self.task_factory.create_task(
            Network.ACTIVE_SCAN_TIMEOUT, self.disable_active_network_scan
        )
        self.__network_scan_duration_timer.start()

    def disable_active_network_scan(self):
        """
        Disable active network scan
        """
        self.logger.debug("Disable active network scan")
        if self.__network_scan_duration_timer:
            self.__network_scan_duration_timer.stop()
            self.__network_scan_duration_timer = None

        self.__network_scan_duration = Network.NETWORK_SCAN_DURATION

    def _check_network_connection(self):
        """
        Check network connection sending event when network is up or down

        It also monitor wifi network status (disconnected/connected/invalid password)
        """
        # Performance optimization: do not check network connection each seconds all the time.
        # To reduce scan frequency frontend enables active scan (each seconds) when user loads network
        # config page and this for a configured duration. After this time, scan duration is set to
        # its optimized value NETWORK_SCAN_DURATION
        if self.network_status and int(time.time()) % self.__network_scan_duration != 0:
            return

        # init
        wifi_interfaces = self.iwconfig.get_interfaces()
        connected = False

        # check interfaces
        for interface_name in netifaces.interfaces():
            # drop local interface
            if interface_name == "lo":
                continue

            # check if at least one interface is connected
            addresses = netifaces.ifaddresses(interface_name)
            if (
                netifaces.AF_INET in addresses
                and len(addresses[netifaces.AF_INET]) == 1
                and addresses[netifaces.AF_INET][0]["addr"].strip()
            ):
                connected = True

            # update interface status
            if interface_name in wifi_interfaces:
                # wireless interface
                self._check_wifi_interface_status(copy.copy(interface_name))
            else:
                # ethernet interface
                self._check_wired_interface_status(copy.copy(interface_name))

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

    def _check_wired_interface_status(self, interface_name):
        """
        Check wired interface status

        Args:
            interface_name (string): name of wired interface
        """
        if interface_name not in self.network_status:
            self.network_status[interface_name] = {
                "network": self.TYPE_WIRED,
                "status": None,
                "ipaddress": None,
            }

        # get old status to send update event after update if necessary
        previous_status = self.network_status[interface_name]["status"]

        # update status
        addresses = netifaces.ifaddresses(interface_name)
        if netifaces.AF_INET in addresses:
            self.network_status[interface_name].update(
                {
                    "status": self.STATUS_CONNECTED,
                    "ipaddress": copy.copy(addresses[netifaces.AF_INET][0]["addr"]),
                }
            )
        # TODO ipv6 appears more quickly than ipv4 so event sends status with ipv6.
        # We need to find a way to handle both ipv4 and ipv6
        # elif netifaces.AF_INET6 in netifaces_infos:
        #     self.network_status[interface].update({
        #        'status': self.STATUS_CONNECTED,
        #        'ipaddress': copy.copy(netifaces_infos[netifaces.AF_INET6][0]['addr'],
        #     })
        else:
            self.network_status[interface_name].update(
                {
                    "status": self.STATUS_DISCONNECTED,
                    "ipaddress": None,
                }
            )

        # send event
        self.logger.debug("======> %s %s", previous_status, self.network_status)
        if (
            previous_status is not None
            and previous_status != self.network_status[interface_name]["status"]
        ):
            self.logger.debug(
                'Wired interface "%s" status %s with ip "%s"',
                interface_name,
                self.network_status[interface_name]["status"],
                self.network_status[interface_name]["ipaddress"],
            )
            self.network_status_update_event.send(
                params={
                    "type": self.TYPE_WIRED,
                    "interface": interface_name,
                    "network": self.network_status[interface_name]["network"],
                    "status": self.network_status[interface_name]["status"],
                    "ipaddress": self.network_status[interface_name]["ipaddress"],
                }
            )

    def reconfigure_wired_interface(self, interface_name):
        """
        Restart network interface

        Args:
            interface_name (string): network interface name
        """
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
            ]
        )

        if self.dhcpcd.is_installed():
            self.ip.restart_interface(interface_name)
        else:
            self.ifupdown.restart_interface(interface_name)

    def save_wired_static_configuration(
        self, interface_name, ip_address, gateway, netmask, fallback
    ):
        """
        Save wired static configuration

        Args:
            interface_name (string): interface name to configure
            ip_address (string): desired ip address
            gateway (string): gateway address
            netmask (string): netmask
            fallback (bool): is configuration used as fallback (>=jessie)
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
                {"name": "ip_address", "value": ip_address, "type": str},
                {"name": "gateway", "value": gateway, "type": str},
                {"name": "netmask", "value": netmask, "type": str},
                {"name": "fallback", "value": fallback, "type": bool},
            ]
        )

        # add new one
        if self.dhcpcd.is_installed():
            # use dhcpcd

            # delete existing configuration for specified interface if exists
            self.dhcpcd.delete_interface(interface_name)

            # add new configuration
            if not fallback:
                if not self.dhcpcd.add_static_interface(
                    interface_name, ip_address, gateway, netmask
                ):
                    self.logger.error(
                        "Unable to save wired static configuration (dhcpcd): unable to add interface %s",
                        interface_name,
                    )
                    raise CommandError("Unable to save configuration")
            else:
                if not self.dhcpcd.add_fallback_interface(
                    interface_name, ip_address, gateway, netmask
                ):
                    self.logger.error(
                        "Unable to save wired fallback configuration (dhcpcd): unable to add interface %s",
                        interface_name,
                    )
                    raise CommandError("Unable to save configuration")

        else:
            # use /etc/network/interfaces file

            # delete existing configuration for specified interface if exists
            self.etcnetworkinterfaces.delete_interface(interface_name)

            # finally add new configuration
            if not self.etcnetworkinterfaces.add_static_interface(
                interface_name,
                EtcNetworkInterfaces.OPTION_HOTPLUG,
                ip_address,
                gateway,
                netmask,
            ):
                self.logger.error(
                    "Unable to save wired static configuration (interfaces): unable to add interface %s",
                    interface_name,
                )
                raise CommandError("Unable to save configuration")

        # restart interface
        self.reconfigure_wired_interface(interface_name)

    def save_wired_dhcp_configuration(self, interface_name):
        """
        Save wired dhcp configuration

        Args:
            interface_name (string): interface name
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
            ]
        )

        if self.dhcpcd.is_installed():
            # save config using dhcpcd

            # delete configuration for specified interface (unconfigured interface in dhcpcd is considered as DHCP)
            self.dhcpcd.delete_interface(interface_name)

        else:
            # save config using /etc/network/interface file

            # delete existing configuration for specified interface
            self.etcnetworkinterfaces.delete_interface(interface_name)

            # finally add new configuration
            if not self.etcnetworkinterfaces.add_dhcp_interface(
                interface_name,
                EtcNetworkInterfaces.OPTION_AUTO + EtcNetworkInterfaces.OPTION_HOTPLUG,
            ):
                self.logger.error(
                    "Unable to save wired dhcp configuration (interfaces): unable to add interface %s",
                    interface_name,
                )
                raise CommandError("Unable to save configuration")

        # restart interface
        self.reconfigure_wired_interface(interface_name)

    # -------------
    # WIRELESS AREA
    # -------------

    def _check_wifi_interface_status(self, interface_name):
        """
        Check wifi interface status

        Args:
            interface_name (string): name of wired interface
        """
        # make sure network status exists
        if interface_name not in self.network_status:
            self.network_status[interface_name] = {
                "network": None,
                "status": self.STATUS_DISCONNECTED,
                "ipaddress": None,
            }

        # status
        old_status = self.network_status[interface_name]["status"]
        current_status = self.wpacli.get_status(interface_name)
        self.logger.trace("Wifi interface status (from wpacli): %s", current_status)

        # convert to network status
        if (
            current_status["state"] == Wpacli.STATE_COMPLETED
            and current_status["ipaddress"] is not None
        ):
            # wait before setting connected status while ip is not attributed (can take sometime to get ip)
            wifi_status = self.STATUS_CONNECTED
        elif (
            current_status["state"] == Wpacli.STATE_COMPLETED
            and current_status["ipaddress"] is None
        ):
            # connection is completed but there is no ip yet
            wifi_status = self.STATUS_CONNECTING
        elif current_status["state"] in (
            Wpacli.STATE_4WAY_HANDSHAKE,
            Wpacli.STATE_GROUP_HANDSHAKE,
        ):
            wifi_status = self.STATUS_WIFI_INVALID_PASSWORD
        elif current_status["state"] in (
            Wpacli.STATE_SCANNING,
            Wpacli.STATE_AUTHENTICATING,
            Wpacli.STATE_ASSOCIATING,
            Wpacli.STATE_ASSOCIATED,
        ):
            wifi_status = self.STATUS_CONNECTING
        else:
            wifi_status = self.STATUS_DISCONNECTED
        self.logger.trace("Wifi status: %s", wifi_status)

        # force status to invalid password because network try to connect again after a while
        # and we want to keep status that password was invalid
        if (
            old_status == self.STATUS_WIFI_INVALID_PASSWORD
            and wifi_status == self.STATUS_CONNECTING
        ):
            wifi_status = self.STATUS_WIFI_INVALID_PASSWORD

        # update current network status
        self.network_status[interface_name].update(
            {
                "network": copy.copy(current_status["network"]),
                "status": wifi_status,
                "ipaddress": copy.copy(current_status["ipaddress"]),
            }
        )

        # send event if necessary
        if old_status != wifi_status:
            self.logger.debug(
                'Wifi interface "%s" status: %s',
                interface_name,
                self.network_status[interface_name],
            )
            self.network_status_update_event.send(
                params={
                    "type": self.TYPE_WIFI,
                    "interface": interface_name,
                    "network": self.network_status[interface_name]["network"],
                    "status": self.network_status[interface_name]["status"],
                    "ipaddress": self.network_status[interface_name]["ipaddress"],
                }
            )

    def _scan_wifi_networks(self, interface_name):
        """
        Scan wifi networks and store them in class member wifi_networks

        Notes:
            TODO:
            iwconfig/iwlist seems to be deprecated, we need to replace it with iw command
            https://dougvitale.wordpress.com/2011/12/21/deprecated-linux-networking-commands-and-their-replacements/

        Notes:
            https://ubuntuforums.org/showthread.php?t=1402284 for different iwlist samples

        Args:
            interface_name (string): interface to use to scan networks

        Returns:
            dict: list of found wifi networks, also update internal wifi_networks variable for cache::

                {
                    network name (string): {
                        interface (string): interface name on which wifi network was found
                        network (string): network name (essid)
                        encryption (string): network encryption (wpa|wpa2|wep|unsecured|unknown)
                        signallevel (float): signal level (in %)
                    },
                    ...
                }

        """
        # get wireless configuration
        wifi_configs = self.wpasupplicantconf.get_configurations()
        wifi_config = (
            wifi_configs[interface_name] if interface_name in wifi_configs else {}
        )
        self.logger.debug(
            'Wifi config for interface "%s": %s', interface_name, wifi_config
        )

        # get networks
        networks = self.iwlist.get_networks(interface_name)
        self.logger.debug("Wifi networks: %s", networks)

        # set some configuration flags
        for network_name, network in networks.items():
            network["hidden"] = False
            if network_name in wifi_config:
                network["configured"] = True
                network["disabled"] = wifi_config[network_name]["disabled"]
                if self._is_wpa3_network(network_name, interface_name):
                    network["encryption"] = Network.ENCRYPTION_TYPE_WPA3
            else:
                network["configured"] = False
                network["disabled"] = False

        # add hidden network
        for network_name, network_config in wifi_config.items():
            if network_config["hidden"]:
                encryption = network_config["encryption"]
                if self._is_wpa3_network(network_config["network"], interface_name):
                    encryption = Network.ENCRYPTION_TYPE_WPA3
                networks[network_config["network"]] = {
                    "encryption": encryption,
                    "interface": interface_name,
                    "network": network_config["network"],
                    "configured": True,
                    "disabled": network_config["disabled"],
                    "hidden": True,
                    "signallevel": None,
                }

        # refresh cache
        self.wifi_networks[interface_name] = networks

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
        self.logger.debug("Wifi adapters: %s", self.wifi_adapters)

        # get wifi interfaces and connected network
        self.wifi_interfaces = self.iwconfig.get_interfaces()

        # scan networks for each interfaces
        for interface in self.wifi_interfaces:
            # scan interface (update wifi_networks member)
            networks = self._scan_wifi_networks(interface)

            # save network names
            self.wifi_network_names = self.wifi_network_names + list(
                set(networks) - set(self.wifi_network_names)
            )

        self.last_wifi_networks_scan = int(time.time())

        self.logger.debug("Wifi networks: %s", self.wifi_networks)
        self.logger.debug("Wifi network names: %s", self.wifi_network_names)

        return self.wifi_networks

    def save_wifi_network_configuration(
        self, interface_name, network_name, encryption, password=None, hidden=False
    ):
        """
        Save wifi network configuration

        Args:
            interface_name (str): interface name
            network_name (str): network to connect interface to
            encryption (str): encryption type (see WpaSupplicantConf.ENCRYPTION_TYPE_XXX + wpa3)
            password (str, optional): network connection password. Defaults to None.
            hidden (bool, optional): True if network is hidden. Defaults to False.

        Returns:
            bool: True if connection succeed
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
                {"name": "network_name", "value": network_name, "type": str},
                {
                    "name": "encryption",
                    "value": encryption,
                    "type": str,
                    "validator": lambda val: val in self._get_allowed_encryptions(),
                },
            ]
        )

        # save config in wpa_supplicant.conf file
        if not self._add_wifi_network(
            network_name, encryption, password, hidden, interface=interface_name
        ):
            raise CommandError("Unable to save network configuration")

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface_name)

    def delete_wifi_network_configuration(self, interface_name, network_name):
        """
        Delete specified network configuration

        Args:
            interface_name (string): interface name
            network_name (string): network config to delete

        Returns:
            bool: True if network deleted
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
                {"name": "network_name", "value": network_name, "type": str},
            ]
        )

        if not self.wpasupplicantconf.delete_network(
            network_name, interface=interface_name
        ):
            raise CommandError("Unable to delete network configuration")

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface_name)

    def update_wifi_network_password(self, interface_name, network_name, password):
        """
        Update wifi network configuration

        Args:
            interface_name (str): interface name
            network_name (str): network to connect interface to
            password (str): network connection password

        Returns:
            bool: True if update succeed
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
                {"name": "network_name", "value": network_name, "type": str},
                {"name": "password", "value": password, "type": str},
            ]
        )

        # WPA3/SAE: core update path would rewrite the network as WPA2-PSK
        if self._is_wpa3_network(network_name, interface_name):
            config = self.wpasupplicantconf.get_configuration(
                network_name, interface_name
            )
            if config is None:
                raise CommandError("Unable to update network password")
            if not self.wpasupplicantconf.delete_network(
                network_name, interface=interface_name
            ):
                raise CommandError("Unable to update network password")
            if not self._add_wpa3_network(
                network_name,
                password,
                hidden=config.get("hidden", False),
                interface=interface_name,
            ):
                raise CommandError("Unable to update network password")
            return self.wpacli.reconfigure_interface(interface_name)

        if not self.wpasupplicantconf.update_network_password(
            network_name, password, interface=interface_name
        ):
            raise CommandError("Unable to update network password")

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface_name)

    def enable_wifi_network(self, interface_name, network_name):
        """
        Enable wifi network

        Args:
            interface_name (string): interface name
            network_name (string): network name

        Returns:
            bool: True if network updated
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
                {"name": "network_name", "value": network_name, "type": str},
            ]
        )

        if not self.wpasupplicantconf.enable_network(
            network_name, interface=interface_name
        ):
            raise CommandError("Unable to enable network")

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface_name)

    def disable_wifi_network(self, interface_name, network_name):
        """
        Disable wifi network

        Args:
            interface_name (string): interface name
            network_name (string): network name

        Returns:
            bool: True if network updated
        """
        # check params
        self._check_parameters(
            [
                {"name": "interface_name", "value": interface_name, "type": str},
                {"name": "network_name", "value": network_name, "type": str},
            ]
        )

        if not self.wpasupplicantconf.disable_network(
            network_name, interface=interface_name
        ):
            raise CommandError("Unable to disable network")

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface_name)

    def reconfigure_wifi_interface(self, interface_name):
        """
        Reconfigure specified interface

        Args:
            interface_name (string): interface to reconfigure

        Returns:
            bool: True if command succeed
        """
        # check params
        self._check_parameters(
            [
                {
                    "name": "interface_name",
                    "value": interface_name,
                    "type": str,
                    "validator": lambda val: val in self.wifi_interfaces,
                },
            ]
        )

        # reconfigure interface
        return self.wpacli.reconfigure_interface(interface_name)
