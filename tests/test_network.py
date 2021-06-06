#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import logging
import sys
import copy
sys.path.append('../')
from backend.network import Network
from cleep.exception import InvalidParameter, MissingParameter, CommandError, Unauthorized, CommandInfo
from cleep.libs.tests import session
from mock import Mock, patch, MagicMock

mock_wpasupplicantconf = Mock()
mock_dhcpcdconf = Mock()
mock_etcnetworkinterfaces = Mock()
mock_iw = Mock()
mock_ip = Mock()
mock_iwlist = Mock()
mock_iwconfig = Mock()
mock_wpacli = Mock()
mock_cleepwificonf = Mock()
mock_task = Mock()
mock_ifconfig = Mock()
mock_netifaces = Mock()
mock_ifupdown = Mock()
mock_time = Mock()

@patch('backend.network.WpaSupplicantConf', mock_wpasupplicantconf)
@patch('backend.network.DhcpcdConf', mock_dhcpcdconf)
@patch('backend.network.EtcNetworkInterfaces', mock_etcnetworkinterfaces)
@patch('backend.network.Iw', mock_iw)
@patch('backend.network.Ip', mock_ip)
@patch('backend.network.Iwlist', mock_iwlist)
@patch('backend.network.Iwconfig', mock_iwconfig)
@patch('backend.network.Wpacli', mock_wpacli)
@patch('backend.network.CleepWifiConf', mock_cleepwificonf)
@patch('backend.network.Task', mock_task)
@patch('backend.network.Ifconfig', mock_ifconfig)
@patch('backend.network.netifaces', mock_netifaces)
@patch('backend.network.Ifupdown', mock_ifupdown)
@patch('backend.network.time', mock_time)
class TestNetwork(unittest.TestCase):

    WIFI_NETWORKS = {
        'interface1': {
            'network1': {
                'interface': 'interface1', 
                'network': 'network1',
                'encryption': 'wpa2',
                'signallevel': 100.0,
                'frequencies': [12.5],
                'configured': False,
                'disabled': False,
            },
        },
        'interface2': {
            'network2': {
                'interface': 'interface2',
                'network': 'network2',
                'encryption': 'wpa2',
                'signallevel': 75.0,
                'frequencies': [66.6],
                'configured': False,
                'disabled': False,
            },
        },
    }
    IWLIST_NETWORK1 = {
        'interface': 'interface1',
        'network': 'network1',
        'encryption': 'wpa2',
        'signallevel': 50.0
    }
    IWLIST_NETWORK2 = {
        'interface': 'interface1',
        'network': 'network2',
        'encryption': 'wpa',
        'signallevel': 75.0
    }
    IWLIST_NETWORK4 = {
        'interface': 'interface1',
        'network': 'network4',
        'encryption': 'wpa',
        'signallevel': 5.0
    }
    DHCPCD_INTERFACE1 = {
        'group': 'dummy_group',
        'interface': 'interface1',
        'netmask': '255.255.255.0',
        'fallback': False,
        'ip_address': '1.1.1.1',
        'gateway': '2.2.2.2',
        'dns_address': '3.3.3.3',
    }
    DHCPCD_INTERFACE2 = {
        'group': 'dummy_group',
        'interface': 'interface2',
        'netmask': '255.255.255.0',
        'fallback': False,
        'ip_address': '4.4.4.4',
        'gateway': '5.5.5.5',
        'dns_address': '6.6.6.6',
    }
    IWCONFIG_INTERFACE1 = {
        'network': None
    }

    def setUp(self):
        self.session = session.TestSession(self)
        logging.basicConfig(level=logging.FATAL, format=u'%(asctime)s %(name)s:%(lineno)d %(levelname)s : %(message)s')

        mock_time.time.return_value = 123
        mock_iw.return_value.get_adapters.return_value = { 'adapter1': { 'interface': 'interface1', 'network': None } }
        mock_iwconfig.return_value.get_interfaces.return_value = {
            'interface1':self.IWCONFIG_INTERFACE1,
        }
        mock_wpasupplicantconf.return_value.get_configurations.return_value = { 
            'interface1': { 
                'network1': { 'network': 'network1', 'hidden': False, 'encryption': 'wpa2', 'disabled': False },
            },
        }
        mock_wpasupplicantconf.ENCRYPTION_TYPE_UNKNOWN = 'unknown'
        mock_wpasupplicantconf.ENCRYPTION_TYPE_UNSECURED = 'unsecured'
        mock_wpasupplicantconf.ENCRYPTION_TYPE_WEP = 'wep'
        mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA = 'wpa'
        mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2 = 'wpa2'
        mock_wpasupplicantconf.ENCRYPTION_TYPES = ['wpa', 'wpa2', 'wep', 'unsecured', 'unknown']
        mock_iwlist.return_value.get_networks.return_value = {
            'network1': self.IWLIST_NETWORK1,
        }
        mock_cleepwificonf.return_value.exists.return_value = False
        mock_dhcpcdconf.return_value.get_configurations.return_value = {
            'interface1': self.DHCPCD_INTERFACE1,
            'interface2': self.DHCPCD_INTERFACE2,
        }
        mock_netifaces.AF_INET = 2
        mock_netifaces.ifaddresses = Mock(return_value={
            17: [{'addr': 'b8:27:eb:62:24:18', 'broadcast': 'ff:ff:ff:ff:ff:ff'}],
            2: [{'addr': '192.168.1.228', 'netmask': '255.255.255.0', 'broadcast': '192.168.1.255'}],
            10: [{'addr': 'fe80::dec4:b0ff:5a7e:804%eth0', 'netmask': 'ffff:ffff:ffff:ffff::/64'}]
        })
        mock_etcnetworkinterfaces.OPTION_AUTO = 1
        mock_etcnetworkinterfaces.OPTION_HOTPLUG = 2
        mock_etcnetworkinterfaces.OPTION_NONE = 3
        mock_wpacli.STATE_4WAY_HANDSHAKE = '4WAY_HANDSHAKE'
        mock_wpacli.STATE_ASSOCIATED = 'ASSOCIATED'
        mock_wpacli.STATE_ASSOCIATING = 'ASSOCIATING'
        mock_wpacli.STATE_AUTHENTICATING = 'AUTHENTICATING'
        mock_wpacli.STATE_COMPLETED = 'COMPLETED'
        mock_wpacli.STATE_DISCONNECTED = 'DISCONNECTED'
        mock_wpacli.STATE_GROUP_HANDSHAKE = 'GROUP_HANDSHAKE'
        mock_wpacli.STATE_INACTIVE = 'INACTIVE'
        mock_wpacli.STATE_INTERFACE_DISABLED = 'INTERFACE_DISABLED'
        mock_wpacli.STATE_SCANNING = 'SCANNING'
        mock_wpacli.STATE_UNKNOWN = 'UNKNOWN'

    def tearDown(self):
        self.session.clean()
        mock_cleepwificonf.reset_mock()
        mock_task.reset_mock()
        mock_wpasupplicantconf.reset_mock()
        mock_iw.reset_mock()
        mock_ip.reset_mock()
        mock_iwconfig.reset_mock()
        mock_iwlist.reset_mock()
        mock_dhcpcdconf.reset_mock()
        mock_ifconfig.reset_mock()
        mock_wpacli.reset_mock()
        mock_ifupdown .reset_mock()

    def init_session(self, start_module=True):
        self.module = self.session.setup(Network)
        if start_module:
            self.session.start_module(self.module)

    def test_configure_wo_cleepwificonf(self):
        self.init_session(start_module=False)
        self.module.refresh_wifi_networks = Mock()
        self.module._load_cleep_wifi_conf = Mock()
        mock_cleepwificonf.return_value.exists.return_value = False

        self.session.start_module(self.module)

        self.module.refresh_wifi_networks.assert_called()
        self.assertFalse(self.module._load_cleep_wifi_conf.called)
        self.assertFalse(mock_cleepwificonf.return_value.delete.called)

        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_configure_with_cleepwificonf(self):
        self.init_session(start_module=False)
        mock_cleepwificonf.return_value.exists.return_value = True
        self.module.refresh_wifi_networks = Mock()
        self.module._load_cleep_wifi_conf = Mock()

        self.session.start_module(self.module)

        self.module.refresh_wifi_networks.assert_called()
        self.module._load_cleep_wifi_conf.assert_called()
        mock_cleepwificonf.return_value.delete.assert_called()

        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_configure_cleepwificonf_exception(self):
        self.init_session(start_module=False)
        mock_cleepwificonf.return_value.exists.return_value = True
        self.module.refresh_wifi_networks = Mock()
        self.module._load_cleep_wifi_conf = Mock(side_effect=Exception('Test exception'))

        self.session.start_module(self.module)

        mock_cleepwificonf.return_value.delete.assert_called()

        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_configure_refresh_wifi_exception(self):
        self.init_session(start_module=False)
        self.module.refresh_wifi_networks = Mock(side_effect=Exception('Test exception'))

        self.session.start_module(self.module)

        self.session.crash_report.report_exception.assert_called()
        mock_cleepwificonf.return_value.exists.assert_called()

    def test_on_start(self):
        self.init_session()

        mock_task.return_value.start.assert_called()
        mock_task.assert_called_with(1.0, self.module._check_network_connection, self.module.logger)

    def test_on_stop(self):
        self.init_session()
        mock_timer = Mock()
        self.module._Network__network_scan_duration_timer = mock_timer

        self.module._on_stop()

        mock_task.return_value.stop.assert_called()
        mock_timer.cancel.assert_called()

    def test_load_cleep_wifi_conf(self):
        self.init_session()
        config = {
            'network': 'network2',
            'password': 'mypassword',
            'encryption': 'wpa2',
            'hidden': False,
        }
        mock_cleepwificonf.return_value.get_configuration.return_value = config
        self.module.wifi_networks = copy.deepcopy(self.WIFI_NETWORKS)
        self.module.reconfigure_wifi_interface = Mock()

        self.module._load_cleep_wifi_conf()

        mock_wpasupplicantconf.return_value.add_network.assert_called_with(
            'network2',
            'wpa2',
            'mypassword',
            encrypt_password=False,
            hidden=False,
            interface='interface2'
        )
        self.module.reconfigure_wifi_interface.assert_called_with('interface2')

        mock_cleepwificonf.return_value.get_configuration.return_value = Mock()

    def test_load_cleep_wifi_conf_overwrite_encryption(self):
        self.init_session()
        config = {
            'network': 'network2',
            'password': 'mypassword',
            'encryption': 'wep',
            'hidden': False,
        }
        mock_cleepwificonf.return_value.get_configuration.return_value = config
        self.module.wifi_networks = copy.deepcopy(self.WIFI_NETWORKS)
        self.module.reconfigure_wifi_interface = Mock()

        self.module._load_cleep_wifi_conf()

        mock_wpasupplicantconf.return_value.add_network.assert_called_with(
            'network2',
            'wpa2', # should be wpa2, not wep
            'mypassword',
            encrypt_password=False,
            hidden=False,
            interface='interface2'
        )
        self.module.reconfigure_wifi_interface.assert_called_with('interface2')

        mock_cleepwificonf.return_value.get_configuration.return_value = Mock()

    def test_load_cleep_wifi_conf_hidden_network(self):
        self.init_session()
        config = {
            'network': 'networkX',
            'password': 'mypassword',
            'encryption': 'wep',
            'hidden': True,
        }
        mock_cleepwificonf.return_value.get_configuration.return_value = config
        self.module.wifi_networks = copy.deepcopy(self.WIFI_NETWORKS)
        del self.module.wifi_networks['interface1']
        self.module.reconfigure_wifi_interface = Mock()

        self.module._load_cleep_wifi_conf()

        mock_wpasupplicantconf.return_value.add_network.assert_called_with(
            'networkX',
            'wep',
            'mypassword',
            encrypt_password=False,
            hidden=True,
            interface='interface2'
        )
        self.module.reconfigure_wifi_interface.assert_called_with('interface2')

        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_load_cleep_wifi_conf_hidden_network_no_interface(self):
        self.init_session()
        config = {
            'network': 'networkX',
            'password': 'mypassword',
            'encryption': 'wep',
            'hidden': True,
        }
        mock_cleepwificonf.return_value.get_configuration.return_value = config
        self.module.wifi_networks = {}
        self.module.reconfigure_wifi_interface = Mock()

        self.module._load_cleep_wifi_conf()

        mock_wpasupplicantconf.return_value.add_network.assert_called_with(
            'networkX',
            'wep',
            'mypassword',
            encrypt_password=False,
            hidden=True,
            interface=None,
        )
        self.assertFalse(self.module.reconfigure_wifi_interface.called)

        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_load_cleep_wifi_conf_empty_file(self):
        self.init_session()
        mock_cleepwificonf.return_value.get_configuration.return_value = {}
        self.module.wifi_networks = copy.deepcopy(self.WIFI_NETWORKS)
        self.module.reconfigure_wifi_interface = Mock()

        self.module._load_cleep_wifi_conf()

        self.assertFalse(mock_wpasupplicantconf.return_value.add_network.called)
        self.assertFalse(self.module.reconfigure_wifi_interface.called)

        mock_cleepwificonf.return_value.exists.return_value = Mock()
        
    def test_load_cleep_wifi_conf_network_not_found(self):
        self.init_session()
        config = {
            'network': 'mynetwork',
            'password': 'mypassword',
            'encryption': 'wpa2',
            'hidden': False,
        }
        mock_cleepwificonf.return_value.get_configuration.return_value = config
        self.module.wifi_networks = copy.deepcopy(self.WIFI_NETWORKS)
        self.module.reconfigure_wifi_interface = Mock()
        self.module.logger = Mock() # careful: no output log

        self.module._load_cleep_wifi_conf()

        self.assertFalse(mock_wpasupplicantconf.return_value.add_network.called)
        self.assertFalse(self.module.reconfigure_wifi_interface.called)
        self.module.logger.warning.assert_called_with('Interface was not found for network "mynetwork" or network is already configured')

        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_load_cleep_wifi_conf_add_wpasupplicantconf_failed(self):
        self.init_session()
        config = {
            'network': 'network2',
            'password': 'mypassword',
            'encryption': 'wpa2',
            'hidden': False,
        }
        mock_cleepwificonf.return_value.get_configuration.return_value = config
        mock_wpasupplicantconf.return_value.add_network.return_value = False
        self.module.wifi_networks = copy.deepcopy(self.WIFI_NETWORKS)
        self.module.reconfigure_wifi_interface = Mock()
        self.module.logger = Mock() # careful: no output log

        self.module._load_cleep_wifi_conf()

        self.assertFalse(self.module.reconfigure_wifi_interface.called)
        self.module.logger.error.assert_called_with('Unable to use config from cleepwifi.conf')

        mock_wpasupplicantconf.return_value.add_network.return_value = Mock()
        mock_cleepwificonf.return_value.exists.return_value = Mock()

    def test_get_module_config_from_dhcpcd(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = True
        interface1_config = {
            'interface': 'interface1',
            'mode': 'mode',
            'address': '1.2.3.4',
            'netmask': '255.255.255.0',
            'gateway': '0.0.0.0',
            'dnsnameservers': ['1.1.1.1'],
            'wifi': True,
            'wifinetwork': 'dummy',
        }
        interface2_config = {
            'interface': 'interface2',
            'mode': 'mode',
            'address': '4.3.2.1',
            'netmask': '255.255.255.0',
            'dnsnameservers': ['2.2.2.2'],
            'wifi': False,
            'wifinetwork': None,
        }
        self.module._get_network_config_from_dhcpcd = Mock(return_value={
            'interface1': interface1_config,
            'interface2': interface2_config,
        })
        self.module._get_network_config_from_network_interfaces = Mock()
        interface1_status = {
            'interface': 'interface1',
            'mac': '00:11:22:33:44:55',
            'ipv4': '1.2.3.4',
        }
        interface2_status = {
            'interface': 'interface2',
            'mac': '55:44:33:22:11:00',
            'ipv4': '1.2.3.4'
        }
        mock_ifconfig.return_value.get_configurations.return_value = {
            'interface1': interface1_status,
            'interface2': interface2_status,
        }
        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }
        network_status = {
            'interface1': {
                'network': 'wired',
                'status': None,
                'ipaddress': None,
            }
        }
        self.module.network_status = network_status
        self.module.last_wifi_networks_scan = 123456789

        config = self.module.get_module_config()
        logging.debug('Config: %s' % config)

        self.assertDictEqual(config, {
            'networks': [
                {
                    'status': interface2_status,
                    'config': interface2_config,
                    'network': 'interface2',
                    'wifi': False,
                    'interface': 'interface2',
                },
                {
                    'status': interface1_status,
                    'config': {
                        **self.IWLIST_NETWORK1,
                        **{
                            'configured': True,
                            'disabled': False,
                            'hidden': False,
                        },
                    },
                    'network': 'network1',
                    'wifi': True,
                    'interface': 'interface1',
                },
            ],
            'wifiinterfaces': ['interface1'],
            'networkstatus': self.module.network_status,
            'lastwifiscan': 123456789,
        })
        self.module._get_network_config_from_dhcpcd.assert_called()
        self.assertFalse(self.module._get_network_config_from_network_interfaces.called)

        mock_dhcpcdconf.return_value.exists.return_value = Mock()
        mock_ifconfig.return_value.get_configurations.return_value = Mock()

    def test_get_module_config_from_network_interfaces(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False
        interface1_config = {
            'interface': 'interface1',
            'mode': 'mode',
            'address': '1.2.3.4',
            'netmask': '255.255.255.0',
            'gateway': '0.0.0.0',
            'dns_nameservers': ['1.1.1.1'],
            'wifi': True,
            'wifinetwork': 'dummy',
        }
        interface2_config = {
            'interface': 'interface2',
            'mode': 'mode',
            'address': '4.3.2.1',
            'netmask': '255.255.255.0',
            'dns_nameservers': ['2.2.2.2'],
            'wifi': False,
            'wifinetwork': None,
        }
        self.module._get_network_config_from_dhcpcd = Mock()
        self.module._get_network_config_from_network_interfaces = Mock(return_value={
            'interface1': interface1_config,
            'interface2': interface2_config,
        })
        interface1_status = {
            'interface': 'interface1',
            'mac': '00:11:22:33:44:55',
            'ipv4': '1.2.3.4',
        }
        interface2_status = {
            'interface': 'interface2',
            'mac': '55:44:33:22:11:00',
            'ipv4': '1.2.3.4'
        }
        mock_ifconfig.return_value.get_configurations.return_value = {
            'interface1': interface1_status,
            'interface2': interface2_status,
        }
        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }
        network_status = {
            'interface1': {
                'network': 'wired',
                'status': None,
                'ipaddress': None,
            }
        }
        self.module.network_status = network_status
        self.module.last_wifi_networks_scan = 123456789

        config = self.module.get_module_config()
        logging.debug('Config: %s' % config)

        self.assertDictEqual(config, {
            'networks': [
                {
                    'status': interface2_status,
                    'config': interface2_config,
                    'network': 'interface2',
                    'wifi': False,
                    'interface': 'interface2',
                },
                {
                    'status': interface1_status,
                    'config': {
                        **self.IWLIST_NETWORK1,
                        **{
                            'configured': True,
                            'disabled': False,
                            'hidden': False,
                        },
                    },
                    'network': 'network1',
                    'wifi': True,
                    'interface': 'interface1',
                },
            ],
            'wifiinterfaces': ['interface1'],
            'networkstatus': self.module.network_status,
            'lastwifiscan': 123456789,
        })
        self.module._get_network_config_from_network_interfaces.assert_called()
        self.assertFalse(self.module._get_network_config_from_dhcpcd.called)

        mock_dhcpcdconf.return_value.exists.return_value = Mock()
        mock_ifconfig.return_value.get_configurations.return_value = Mock()

    def test_get_network_config_from_dhcpcd(self):
        self.init_session()
        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }

        config = self.module._get_network_config_from_dhcpcd(['interface1', 'interface3', 'interface2'])
        logging.debug('Config: %s' % config)

        self.assertDictEqual(config, {
            'interface1': {
                'interface': 'interface1',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_STATIC,
                'address': self.DHCPCD_INTERFACE1['ip_address'],
                'netmask': self.DHCPCD_INTERFACE1['netmask'],
                'gateway': self.DHCPCD_INTERFACE1['gateway'],
                'dnsnameservers': self.DHCPCD_INTERFACE1['dns_address'],
                'wifi': True,
                'wifinetwork': 'network1',
            },
            'interface3': {
                'interface': 'interface3',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_DHCP,
                'address': None,
                'netmask': None,
                'gateway': None,
                'dnsnameservers': None,
                'wifi': False,
                'wifinetwork': None,
            },
            'interface2': {
                'interface': 'interface2',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_STATIC,
                'address': self.DHCPCD_INTERFACE2['ip_address'],
                'netmask': self.DHCPCD_INTERFACE2['netmask'],
                'gateway': self.DHCPCD_INTERFACE2['gateway'],
                'dnsnameservers': self.DHCPCD_INTERFACE2['dns_address'],
                'wifi': False,
                'wifinetwork': None,
            },
        })

    def test_get_network_config_from_network_interfaces(self):
        self.init_session()
        mock_etcnetworkinterfaces.return_value.get_configurations.return_value = {
            'interface1': {
                'interface': 'interface1',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_STATIC,
                'address': '1.1.1.1',
                'netmask': '255.255.255.0',
                'broadcast': '2.2.2.2',
                'gateway': '3.3.3.3',
                'dnsnameservers': '4.4.4.4',
                'dnsdomain': 'domain',
                'hotplug': True,
                'auto': True,
                'wpaconf': 'wpa_interface1', # test connected wifi network
            },
            'interface2': {
                'interface': 'interface2',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_DHCP,
                'address': '5.5.5.5',
                'netmask': '255.255.255.0',
                'broadcast': '6.6.6.6',
                'gateway': '7.7.7.7',
                'dnsnameservers': '8.8.8.8',
                'dnsdomain': 'domain',
                'hotplug': True,
                'auto': True,
                'wpaconf': 'wpa_interface2', # test not connected wifi network
            },
            'interface3': {
                'interface': 'interface3',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_STATIC,
                'address': '9.9.9.9',
                'netmask': '255.255.255.0',
                'broadcast': '10.10.10.10',
                'gateway': '11.11.11.11',
                'dnsnameservers': '12.12.12.12',
                'dnsdomain': 'domain',
                'hotplug': True,
                'auto': True,
                'wpaconf': None,
            },
            'lo': {
                'interface': 'lo',
            },
        }
        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }
        
        config = self.module._get_network_config_from_network_interfaces()
        logging.debug('Config: %s' % config)

        self.assertCountEqual(
            ['interface', 'mode', 'address', 'netmask', 'gateway', 'dnsnameservers', 'wifi', 'wifinetwork'],
            list(config['interface1'].keys())
        )
        self.maxDiff = None
        self.assertDictEqual(config, {
            'interface1': {
                'interface': 'interface1',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_STATIC,
                'address': '1.1.1.1',
                'netmask': '255.255.255.0',
                'gateway': '3.3.3.3',
                'dnsnameservers': '4.4.4.4',
                'wifi': True,
                'wifinetwork': 'network1',
            },
            'interface2': {
                'interface': 'interface2',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_DHCP,
                'address': '5.5.5.5',
                'netmask': '255.255.255.0',
                'gateway': '7.7.7.7',
                'dnsnameservers': '8.8.8.8',
                'wifi': True,
                'wifinetwork': None,
            },
            'interface3': {
                'interface': 'interface3',
                'mode': mock_etcnetworkinterfaces.return_value.MODE_STATIC,
                'address': '9.9.9.9',
                'netmask': '255.255.255.0',
                'gateway': '11.11.11.11',
                'dnsnameservers': '12.12.12.12',
                'wifi': False,
                'wifinetwork': None,
            },
        })

        mock_etcnetworkinterfaces.return_value.get_configurations.return_value = Mock()

    def test_on_event(self):
        self.init_session()

        self.module.on_event({
            'event': 'parameters.time.now',
            'params': {}
        })
        
        self.assertFalse(mock_wpasupplicantconf.return_value.set_country.called)

    def test_on_event_update_wpasupplicant_country(self):
        self.init_session()

        self.module.on_event({
            'event': 'parameters.country.update',
            'params': {'country': 'france', 'alpha2': 'FR'}
        })
        
        mock_wpasupplicantconf.return_value.set_country_alpha2.assert_called_with('FR')

    @patch('backend.network.Timer')
    def test_enable_active_network_scan(self, mock_timer):
        self.init_session()

        self.module.enable_active_network_scan()

        mock_timer.assert_called_with(self.module.ACTIVE_SCAN_TIMEOUT, self.module.disable_active_network_scan)
        mock_timer.return_value.start.assert_called()
        self.assertEqual(self.module._Network__network_scan_duration, 1)

    @patch('backend.network.Timer')
    def test_enable_active_network_scan_restart_timer(self, mock_timer):
        self.init_session()
        mock_old_timer = Mock()
        self.module._Network__network_scan_duration_timer = mock_old_timer

        self.module.enable_active_network_scan()

        mock_timer.assert_called_with(self.module.ACTIVE_SCAN_TIMEOUT, self.module.disable_active_network_scan)
        mock_timer.return_value.start.assert_called()
        self.assertEqual(self.module._Network__network_scan_duration, 1)
        mock_old_timer.cancel.assert_called()

    def test_disable_active_network_scan(self):
        self.init_session()
        mock_old_timer = Mock()
        self.module._Network__network_scan_duration_timer = mock_old_timer

        self.module.disable_active_network_scan()
        
        mock_old_timer.cancel.assert_called()
        self.assertEqual(self.module._Network__network_scan_duration, self.module.NETWORK_SCAN_DURATION)

    def test_check_network_connection_connected_to_wifi(self):
        self.init_session()
        mock_iwconfig.return_value.get_interfaces.return_value = { 'interface1': { 'network': 'network1' } }
        mock_netifaces.interfaces = Mock(return_value=['interface1', 'lo'])
        ifaddresses = {
            2: [
                { 'addr': '127.0.0.1' }
            ],
        }
        mock_netifaces.ifaddresses = Mock(return_value=ifaddresses)
        self.module._check_wifi_interface_status = Mock()
        self.module._check_wired_interface_status = Mock()
        self.module._Network__network_is_down = True

        self.module._check_network_connection()

        self.module._check_wifi_interface_status.assert_called_with('interface1')
        self.assertFalse(self.module._check_wired_interface_status.called)
        self.session.assert_event_called('network.status.up')
        self.assertFalse(self.session.event_called('network.status.down'))

        mock_iwconfig.return_value.get_interfaces.return_value = {
            'interface1':self.IWCONFIG_INTERFACE1,
        }
        mock_netifaces.interfaces = Mock()

    def test_check_network_connection_connected_to_wired(self):
        self.init_session()
        mock_iwconfig.return_value.get_interfaces.return_value = {}
        mock_netifaces.interfaces = Mock(return_value=['interface1'])
        ifaddresses = {
            2: [
                { 'addr': '127.0.0.1' }
            ],
        }
        mock_netifaces.ifaddresses = Mock(return_value=ifaddresses)
        self.module._check_wifi_interface_status = Mock()
        self.module._check_wired_interface_status = Mock()
        self.module._Network__network_is_down = True

        self.module._check_network_connection()

        self.assertFalse(self.module._check_wifi_interface_status.called)
        self.module._check_wired_interface_status.assert_called_with('interface1')
        self.session.assert_event_called('network.status.up')
        self.assertFalse(self.session.event_called('network.status.down'))

        mock_iwconfig.return_value.get_interfaces.return_value = {
            'interface1':self.IWCONFIG_INTERFACE1,
        }
        #mock_netifaces.interfaces = Mock()

    def test_check_network_connection_disconnected(self):
        self.init_session()
        mock_iwconfig.return_value.get_interfaces.return_value = {}
        mock_netifaces.interfaces = Mock(return_value=['interface1'])
        ifaddresses = {}
        mock_netifaces.ifaddresses = Mock(return_value=ifaddresses)
        self.module._check_wifi_interface_status = Mock()
        self.module._check_wired_interface_status = Mock()
        self.module._Network__network_is_down = False

        self.module._check_network_connection()

        self.assertFalse(self.module._check_wifi_interface_status.called)
        self.module._check_wired_interface_status.assert_called_with('interface1')
        self.session.assert_event_called('network.status.down')
        self.assertFalse(self.session.event_called('network.status.up'))

        mock_iwconfig.return_value.get_interfaces.return_value = {
            'interface1':self.IWCONFIG_INTERFACE1,
        }
        mock_netifaces.interfaces = Mock()

    def test_check_network_connection_optimized(self):
        self.init_session()
        mock_iwconfig.return_value.get_interfaces.return_value = { 'interface1': { 'network': 'network1' } }
        mock_netifaces.interfaces = Mock(return_value=['interface1', 'lo'])
        ifaddresses = {
            2: [
                { 'addr': '127.0.0.1' }
            ],
        }
        mock_netifaces.ifaddresses = Mock(return_value=ifaddresses)
        self.module._check_wifi_interface_status = Mock()
        self.module._check_wired_interface_status = Mock()
        self.module._Network__network_is_down = True
        self.module.network_status = {
            'interface1': {}
        }

        self.module._check_network_connection()

        self.assertFalse(self.module._check_wifi_interface_status.called)
        self.assertFalse(self.module._check_wired_interface_status.called)
        self.assertFalse(self.session.event_called('network.status.up'))
        self.assertFalse(self.session.event_called('network.status.down'))

        mock_iwconfig.return_value.get_interfaces.return_value = {
            'interface1':self.IWCONFIG_INTERFACE1,
        }
        mock_netifaces.interfaces = Mock()

    def test_check_wired_interface_status_connected(self):
        self.init_session()
        mock_netifaces.ifaddresses = Mock(return_value={
            2: [
                { 'addr': '192.168.1.1' }
            ],
        })
        self.module.network_status = {
            'interface1': {
                'network': self.module.TYPE_WIRED,
                'status': self.module.STATUS_DISCONNECTED,
                'ipaddress': None,
            },
        }

        self.module._check_wired_interface_status('interface1')

        self.session.assert_event_called_with('network.status.update', {
            'type': self.module.TYPE_WIRED,
            'interface': 'interface1',
            'network': 'wired',
            'status': self.module.STATUS_CONNECTED,
            'ipaddress': '192.168.1.1',
        })

    def test_check_wired_interface_status_no_update_if_already_connected(self):
        self.init_session()
        netifaces_infos = {
            2: [
                { 'addr': '192.168.1.1' }
            ],
        }
        self.module.network_status = {
            'interface1': {
                'network': self.module.TYPE_WIRED,
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.1',
            },
        }

        self.module._check_wired_interface_status('interface1')

        self.assertFalse(self.session.event_called('network.status.update'))

    def test_check_wired_interface_status_disconnected(self):
        self.init_session()
        mock_netifaces.ifaddresses = Mock(return_value={})
        self.module.network_status = {
            'interface1': {
                'network': self.module.TYPE_WIRED,
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.255',
            },
        }

        self.module._check_wired_interface_status('interface1')

        self.session.assert_event_called_with('network.status.update', {
            'type': self.module.TYPE_WIRED,
            'interface': 'interface1',
            'network': 'wired',
            'status': self.module.STATUS_DISCONNECTED,
            'ipaddress': None,
        })

    def test_check_wired_interface_status_no_update_if_already_disconnected(self):
        self.init_session()
        mock_netifaces.ifaddresses = Mock(return_value={})
        self.module.network_status = {
            'interface1': {
                'network': self.module.TYPE_WIRED,
                'status': self.module.STATUS_DISCONNECTED,
                'ipaddress': None,
            },
        }

        self.module._check_wired_interface_status('interface1')

        self.assertFalse(self.session.event_called('network.status.update'))

    def test_check_wired_interface_status_unknown_interface(self):
        self.init_session()
        netifaces_infos = {}
        self.module.network_status = {}

        self.module._check_wired_interface_status('interface1')

        self.assertFalse(self.session.event_called('network.status.update'))

    def test_reconfigure_wired_interface_with_dhcpcd(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = True

        self.module.reconfigure_wired_interface('interface1')

        mock_ip.return_value.restart_interface.assert_called_with('interface1')
        self.assertFalse(mock_ifupdown.return_value.restart_interface.called)

    def test_reconfigure_wired_interface_with_network_interfaces(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False

        self.module.reconfigure_wired_interface('interface1')

        self.assertFalse(mock_ip.return_value.restart_interface.called)
        mock_ifupdown.return_value.restart_interface.assert_called_with('interface1')

    def test_reconfigure_wired_interface_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.reconfigure_wired_interface(None)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.reconfigure_wired_interface('')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.reconfigure_wired_interface(123)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')

    def test_save_wired_static_interface_static_with_dhcpcd(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = True
        self.module.reconfigure_wired_interface = Mock()

        self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', False)

        mock_dhcpcdconf.return_value.delete_interface.assert_called_with('interface1')
        mock_dhcpcdconf.return_value.add_static_interface.assert_called_with('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1')
        self.assertFalse(mock_dhcpcdconf.return_value.add_fallback_interface.called)
        self.module.reconfigure_wired_interface.assert_called_with('interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_static_interface_fallback_with_dhcpcd(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = True
        self.module.reconfigure_wired_interface = Mock()

        self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', True)

        mock_dhcpcdconf.return_value.delete_interface.assert_called_with('interface1')
        self.assertFalse(mock_dhcpcdconf.return_value.add_static_interface.called)
        mock_dhcpcdconf.return_value.add_fallback_interface.assert_called_with('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1')
        self.module.reconfigure_wired_interface.assert_called_with('interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_static_interface_with_dhcpcd_failed(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = True
        self.module.logger = Mock()

        # add_static_interface failed
        mock_dhcpcdconf.return_value.add_static_interface.return_value = False
        with self.assertRaises(CommandError) as cm:
            self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', False)
        self.assertEqual(str(cm.exception), 'Unable to save configuration')
        self.module.logger.error.assert_called_with('Unable to save wired static configuration (dhcpcd): unable to add interface interface1')
        mock_dhcpcdconf.return_value.add_static_interface.return_value = Mock()

        # add_fallback_interface failed
        mock_dhcpcdconf.return_value.add_fallback_interface.return_value = False
        with self.assertRaises(CommandError) as cm:
            self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', True)
        self.assertEqual(str(cm.exception), 'Unable to save configuration')
        self.module.logger.error.assert_called_with('Unable to save wired fallback configuration (dhcpcd): unable to add interface interface1')
        mock_dhcpcdconf.return_value.add_fallback_interface.return_value = Mock()

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_static_interface_static_with_network_interfaces(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False
        self.module.reconfigure_wired_interface = Mock()

        self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', False)

        mock_etcnetworkinterfaces.return_value.delete_interface.assert_called_with('interface1')
        mock_etcnetworkinterfaces.return_value.add_static_interface.assert_called_with(
            'interface1',
            mock_etcnetworkinterfaces.OPTION_HOTPLUG,
            '192.168.1.1',
            '1.1.1.1',
            '255.255.255.1'
        )
        self.module.reconfigure_wired_interface.assert_called_with('interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_static_interface_static_with_network_interfaces_fallback_does_nothing(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False
        self.module.reconfigure_wired_interface = Mock()

        self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', True)

        mock_etcnetworkinterfaces.return_value.delete_interface.assert_called_with('interface1')
        mock_etcnetworkinterfaces.return_value.add_static_interface.assert_called_with(
            'interface1',
            mock_etcnetworkinterfaces.OPTION_HOTPLUG,
            '192.168.1.1',
            '1.1.1.1',
            '255.255.255.1'
        )
        self.module.reconfigure_wired_interface.assert_called_with('interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_static_interface_with_network_interfaces_failed(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False
        self.module.logger = Mock()

        # add_static_interface failed
        mock_etcnetworkinterfaces.return_value.add_static_interface.return_value = False
        with self.assertRaises(CommandError) as cm:
            self.module.save_wired_static_configuration('interface1', '192.168.1.1', '1.1.1.1', '255.255.255.1', False)
        self.assertEqual(str(cm.exception), 'Unable to save configuration')
        self.module.logger.error.assert_called_with('Unable to save wired static configuration (interfaces): unable to add interface interface1')
        mock_etcnetworkinterfaces.return_value.add_static_interface.return_value = Mock()

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_static_interface_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wired_static_configuration(None, '1.1.1.1', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wired_static_configuration('interface', None, '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "ip_address" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wired_static_configuration('interface', '1.1.1.1', None, '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "gateway" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wired_static_configuration('interface', '1.1.1.1', '2.2.2.2', None, False)
        self.assertEqual(str(cm.exception), 'Parameter "netmask" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wired_static_configuration('interface', '1.1.1.1', '2.2.2.2', '3.3.3.3', None)
        self.assertEqual(str(cm.exception), 'Parameter "fallback" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('', '1.1.1.1', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration(123, '1.1.1.1', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0', '', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "ip_address" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0', 123, '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "ip_address" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0', '1.1.1.1', '', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "gateway" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0', '1.1.1.1', 123, '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "gateway" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0.', '1.1.1.1', '2.2.2.2', '', False)
        self.assertEqual(str(cm.exception), 'Parameter "netmask" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0.', '1.1.1.1', '2.2.2.2', 123, False)
        self.assertEqual(str(cm.exception), 'Parameter "netmask" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('0.0.0.0.', '1.1.1.1', '2.2.2.2', '3.3.3.3', 123)
        self.assertEqual(str(cm.exception), 'Parameter "fallback" must be of type "bool"')

    def test_save_wired_dhcp_configuration_with_dhcpcd(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = True
        self.module.reconfigure_wired_interface = Mock()

        self.module.save_wired_dhcp_configuration('interface1')

        mock_dhcpcdconf.return_value.delete_interface.assert_called_with('interface1')
        self.module.reconfigure_wired_interface.assert_called_with('interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_dhcp_configuration_with_network_interfaces(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False
        self.module.reconfigure_wired_interface = Mock()

        self.module.save_wired_dhcp_configuration('interface1')

        mock_etcnetworkinterfaces.return_value.delete_interface.assert_called_with('interface1')
        mock_etcnetworkinterfaces.return_value.add_dhcp_interface.assert_called_with(
            'interface1',
            mock_etcnetworkinterfaces.OPTION_AUTO + mock_etcnetworkinterfaces.OPTION_HOTPLUG
        )
        self.module.reconfigure_wired_interface.assert_called_with('interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()

    def test_save_wired_dhcp_configuration_with_network_interfaces_failed(self):
        self.init_session()
        mock_dhcpcdconf.return_value.is_installed.return_value = False
        mock_etcnetworkinterfaces.return_value.add_dhcp_interface.return_value = False
        self.module.logger = Mock()

        with self.assertRaises(CommandError) as cm:
            self.module.save_wired_dhcp_configuration('interface1')
        self.assertEqual(str(cm.exception), 'Unable to save configuration')
        self.module.logger.error.assert_called_with('Unable to save wired dhcp configuration (interfaces): unable to add interface interface1')

        mock_dhcpcdconf.return_value.is_installed.return_value = Mock()
        mock_etcnetworkinterfaces.return_value.add_dhcp_interface.return_value = Mock()

    def test_save_wired_dhcp_interface_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wired_static_configuration(None, '1.1.1.1', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration('', '1.1.1.1', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wired_static_configuration(123, '1.1.1.1', '2.2.2.2', '3.3.3.3', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')

    def test_check_wifi_interface_status_connected(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': 'network1',
            'state': mock_wpacli.STATE_COMPLETED,
            'ipaddress': '192.168.1.1'
        }
        self.module.network_status = {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_CONNECTING,
                'ipaddress': None,
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': 'network1',
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.1',
            }
        })
        self.session.assert_event_called_with('network.status.update', {
            'network': 'network1',
            'status': self.module.STATUS_CONNECTED,
            'ipaddress': '192.168.1.1',
            'interface': 'interface1',
            'type': self.module.TYPE_WIFI,
        })

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_check_wifi_interface_status_disconnected(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': None,
            'state': mock_wpacli.STATE_DISCONNECTED,
            'ipaddress': None,
        }
        self.module.network_status = {
            'interface1': {
                'network': 'network1',
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.1',
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_DISCONNECTED,
                'ipaddress': None,
            }
        })
        self.session.assert_event_called_with('network.status.update', {
            'network': None,
            'status': self.module.STATUS_DISCONNECTED,
            'ipaddress': None,
            'interface': 'interface1',
            'type': self.module.TYPE_WIFI,
        })

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_check_wifi_interface_status_connecting(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': None,
            'state': mock_wpacli.STATE_AUTHENTICATING,
            'ipaddress': None,
        }
        self.module.network_status = {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_DISCONNECTED,
                'ipaddress': None,
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_CONNECTING,
                'ipaddress': None,
            }
        })
        self.session.assert_event_called_with('network.status.update', {
            'network': None,
            'status': self.module.STATUS_CONNECTING,
            'ipaddress': None,
            'interface': 'interface1',
            'type': self.module.TYPE_WIFI,
        })

        mock_wpacli.return_value.get_status.return_value = Mock()
        
    def test_check_wifi_interface_status_no_previous_status(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': 'network1',
            'state': mock_wpacli.STATE_COMPLETED,
            'ipaddress': '192.168.1.1'
        }
        self.module.network_status = {}

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': 'network1',
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.1',
            }
        })
        self.session.assert_event_called_with('network.status.update', {
            'network': 'network1',
            'status': self.module.STATUS_CONNECTED,
            'ipaddress': '192.168.1.1',
            'interface': 'interface1',
            'type': self.module.TYPE_WIFI,
        })

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_check_wifi_interface_status_invalid_password(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': None,
            'state': mock_wpacli.STATE_GROUP_HANDSHAKE,
            'ipaddress': None,
        }
        self.module.network_status = {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_CONNECTING,
                'ipaddress': None,
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_WIFI_INVALID_PASSWORD,
                'ipaddress': None,
            }
        })
        self.session.assert_event_called_with('network.status.update', {
            'network': None,
            'status': self.module.STATUS_WIFI_INVALID_PASSWORD,
            'ipaddress': None,
            'interface': 'interface1',
            'type': self.module.TYPE_WIFI,
        })

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_check_wifi_interface_status_do_not_send_again_event(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': 'network1',
            'state': mock_wpacli.STATE_COMPLETED,
            'ipaddress': '192.168.1.1'
        }
        self.module.network_status = {
            'interface1': {
                'network': 'network1',
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.1',
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': 'network1',
                'status': self.module.STATUS_CONNECTED,
                'ipaddress': '192.168.1.1',
            }
        })
        self.assertFalse(self.session.event_call_count('network.status.update'))

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_check_wifi_interface_status_still_connecting(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': None,
            'state': mock_wpacli.STATE_COMPLETED,
            'ipaddress': None,
        }
        self.module.network_status = {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_DISCONNECTED,
                'ipaddress': None,
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_CONNECTING,
                'ipaddress': None,
            }
        })
        self.session.assert_event_called_with('network.status.update', {
            'network': None,
            'status': self.module.STATUS_CONNECTING,
            'ipaddress': None,
            'interface': 'interface1',
            'type': self.module.TYPE_WIFI,
        })

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_check_wifi_interface_status_still_keep_invalid_password_status(self):
        self.init_session()
        mock_wpacli.return_value.get_status.return_value = {
            'network': None,
            'state': mock_wpacli.STATE_AUTHENTICATING,
            'ipaddress': None,
        }
        self.module.network_status = {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_WIFI_INVALID_PASSWORD,
                'ipaddress': None,
            }
        }

        self.module._check_wifi_interface_status('interface1')

        self.assertDictEqual(self.module.network_status, {
            'interface1': {
                'network': None,
                'status': self.module.STATUS_WIFI_INVALID_PASSWORD,
                'ipaddress': None,
            }
        })

        mock_wpacli.return_value.get_status.return_value = Mock()

    def test_scan_wifi_networks(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.get_configurations.return_value = { 
            'interface1': { 
                'network1': { 'network': 'network1', 'hidden': False, 'encryption': 'wpa2', 'disabled': False },
                'network2': { 'network': 'network2', 'hidden': False, 'encryption': 'wpa', 'disabled': True },
                'network3': { 'network': 'network3', 'hidden': True, 'encryption': 'wep', 'disabled': False },
            },
        }
        mock_iwlist.return_value.get_networks.return_value = {
            'network1': self.IWLIST_NETWORK1,
            'network2': self.IWLIST_NETWORK2,
            'network4': self.IWLIST_NETWORK4,
        }

        networks = self.module._scan_wifi_networks('interface1')
        logging.debug('Wifi networks: %s' % networks)

        self.maxDiff = None
        self.assertDictEqual(networks, self.module.wifi_networks['interface1'])
        self.assertDictEqual(networks, {
            'network1': {
                'network': 'network1',
                'interface': 'interface1',
                'encryption': 'wpa2',
                'hidden': False,
                'configured': True,
                'disabled': False,
                'signallevel': 50.0,
            },
            'network2': {
                'network': 'network2',
                'interface': 'interface1',
                'encryption': 'wpa',
                'hidden': False,
                'configured': True,
                'disabled': True,
                'signallevel': 75.0,
            },
            'network3': {
                'network': 'network3',
                'interface': 'interface1',
                'encryption': 'wep',
                'hidden': True,
                'configured': True,
                'disabled': False,
                'signallevel': None,
            },
            'network4': {
                'network': 'network4',
                'interface': 'interface1',
                'encryption': 'wpa',
                'hidden': False,
                'configured': False,
                'disabled': False,
                'signallevel': 5.0,
            },
        })

    def test_save_wifi_network(self):
        self.init_session()

        self.module.save_wifi_network_configuration('interface1', 'network1', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)

        mock_wpasupplicantconf.return_value.add_network.assert_called_with('network1', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False, interface='interface1')
        mock_wpacli.return_value.reconfigure_interface.assert_called_with('interface1')

    def test_save_wifi_network_failed(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.add_network.return_value = False

        with self.assertRaises(CommandError) as cm:
            self.module.save_wifi_network_configuration('interface1', 'network1', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Unable to save network configuration')

        mock_wpasupplicantconf.return_value.add_network = Mock()

    def test_save_wifi_network_exception(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.add_network.return_value = False

        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wifi_network_configuration(None, 'network1', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wifi_network_configuration('interface1', None, mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.save_wifi_network_configuration('interface1', 'network1', None, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "encryption" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wifi_network_configuration('', 'network1', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wifi_network_configuration(123, 'network1', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wifi_network_configuration('interface1', '', mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wifi_network_configuration('interface1', 123, mock_wpasupplicantconf.ENCRYPTION_TYPE_WPA2, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wifi_network_configuration('interface1', 'network1', 'dummy', 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "encryption" is invalid (specified="dummy")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.save_wifi_network_configuration('interface1', 'network1', 123, 'password', False)
        self.assertEqual(str(cm.exception), 'Parameter "encryption" must be of type "str"')

    def test_delete_wifi_network(self):
        self.init_session()

        self.module.delete_wifi_network_configuration('interface1', 'network1')

        mock_wpasupplicantconf.return_value.delete_network.assert_called_with('network1', interface='interface1')
        mock_wpacli.return_value.reconfigure_interface.assert_called_with('interface1')

    def test_delete_wifi_network_failed(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.delete_network.return_value = False

        with self.assertRaises(CommandError) as cm:
            self.module.delete_wifi_network_configuration('interface1', 'network1')
        self.assertEqual(str(cm.exception), 'Unable to delete network configuration')

        mock_wpasupplicantconf.return_value.delete_network = Mock()

    def test_delete_wifi_network_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.delete_wifi_network_configuration(None, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.delete_wifi_network_configuration('interface1', None)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.delete_wifi_network_configuration('', 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.delete_wifi_network_configuration(123, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.delete_wifi_network_configuration('interface1', '')
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.delete_wifi_network_configuration('interface1', 123)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" must be of type "str"')

    def test_update_wifi_network_password(self):
        self.init_session()

        self.module.update_wifi_network_password('interface1', 'network1', 'newpassword')

        mock_wpasupplicantconf.return_value.update_network_password.assert_called_with('network1', 'newpassword', interface='interface1')
        mock_wpacli.return_value.reconfigure_interface.assert_called_with('interface1')

    def test_update_wifi_network_password_failed(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.update_network_password.return_value = False

        with self.assertRaises(CommandError) as cm:
            self.module.update_wifi_network_password('interface1', 'network1', 'newpassword')
        self.assertEqual(str(cm.exception), 'Unable to update network password')

        mock_wpasupplicantconf.return_value.update_network_password = Mock()

    def test_update_wifi_network_password_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.update_wifi_network_password(None, 'network1', 'newpassword')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.update_wifi_network_password('interface1', None, 'newpassword')
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.update_wifi_network_password('interface1', 'network1', None)
        self.assertEqual(str(cm.exception), 'Parameter "password" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.update_wifi_network_password('', 'network1', 'newpassword')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.update_wifi_network_password(123, 'network1', 'newpassword')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.update_wifi_network_password('interface1', '', 'newpassword')
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.update_wifi_network_password('interface1', 123, 'newpassword')
        self.assertEqual(str(cm.exception), 'Parameter "network_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.update_wifi_network_password('interface1', 'network1', '')
        self.assertEqual(str(cm.exception), 'Parameter "password" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.update_wifi_network_password('interface1', 'network1', 123)
        self.assertEqual(str(cm.exception), 'Parameter "password" must be of type "str"')

    def test_enable_wifi_network(self):
        self.init_session()

        self.module.enable_wifi_network('interface1', 'network1')

        mock_wpasupplicantconf.return_value.enable_network.assert_called_with('network1', interface='interface1')
        mock_wpacli.return_value.reconfigure_interface.assert_called_with('interface1')

    def test_enable_wifi_network_failed(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.enable_network.return_value = False

        with self.assertRaises(CommandError) as cm:
            self.module.enable_wifi_network('interface1', 'network1')
        self.assertEqual(str(cm.exception), 'Unable to enable network')

        mock_wpasupplicantconf.return_value.enable_network = Mock()

    def test_enable_wifi_network_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.enable_wifi_network(None, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.enable_wifi_network('interface1', None)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.enable_wifi_network('', 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.enable_wifi_network(123, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.enable_wifi_network('interface1', '')
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.enable_wifi_network('interface1', 123)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" must be of type "str"')

    def test_disable_wifi_network(self):
        self.init_session()

        self.module.disable_wifi_network('interface1', 'network1')

        mock_wpasupplicantconf.return_value.disable_network.assert_called_with('network1', interface='interface1')
        mock_wpacli.return_value.reconfigure_interface.assert_called_with('interface1')

    def test_disable_wifi_network_failed(self):
        self.init_session()
        mock_wpasupplicantconf.return_value.disable_network.return_value = False

        with self.assertRaises(CommandError) as cm:
            self.module.disable_wifi_network('interface1', 'network1')
        self.assertEqual(str(cm.exception), 'Unable to disable network')

        mock_wpasupplicantconf.return_value.disable_network = Mock()

    def test_disable_wifi_network_exception(self):
        self.init_session()

        with self.assertRaises(MissingParameter) as cm:
            self.module.disable_wifi_network(None, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')
        with self.assertRaises(MissingParameter) as cm:
            self.module.disable_wifi_network('interface1', None)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.disable_wifi_network('', 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.disable_wifi_network(123, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.disable_wifi_network('interface1', '')
        self.assertEqual(str(cm.exception), 'Parameter "network_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.disable_wifi_network('interface1', 123)
        self.assertEqual(str(cm.exception), 'Parameter "network_name" must be of type "str"')

    def test_reconfigure_wifi_interface(self):
        self.init_session()
        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }

        self.assertTrue(self.module.reconfigure_wifi_interface('interface1'))

        mock_wpacli.return_value.reconfigure_interface.assert_called_with('interface1')
        
    def test_reconfigure_wifi_interface_failed(self):
        self.init_session()
        mock_wpacli.return_value.reconfigure_interface.return_value = False
        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }

        self.assertFalse(self.module.reconfigure_wifi_interface('interface1'))
        self.assertTrue(mock_wpacli.return_value.reconfigure_interface.called)

    def test_reconfigure_wifi_interface_exception(self):
        self.init_session()

        self.module.wifi_interfaces = {}
        with self.assertRaises(InvalidParameter) as cm:
            self.module.reconfigure_wifi_interface('interface1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="interface1")')

        self.module.wifi_interfaces = {
            'interface1': {
                'network': 'network1',
            }
        }
        with self.assertRaises(MissingParameter) as cm:
            self.module.disable_wifi_network(None, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is missing')

        with self.assertRaises(InvalidParameter) as cm:
            self.module.disable_wifi_network('', 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" is invalid (specified="")')
        with self.assertRaises(InvalidParameter) as cm:
            self.module.disable_wifi_network(123, 'network1')
        self.assertEqual(str(cm.exception), 'Parameter "interface_name" must be of type "str"')



if __name__ == '__main__':
    # coverage run --omit="*lib/python*/*","test_*" --concurrency=thread test_network.py; coverage report -m -i
    unittest.main()
    
