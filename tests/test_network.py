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
mock_iwlist = Mock()
mock_iwconfig = Mock()
mock_wpacli = Mock()
mock_cleepwificonf = Mock()
mock_task = Mock()
mock_ifconfig = Mock()

@patch('backend.network.WpaSupplicantConf', mock_wpasupplicantconf)
@patch('backend.network.DhcpcdConf', mock_dhcpcdconf)
@patch('backend.network.EtcNetworkInterfaces', mock_etcnetworkinterfaces)
@patch('backend.network.Iw', mock_iw)
@patch('backend.network.Iwlist', mock_iwlist)
@patch('backend.network.Iwconfig', mock_iwconfig)
@patch('backend.network.Wpacli', mock_wpacli)
@patch('backend.network.CleepWifiConf', mock_cleepwificonf)
@patch('backend.network.Task', mock_task)
@patch('backend.network.Ifconfig', mock_ifconfig)
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

    def setUp(self):
        self.session = session.TestSession(self)
        logging.basicConfig(level=logging.DEBUG, format=u'%(asctime)s %(name)s:%(lineno)d %(levelname)s : %(message)s')

        mock_iw.return_value.get_adapters.return_value = { 'adapter1': { 'interface': 'interface1', 'network': None } }
        mock_iwconfig.return_value.get_interfaces.return_value = { 'interface1': { 'network': None } }
        mock_wpasupplicantconf.return_value.get_configurations.return_value = { 
            'interface1': { 
                'network1': { 'network': 'network1', 'hidden': False, 'encryption': 'wpa2', 'disabled': False }
            },
        }
        mock_iwlist.return_value.get_networks.return_value = {
            'network1': self.IWLIST_NETWORK1,
        }
        mock_cleepwificonf.return_value.exists.return_value = False
        mock_dhcpcdconf.return_value.get_configurations.return_value = {
            'interface1': self.DHCPCD_INTERFACE1,
            'interface2': self.DHCPCD_INTERFACE2,
        }

    def tearDown(self):
        self.session.clean()
        mock_cleepwificonf.reset_mock()
        mock_task.reset_mock()
        mock_wpasupplicantconf.reset_mock()
        mock_iw.reset_mock()
        mock_iwconfig.reset_mock()
        mock_iwlist.reset_mock()
        mock_dhcpcdconf.reset_mock()
        mock_ifconfig.reset_mock()

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

    def test_on_start(self):
        self.init_session()

        mock_task.return_value.start.assert_called()
        mock_task.assert_called_with(1.0, self.module._check_network_connection, self.module.logger)

    def test_on_stop(self):
        self.init_session()

        self.module._on_stop()

        mock_task.return_value.stop.assert_called()

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

        

if __name__ == '__main__':
    # coverage run --omit="*lib/python*/*","test_*" --concurrency=thread test_network.py; coverage report -m -i
    unittest.main()
    
