/**
 * Network service
 * Handle network module requests
 */
angular
.module('Cleep')
.service('networkService', ['$q', '$rootScope', 'rpcService', 'cleepService',
function($q, $rootScope, rpcService, cleepService) {
    var self = this;

    self.saveWiredStaticConfiguration = function(interface, ipAddress, gateway, netmask, fallback) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand(
            'save_wired_static_configuration',
            'network',
            {
                'interface_name': interface,
                'ip_address': ipAddress,
                'gateway': gateway,
                'netmask': netmask,
                'fallback': fallback
            }
        );
    };

    self.saveWiredDhcpConfiguration = function(interface) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand('save_wired_dhcp_configuration', 'network', {'interface_name':interface});
    };

    self.saveWifiNetwork = function(interface, network, password, encryption, hidden) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand(
            'save_wifi_network_configuration',
            'network', {
                'interface_name': interface,
                'network_name': network,
                'encryption': encryption,
                'password': password,
                'hidden': hidden,
            },
            30,
        )
            .then(function() {
                return self.refreshWifiNetworks();
            });
    };

    self.deleteWifiNetwork = function(interface, network) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand(
            'delete_wifi_network_configuration',
            'network',
            {
                'interface_name': interface,
                'network_name': network,
            },
            30,
        )
            .then(function() {
                return self.refreshWifiNetworks();
            });
    };

    self.enableWifiNetwork = function(interface, network) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand(
            'enable_wifi_network',
            'network',
            {
                'interface_name': interface,
                'network_name': network,
            },
            30,
        )
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.disableWifiNetwork = function(interface, network) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand(
            'disable_wifi_network',
            'network',
            {
                'interface_name': interface,
                'network_name': network,
            },
            30,
        )
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.updateWifiNetworkPassword = function(interface, network, password) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand(
            'update_wifi_network_password',
            'network',
            {
                'interface_name': interface,
                'network_name': network,
                'password': password,
            },
            30,
        )
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.reconfigureWifiNetwork = function(interface) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand('reconfigure_wifi_interface', 'network', {'interface_name': interface}, 30)
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.reconfigureWiredNetwork = function(interface) {
        self.enableActiveNetworkScan();
        return rpcService.sendCommand('reconfigure_wired_interface', 'network', {'interface_name': interface}, 30)
            .then(function(resp) {
                //reload module config
                return cleepService.reloadModuleConfig('network');
            })
            .then(function(config) {
                return config;
            });
    };

    self.refreshWifiNetworks = function() {
        var wifiNetworks = null;
        return rpcService.sendCommand('refresh_wifi_networks', 'network', null, 30)
            .then(function(resp) {
                //reload module config
                return cleepService.reloadModuleConfig('network')
            })
            .then(function(config) {
                return config;
            });
    };

    self.enableActiveNetworkScan = function() {
        return rpcService.sendCommand('enable_active_network_scan', 'network');
    };

    self.disableActiveNetworkScan = function() {
        return rpcService.sendCommand('disable_active_network_scan', 'network');
    };
}]);
 
