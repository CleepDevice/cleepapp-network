/**
 * Network service
 * Handle network module requests
 */
var networkService = function($q, $rootScope, rpcService, raspiotService) {
    var self = this;

    self.saveWiredStaticConfiguration = function(interface, ipAddress, gateway, netmask, fallback) {
        return rpcService.sendCommand('save_wired_static_configuration', 'network', {'interface':interface, 'ip_address':ipAddress, 'gateway':gateway, 'netmask':netmask, 'fallback':fallback});
    };

    self.saveWiredDhcpConfiguration = function(interface) {
        return rpcService.sendCommand('save_wired_dhcp_configuration', 'network', {'interface':interface});
    };

    self.testWifiNetwork = function(interface, network, password, encryption, hidden) {
        return rpcService.sendCommand('test_wifi_network', 'network', {'interface':interface, 'network':network, 'encryption':encryption, 'password':password, 'hidden':hidden}, 60);
    };

    self.saveWifiNetwork = function(interface, network, password, encryption, hidden) {
        return rpcService.sendCommand('save_wifi_network', 'network', {'interface':interface, 'network':network, 'encryption':encryption, 'password':password, 'hidden':hidden}, 30)
            .then(function() {
                return self.refreshWifiNetworks();
            });
    };

    self.deleteWifiNetwork = function(interface, network) {
        return rpcService.sendCommand('delete_wifi_network', 'network', {'interface':interface, 'network':network}, 30)
            .then(function() {
                return self.refreshWifiNetworks();
            });
    };

    self.enableWifiNetwork = function(interface, network) {
        return rpcService.sendCommand('enable_wifi_network', 'network', {'interface':interface, 'network':network}, 30)
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.disableWifiNetwork = function(interface, network) {
        return rpcService.sendCommand('disable_wifi_network', 'network', {'interface':interface, 'network':network}, 30)
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.updateWifiNetworkPassword = function(interface, network, password) {
        return rpcService.sendCommand('update_wifi_network_password', 'network', {'interface':interface, 'network':network, 'password':password}, 30)
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.reconfigureWifiNetwork = function(interface) {
        return rpcService.sendCommand('reconfigure_wifi_interface', 'network', {'interface':interface}, 30)
            .then(function(resp) {
                return self.refreshWifiNetworks();
            });
    };

    self.reconfigureWiredNetwork = function(interface) {
        return rpcService.sendCommand('reconfigure_wired_interface', 'network', {'interface':interface}, 30)
            .then(function(resp) {
                //reload module config
                return raspiotService.reloadModuleConfig('network');
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
                return raspiotService.reloadModuleConfig('network')
            })
            .then(function(config) {
                return config;
            });
    };
};
    
var RaspIot = angular.module('RaspIot');
RaspIot.service('networkService', ['$q', '$rootScope', 'rpcService', 'raspiotService', networkService]);

