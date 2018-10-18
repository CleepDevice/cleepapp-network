/**
 * Network config directive
 * Handle network configuration
 */
var networkConfigDirective = function($rootScope, raspiotService, networkService, toast, confirm, $mdDialog) {

    var networkController = ['$scope', function($scope) {
        var self = this;
        self.lastWifiScan = 0;
        self.networks = [];
        self.wifiInterfaces = [];
        self.networkStatus = {};
        self.newConfig = null;
        self.selectedNetwork = null;
        self.wifiPassword = null;
        self.encryptions = [
            {label:'No security', value:'unsecured'},
            {label:'WEP', value:'wep'},
            {label:'WPA', value:'wpa'},
            {label:'WPA2', value:'wpa2'}
        ];
        self.loading = false;

        /**
         * Update config
         * @param networks: list of networks returned by rpc
         */
        self.__updateConfig = function(config)
        {
            self.networks = config.networks;
            self.wifiInterfaces = config.wifiinterfaces;
            self.lastWifiScan = config.lastwifiscan;
            self.networkStatus = config.networkstatus;
        };

        /**
         * Block ui when loading stuff
         */
        self.networkLoading = function(block)
        {
            if( block )
            {
                self.loading = true;
            }
            else
            {
                self.loading = false;
            }
        };

        /**
         * Reset dialog variables
         */
        self.resetDialogVariables = function()
        {
            self.newConfig = null;
            self.selectedNetwork = null;
            self.wifiPassword = null;
        };

        /**
         * Cancel dialog (close modal and reset variables)
         */
        self.cancelDialog = function()
        {
            self.resetDialogVariables()
            $mdDialog.cancel();
        };

        /**
         * Valid dialog (only close modal)
         * Note: don't forget to reset variables !
         */
        self.validDialog = function() {
            $mdDialog.hide();
        };

        /**
         * Show interface configuration
         * @param item: selected item
         * @param type: type of network (wifi|wired)
         */
        self.showConfig = function(item, type)
        {
            self.selectedNetwork = item;

            $mdDialog.show({
                controller: function() { return self; },
                controllerAs: 'dialogCtl',
                templateUrl: 'networkInfosDialog.html',
                parent: angular.element(document.body),
                clickOutsideToClose: true,
                fullscreen: true
            })
            .then(function() {}, function() {});
        };

        /**
         * Fill new config class member with specified interface configuration
         * @param network: selected network
         */
        self.__fillNewConfig = function(network)
        {
            self.newConfig = {
                interface: network.interface,
                dhcp: network.config.mode=='dhcp'? true : false,
                ipv4: network.config.address,
                gateway_ipv4: network.config.gateway,
                netmask_ipv4: network.config.netmask
            };
        };

        /**
         * Show wired edition dialog
         * @param network: selected network
         */
        self.editWiredConfig = function(network)
        {
            self.selectedNetwork = network;

            //get interfaces and fill new class config member
            self.__fillNewConfig(network);

            $mdDialog.show({
                controller: function() { return self; },
                controllerAs: 'dialogCtl',
                templateUrl: 'wiredEditDialog.html',
                parent: angular.element(document.body),
                clickOutsideToClose: true,
                fullscreen: true
            }).then(function() {
                //save edition
                var promise = null;
                if( self.newConfig.dhcp )
                {
                    //save wired dhcp
                    promise = networkService.saveWiredDhcpConfiguration(self.newConfig.interface);
                }
                else
                {
                    //save wired static
                    //TODO handle fallback option when dhcpcd is installed
                    promise = networkService.saveWiredStaticConfiguration(self.newConfig.interface, self.newConfig.ipv4, self.newConfig.gateway_ipv4, self.newConfig.netmask_ipv4, false);
                }

                //execute promise
                promise
                    .then(function() {
                        toast.success('Configuration saved');
                    }, function() {
                        toast.error('Problem during configuration saving');
                    })
                    .finally(function() {
                        self.resetDialogVariables();
                    });
            }, function() {});
        };

        /**
         * Show wifi edition dialog
         * @param network: selected network
         */
        self.editWifiConfig = function(network)
        {
            //self.selectedConfig = item;
            self.selectedNetwork = network;

            //prepare new config
            self.__fillNewConfig(network);

            $mdDialog.show({
                controller: function() { return self; },
                controllerAs: 'dialogCtl',
                templateUrl: 'wifiEditDialog.html',
                parent: angular.element(document.body),
                clickOutsideToClose: true,
                fullscreen: true
            })
            .then(function() {}, function() {});
        };

        /**
         * Refresh wifi networks
         */
        self.refreshWifiNetworks = function()
        {
            //lock ui
            self.networkLoading(true);

            networkService.refreshWifiNetworks()
                .then(function(config) {
                    //update config
                    self.__updateConfig(config);
                })
                .finally(function() {
                    self.networkLoading(false);
                });
        };

        /**
         * Change wifi password
         */
        self.changeWifiPassword = function()
        {
            //lock ui
            self.validDialog();
            self.networkLoading(true);
            toast.loading('Changing password...');

            networkService.updateWifiNetworkPassword(self.selectedNetwork.interface, self.selectedNetwork.network, self.wifiPassword)
                .then(function(config) {
                    //update config
                    self.__updateConfig(config);

                    //user message
                    toast.success('Password updated');
                })
                .finally(function() {
                    self.resetDialogVariables();
                    self.networkLoading(false);
                });
        };

        /**
         * Enable wifi network
         */
        self.enableWifiNetwork = function()
        {
            //lock ui
            self.validDialog();
            self.networkLoading(true);
            toast.loading('Enabling network...');

            networkService.enableWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network)
                .then(function(config) {
                    //update config
                    self.__updateConfig(config);
                    
                    //user message
                    toast.success('Network enabled');
                })
                .finally(function() {
                    self.resetDialogVariables();
                    self.networkLoading(false);
                });
        };

        /**
         * Disable wifi network
         */
        self.disableWifiNetwork = function()
        {
            //lock ui
            self.validDialog();
            self.networkLoading(true);
            toast.loading('Disabling network...');

            networkService.disableWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network)
                .then(function(config) {
                    //update config
                    self.__updateConfig(config);
                    
                    //user message
                    toast.success('Network disabled');
                })
                .finally(function() {
                    self.resetDialogVariables();
                    self.networkLoading(false);
                });
        };

        /**
         * Forget wifi network
         */
        self.forgetWifiNetwork = function()
        {
            //only 1 modal allowed, close properly current one before opening confirm dialog
            //it keeps all variables
            self.validDialog();

            //open confirm dialog
            confirm.open('Forget network', 'All wifi network configuration will be deleted', 'Forget')
                .then(function() {
                    //block ui
                    self.networkLoading(true);
                    toast.loading('Forgetting network...');

                    //perform deletion
                    return networkService.deleteWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network)
                        .then(function(config) {
                            //update config
                            self.__updateConfig(config);

                            //user message
                            toast.success('Network configuration has been forgotten')
                        })
                        .finally(function() {
                            self.networkLoading(false);
                        });
                })
                .finally(function() {
                    self.resetDialogVariables();
                });
        };

        /**
         * Connect to wifi network
         * Open password dialog and try to connect
         */
        self.connectWifiNetwork = function(network)
        {
            self.selectedNetwork = network;

            if( self.selectedNetwork.config.encryption!=='unsecured' )
            {
                //encrypted connection, prompt network password
                $mdDialog.show({
                    controller: function() { return self; },
                    controllerAs: 'dialogCtl',
                    templateUrl: 'wifiConnectionDialog.html',
                    parent: angular.element(document.body),
                    clickOutsideToClose: false,
                    escapeToClose: false,
                    fullscreen: true
                })
                .then(function() {
                    //lock ui
                    self.networkLoading(true);
                    toast.loading('Connecting to network...');

                    //perform action
                    networkService.saveWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network, self.wifiPassword, self.selectedNetwork.config.encryption)
                        .then(function(config) {
                            //update config
                            self.__updateConfig(config);

                            //user message
                            toast.success('Wifi network configuration saved. Device should be able to connect to this network');
                        })
                        .finally(function() {
                            //unlock ui
                            self.networkLoading(false);
                        });
                }, function() {})
                .finally(function() {
                    self.resetDialogVariables();
                });
            }
            else
            {
                //unsecured network, directly add network
                self.networkLoading(true);
                toast.loading('Connecting to network...');

                networkService.saveWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network, self.wifiPassword, self.selectedNetwork.config.encryption)
                    .then(function(config) {
                        //update config
                        self.__updateConfig(config);

                        //user message
                        toast.success('Wifi network configuration saved. Device should be able to connect to this network');
                    })
                    .finally(function() {
                        //unlock ui
                        self.networkLoading(false);
                    });
            }
        };

        /**
         * Reconfigure network interface
         */
        self.reconfigureWifiNetwork = function()
        {
            //only 1 modal allowed, close properly current one before opening confirm dialog
            //it keeps all variables
            self.validDialog();

            //open confirm dialog
            confirm.open('Reconfigure network', 'This action can disconnect the device temporarly. Please wait until it connects again.', 'Reconfigure')
            .then(function() {
                //block ui
                self.networkLoading(true);
                toast.loading('Reconfiguring network...');

                //execute action
                return networkService.reconfigureWifiNetwork(self.selectedNetwork.interface)
                    .then(function(config) {
                        //update config
                        self.__updateConfig(config);
                         //user message
                        toast.success('Network has been reconfigured')
                    })
                    .finally(function() {
                        //unblock ui
                        self.networkLoading(false);
                    });
            }, function() {})
            .finally(function() {
                self.resetDialogVariables();
            });
        };

        /**
         * Fill newNetwork member with default values
         */
        self.__fillNewNetwork = function()
        {
            self.newNetwork = {
                network: null,
                password: null,
                encryption: 'wpa2',
                hidden: true,
                interface: self.wifiInterfaces[0]
            };
        };

        /**
         * Add hidden wifi network
         */
        self.addHiddenWifiNetwork = function()
        {
            //fill new network
            self.__fillNewNetwork();

            //open dialog
            $mdDialog.show({
                controller: function() { return self; },
                controllerAs: 'dialogCtl',
                templateUrl: 'addHiddenWifiDialog.html',
                parent: angular.element(document.body),
                clickOutsideToClose: false,
                escapeToClose: false,
                fullscreen: true
            })
            .then(function() {
                //lock ui
                self.networkLoading(true);
                toast.loading('Saving hidden network...');

                //perform action
                networkService.saveWifiNetwork(self.newNetwork.interface, self.newNetwork.network, self.newNetwork.password, self.newNetwork.encryption, self.newNetwork.hidden)
                    .then(function(config) {
                        //update config
                        self.__updateConfig(config);

                        //user message
                        toast.success('Hidden wifi network configuration saved. Device should be able to connect to this network');
                    })
                    .finally(function() {
                        //unlock ui
                        self.networkLoading(false);
                    });
            }, function() {})
            .finally(function() {
                self.resetDialogVariables();
            });
        };

        /**
         * Controller init
         */
        self.init = function()
        {
            //load config
            raspiotService.getModuleConfig('network')
                .then(function(config) {
                    self.__updateConfig(config);
                })
                .finally(function() {
                    self.networkLoading(false);
                });
        };

        /**
         * Handle network events
         */
        $rootScope.$on('network.status.update', function(event, uuid, params)
        {
            if( self.networkStatus[params.interface]===undefined )
            {
                self.networkStatus[params.interface] = {};
            }
            self.networkStatus[params.interface].network = params.network;
            self.networkStatus[params.interface].status = params.status;
            self.networkStatus[params.interface].ipaddress = params.ipaddress;
        });

    }];

    var networkLink = function(scope, element, attrs, controller) {
        controller.init();
    };

    return {
        templateUrl: 'network.config.html',
        replace: true,
        scope: true,
        controller: networkController,
        controllerAs: 'networkCtl',
        link: networkLink
    };
};

var RaspIot = angular.module('RaspIot');
RaspIot.directive('networkConfigDirective', ['$rootScope', 'raspiotService', 'networkService', 'toastService', 'confirmService', '$mdDialog', networkConfigDirective])
