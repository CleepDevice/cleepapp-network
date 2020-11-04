/**
 * Network config Component
 * Handle network configuration
 */
angular
.module('Cleep')
.directive('networkConfigComponent', ['$rootScope', 'cleepService', 'networkService', 'toastService', 'confirmService', '$mdDialog',
function($rootScope, cleepService, networkService, toast, confirm, $mdDialog) {

    var networkController = ['$scope', function($scope) {
        var self = this;
        self.config = {};
        self.dialogData = null;
        self.selectedNetwork = null;
        self.encryptions = [
            {label:'No security', value:'unsecured'},
            {label:'WEP', value:'wep'},
            {label:'WPA', value:'wpa'},
            {label:'WPA2', value:'wpa2'}
        ];
        self.loading = false;

        /**
         * Block ui when loading stuff
         */
        self.networkLoading = function(block) {
            if( block ) {
                self.loading = true;
            } else {
                self.loading = false;
            }
        };

        /**
         * Reset dialog variables
         */
        self.resetDialogVariables = function() {
            self.dialogData = null;
            self.selectedNetwork = null;
        };

        /**
         * Cancel dialog (close modal and reset variables)
         */
        self.cancelDialog = function() {
            self.resetDialogVariables()
            $mdDialog.cancel();
        };

        /**
         * Valid dialog (only close modal)
         * Note: don't forget to reset variables !
         */
        self.closeDialog = function() {
            $mdDialog.hide();
        };

        /**
         * Show interface configuration
         * @param item: selected item
         * @param type: type of network (wifi|wired)
         */
        self.showConfig = function(item, type, ev) {
            self.selectedNetwork = item;

            $mdDialog.show({
                controller: function($mdDialog) {
                    this.config = self.config;
                    this.selectedNetwork = self.selectedNetwork;
                    this.cancelDialog = self.cancelDialog;
                },
                controllerAs: 'dialogCtl',
                targetEvent: ev,
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
        self.__fillDialogDataWithNetwork = function(network) {
            self.dialogData = {
                interface: network.interface,
                dhcp: network.config.mode == 'dhcp' ? true : false,
                ipv4: network.config.address,
                gateway_ipv4: network.config.gateway,
                netmask_ipv4: network.config.netmask
            };
        };

        /**
         * Show wired edition dialog
         * @param network: selected network
         */
        self.editWiredConfig = function(network, ev) {
            self.selectedNetwork = network;

            // get interfaces and fill new class config member
            self.__fillDialogDataWithNetwork(network);

            $mdDialog.show({
                controller: function($mdDialog) {
                    this.dialogData = self.dialogData;
                    this.cancelDialog = self.cancelDialog;
                    this.closeDialog = self.closeDialog;
                },
                controllerAs: 'dialogCtl',
                targetEvent: ev,
                templateUrl: 'wiredEditDialog.html',
                parent: angular.element(document.body),
                clickOutsideToClose: true,
                fullscreen: true
            }).then(function() {
                // save edition
                var promise = null;
                if( self.dialogData.dhcp ) {
                    // save wired dhcp
                    promise = networkService.saveWiredDhcpConfiguration(self.dialogData.interface);
                } else {
                    // save wired static
                    promise = networkService.saveWiredStaticConfiguration(
                        self.dialogData.interface,
                        self.dialogData.ipv4,
                        self.dialogData.gateway_ipv4,
                        self.dialogData.netmask_ipv4,
                        false
                    );
                }

                // execute promise
                promise
                    .then(function() {
                        toast.success('Configuration saved');
                    }, function() {
                        toast.error('Error occured during configuration saving');
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
        self.editWifiConfig = function(network, ev) {
            self.selectedNetwork = network;
            self.dialogData = {
                wifiPassword: null,
            };

            // prepare dialog data
            self.__fillDialogDataWithNetwork(network);

            $mdDialog.show({
                controller: function($mdDialog) {
                    this.selectedNetwork = self.selectedNetwork;
                    this.dialogData = self.dialogData;
                    this.cancelDialog = self.cancelDialog;
                    this.changeWifiPassword = self.changeWifiPassword;
                    this.disableWifiNetwork = self.disableWifiNetwork;
                    this.enableWifiNetwork = self.enableWifiNetwork;
                    this.reconfigureWifiNetwork = self.reconfigureWifiNetwork;
                    this.forgetWifiNetwork = self.forgetWifiNetwork;
                },
                controllerAs: 'dialogCtl',
                targetEvent: ev,
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
        self.refreshWifiNetworks = function() {
            // lock ui
            self.networkLoading(true);

            networkService.refreshWifiNetworks()
                .then(function(config) {
                    // update config
                    cleepService.reloadModuleConfig('network')
                })
                .finally(function() {
                    self.networkLoading(false);
                });
        };

        /**
         * Change wifi password
         */
        self.changeWifiPassword = function() {
            // lock ui
            self.closeDialog();
            self.networkLoading(true);
            toast.loading('Changing password...');

            networkService.updateWifiNetworkPassword(self.selectedNetwork.interface, self.selectedNetwork.network, self.dialogData.wifiPassword)
                .then(function(config) {
                    // update config
                    cleepService.reloadModuleConfig('network')

                    // user message
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
        self.enableWifiNetwork = function() {
            // lock ui
            self.closeDialog();
            self.networkLoading(true);
            toast.loading('Enabling network...');

            networkService.enableWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network)
                .then(function(config) {
                    // update config
                    cleepService.reloadModuleConfig('network')
                    
                    // user message
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
        self.disableWifiNetwork = function() {
            // lock ui
            self.closeDialog();
            self.networkLoading(true);
            toast.loading('Disabling network...');

            networkService.disableWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network)
                .then(function(config) {
                    // update config
                    cleepService.reloadModuleConfig('network')
                    
                    // user message
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
        self.forgetWifiNetwork = function() {
            // only 1 modal allowed, close properly current one before opening confirm dialog
            // it keeps all variables
            self.closeDialog();

            // open confirm dialog
            confirm.open('Forget network', 'All configuration for this network will be deleted', 'Forget')
                .then(function() {
                    // block ui
                    self.networkLoading(true);
                    toast.loading('Forgetting network...');

                    // perform deletion
                    return networkService.deleteWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network)
                        .then(function(config) {
                            // update config
                            cleepService.reloadModuleConfig('network')

                            // user message
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
        self.connectWifiNetwork = function(network, ev) {
            self.selectedNetwork = network;

            // fill dialog data
            self.dialogData = {
                wifiPassword: null,
            }

            if( self.selectedNetwork.config.encryption!=='unsecured' ) {
                // encrypted connection, prompt network password
                $mdDialog.show({
                    controller: function($mdDialog) {
                        this.dialogData = self.dialogData;
                        this.config = self.config;
                        this.selectedNetwork = self.selectedNetwork;
                        this.cancelDialog = self.cancelDialog;
                        this.closeDialog = self.closeDialog;
                    },
                    controllerAs: 'dialogCtl',
                    targetEvent: ev,
                    templateUrl: 'wifiConnectionDialog.html',
                    parent: angular.element(document.body),
                    clickOutsideToClose: false,
                    escapeToClose: false,
                    fullscreen: true
                })
                .then(function() {
                    // lock ui
                    self.networkLoading(true);
                    toast.loading('Connecting to network...');

                    // perform action
                    networkService.saveWifiNetwork(
                        self.selectedNetwork.interface,
                        self.selectedNetwork.network,
                        self.dialogData.wifiPassword,
                        self.selectedNetwork.config.encryption
                    )
                        .then(function(config) {
                            // update config
                            cleepService.reloadModuleConfig('network')

                            // user message
                            toast.success('Wifi network configuration saved. Device should be able to connect to this network');
                        })
                        .finally(function() {
                            // unlock ui
                            self.networkLoading(false);
                        });
                }, function() {})
                .finally(function() {
                    self.resetDialogVariables();
                });
            } else {
                // unsecured network, directly add network
                self.networkLoading(true);
                toast.loading('Connecting to network...');

                // perform action
                networkService.saveWifiNetwork(self.selectedNetwork.interface, self.selectedNetwork.network, self.wifiPassword, self.selectedNetwork.config.encryption)
                    .then(function(config) {
                        // update config
                        cleepService.reloadModuleConfig('network')

                        // user message
                        toast.success('Wifi network configuration saved. Device should be able to connect to this network');
                    })
                    .finally(function() {
                        // unlock ui
                        self.networkLoading(false);
                    });
            }
        };

        /**
         * Reconfigure network interface
         */
        self.reconfigureWifiNetwork = function() {
            // only 1 modal allowed, close properly current one before opening confirm dialog
            // it keeps all variables
            self.closeDialog();

            // open confirm dialog
            confirm.open('Reconfigure network', 'This action can disconnect the device temporarly. Please wait until it connects again.', 'Reconfigure')
            .then(function() {
                // block ui
                self.networkLoading(true);
                toast.loading('Reconfiguring network...');

                // execute action
                return networkService.reconfigureWifiNetwork(self.selectedNetwork.interface)
                    .then(function(config) {
                        // update config
                        cleepService.reloadModuleConfig('network')
                        // user message
                        toast.success('Network has been reconfigured')
                    })
                    .finally(function() {
                        // unblock ui
                        self.networkLoading(false);
                    });
            }, function() {})
            .finally(function() {
                self.resetDialogVariables();
            });
        };

        /**
         * Add hidden wifi network
         */
        self.addHiddenWifiNetwork = function(ev) {
            // fill dialog data
            self.dialogData = {
                network: null,
                password: null,
                encryption: 'wpa2',
                hidden: true,
                interface: self.config.wifiinterfaces[0],
            };

            // open dialog
            $mdDialog.show({
                controller: function($mdDialog) {
                    this.dialogData = self.dialogData;
                    this.encryptions = self.encryptions;
                    this.cancelDialog = self.cancelDialog;
                    this.closeDialog = self.closeDialog;
                },
                controllerAs: 'dialogCtl',
                targetEvent: ev,
                templateUrl: 'addHiddenWifiDialog.html',
                parent: angular.element(document.body),
                clickOutsideToClose: false,
                escapeToClose: false,
                fullscreen: true
            })
            .then(function() {
                // lock ui
                self.networkLoading(true);
                toast.loading('Saving hidden network...');

                // perform action
                networkService.saveWifiNetwork(
                    self.dialogData.interface,
                    self.dialogData.network,
                    self.dialogData.password,
                    self.dialogData.encryption,
                    self.dialogData.hidden
                )
                    .then(function(config) {
                        // update config
                        cleepService.reloadModuleConfig('network')

                        // user message
                        toast.success('Hidden wifi network configuration saved. Device should be able to connect to this network');
                    })
                    .finally(function() {
                        // unlock ui
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
        self.$onInit = function() {
            // load config
            cleepService.getModuleConfig('network')
                .finally(function() {
                    self.networkLoading(false);
                });

            // enable active network scan
            networkService.enableActiveNetworkScan()
        };

        /**
         * Controller exit
         */
        self.$onDestroy = function() {
            // disable active network scan
            networkService.disableActiveNetworkScan()
        };

        /**
         * Watch configuration changes
         */
        $rootScope.$watch(
            function() {
                return cleepService.modules['network'].config;
            },
            function(newVal, oldVal) {
                if( newVal && Object.keys(newVal).length ) {
                    Object.assign(self.config, newVal);
                }
            }
        );

        /**
         * Handle network events
         */
        $rootScope.$on('network.status.update', function(event, uuid, params) {
            cleepService.reloadModuleConfig('network')
        });

    }];

    return {
        templateUrl: 'network.config.html',
        replace: true,
        scope: true,
        controller: networkController,
        controllerAs: 'networkCtl',
    };
}]);

