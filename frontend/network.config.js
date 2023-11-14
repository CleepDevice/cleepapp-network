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
        self.wiredNetworks = [];
        self.wirelessNetworks = {};
        self.wirelessButtons = [];

        /**
         * Block ui when loading stuff
         */
        self.networkLoading = function(block) {
            self.loading = block;
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

        self.showConfig = function(meta) {
            self.selectedNetwork = meta.network;

            $mdDialog.show({
                controller: function($mdDialog) {
                    this.config = self.config;
                    this.selectedNetwork = self.selectedNetwork;
                    this.cancelDialog = self.cancelDialog;
                },
                controllerAs: '$ctrl',
                targetEvent: meta.event,
                templateUrl: 'network-infos.dialog.html',
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
                templateUrl: 'wired-edit.dialog.html',
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
                controllerAs: '$ctrl',
                targetEvent: ev,
                templateUrl: 'wifi-edit.dialog.html',
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
                    controllerAs: '$ctrl',
                    targetEvent: ev,
                    templateUrl: 'wifi-connection.dialog.html',
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
        self.addHiddenWifiNetwork = function(event) {
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
                controllerAs: '$ctrl',
                targetEvent: event,
                templateUrl: 'add-hidden-wifi.dialog.html',
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
            self.wirelessButtons.push(
                { label: 'Connect to hidden network', icon: 'wifi-plus', click: self.addHiddenWifiNetwork, color: 'md-primary' },
                { label: 'Scan wifi networks', icon: 'wifi-sync', click: self.refreshWifiNetworks, color: 'md-primary' },
            );

            // load config
            cleepService.getModuleConfig('network')
                .finally(function() {
                    self.networkLoading(false);
                });

            // enable active network scan
            networkService.enableActiveNetworkScan();
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
        $rootScope.$watchCollection(
            () => cleepService.modules['network'].config,
            (newVal) => {
                if( newVal && Object.keys(newVal).length ) {
                    Object.assign(self.config, newVal);

                    // fill networks
                    self.wiredNetworks = [];
                    self.wirelessNetworks = [];
                    for (const network of self.config.networks) {
                        if (network.wifi) {
                            self.fillWifiNetwork(network)
                        } else {
                            self.fillWiredNetwork(network)
                        }
                    }
                }
            },
        );

        self.fillWiredNetwork = function(network) {
            const connected = self.config.networkstatus[network.interface].status === 2;
            const label = connected ? 'connected with ip address ' + self.config.networkstatus[network.interface].ipaddress : 'not connected';

            self.wiredNetworks.push({
                title: network.network + ' : ' + label,
                icon: 'ethernet',
                clicks: [
                    { icon: 'information', tooltip: 'Info', click: self.showConfig, meta: { network, type: 'wired' }, style: 'md-raised md-primary' },
                    { icon: 'cog', tooltip: 'Configure', click: self.editWiredConfig, meta: { network }, style: 'md-primary md-raised' },
                ],
            });
        };

        self.fillWifiNetwork = function(network) {
            if (!self.wirelessNetworks[network.interface]) {
                self.wirelessNetworks[network.interface] = [];
            }

            const connected = self.config.networkstatus[network.interface].status === 2;
            const label = self.getWifiLabel(network);
            const secured = network.config.encryption === 'unsecured' 
            const security = secured ? { icon: 'lock-open', tooltip: 'Insecured network' } : { icon: 'lock', tooltip : network.config.encryption + ' encryption' };
            const signalIcon = self.getWifiSignalLevelIcon(network.config.signallevel || 0);
            const interface = self.config.wifiinterfaces.length === 1 ? '' : ' (' + network.interface + ')';

            const clicks = [
                { icon: security.icon, tooltip: security.tooltip },
                { icon: signalIcon, tooltip: 'Signal level ' + network.config.signallevel + '%' },
                { icon: 'information', style: 'md-raised md-primary', tooltip: 'Info', click: self.showConfig, meta: { network, type: 'wifi' } },
            ];
            if (network.config.hidden) {
                clicks.unshift({ icon: 'ghost', tooltip: 'Hidden network' });
            }
            if (network.config.configured) {
                clicks.push({ icon: 'cog', style: 'md-raised md-primary', tooltip: 'Configure', click: self.editWifiConfig, meta: { network } });
            } else {
                clicks.push({ icon: 'lan-connect', style: 'md-raised md-primary', tooltip: 'Connect to network', click: self.connectWifiNetwork, meta: { network } });
            }

            self.wirelessNetworks[network.interface].push({
                title: network.network + interface + ' : ' + label,
                icon: 'wifi',
                clicks,
            });
        };

        self.getWifiLabel = function(network) {
            switch (self.config.networkstatus[network.interface].status) {
                case 0:
                    return network.config.disabled ? 'not connected (disabled)' : 'not connected';
                case 1:
                    return 'connecting...';
                case 2:
                    if (self.config.networkstatus[network.interface].network !== network.network) {
                        return 'not connected';
                    }
                    const ip = self.config.networkstatus[network.interface].ipaddress;
                    return 'connected' + (ip ? ' with ip address ' + ip : '');
                case 3:
                    if (self.config.networkstatus[network.interface].network !== network.network) {
                        return 'not connected';
                    }
                    return 'unable to connect, invalid password';
                default:
                    return 'not connected';
            }
        };

        self.getWifiSignalLevelIcon = function(level) {
            if (!level) return 'wifi-strength-off';
            if (level <= 25) return 'wifi-strength-1';
            if (level <= 50) return 'wifi-strength-2';
            if (level <= 75) return 'wifi-strength-3';
            return 'wifi-strength-4';
        };

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
        controllerAs: '$ctrl',
    };
}]);

