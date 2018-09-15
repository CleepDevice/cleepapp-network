/**
 * Network config directive
 * Handle network configuration
 */
var networkConfigDirective = function(toast, networkService, raspiotService) {

    var networkController = function()
    {
        var self = this;
        self.networkType = 'wifi';
    };

    return {
        templateUrl: 'network.directive.html',
        replace: true,
        scope: true,
        controller: networkController,
        controllerAs: 'networkCtl'
    };
};

var RaspIot = angular.module('RaspIot');
RaspIot.directive('networkConfigDirective', ['toastService', 'networkService', 'raspiotService', networkConfigDirective])
