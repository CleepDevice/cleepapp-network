#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cleep.libs.internals.event import Event

class NetworkStatusUpdateEvent(Event):
    """
    Network.status.update event.

    Report network interface status
    """

    EVENT_NAME = u'network.status.update'
    EVENT_SYSTEM = True

    def __init__(self, bus, formatters_broker):
        """ 
        Constructor

        Args:
            bus (MessageBus): message bus instance
            formatters_broker (FormattersBroker): formatters broker instance
        """
        Event.__init__(self, bus, formatters_broker)

    def _check_params(self, params):
        """
        Check event parameters

        Args:
            params (dict): event parameters

        Return:
            bool: True if params are valid, False otherwise
        """
        keys = [ 
            u'interface',
            u'network',
            u'ipaddress',
            u'status'
        ]   
        return all(key in keys for key in params.keys())

