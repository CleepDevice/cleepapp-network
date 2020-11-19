#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cleep.libs.internals.event import Event

class NetworkStatusUpdateEvent(Event):
    """
    Network.status.update event.

    Report network interface status
    """

    EVENT_NAME = 'network.status.update'
    EVENT_PROPAGATE = False
    EVENT_PARAMS = ['type', 'interface', 'network', 'ipaddress', 'status']

    def __init__(self, bus, formatters_broker):
        """ 
        Constructor

        Args:
            bus (MessageBus): message bus instance
            formatters_broker (FormattersBroker): formatters broker instance
        """
        Event.__init__(self, bus, formatters_broker)

