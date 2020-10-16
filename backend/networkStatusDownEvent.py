#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cleep.libs.internals.event import Event

class NetworkStatusDownEvent(Event):
    """
    Network.status.down event
    """

    EVENT_NAME = u'network.status.down'
    EVENT_SYSTEM = True
    EVENT_PARAMS = []

    def __init__(self, bus, formatters_broker):
        """ 
        Constructor

        Args:
            bus (MessageBus): message bus instance
            formatters_broker (FormattersBroker): formatters broker instance
        """
        Event.__init__(self, bus, formatters_broker)

