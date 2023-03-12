#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cleep.libs.internals.event import Event


class NetworkStatusUpdateEvent(Event):
    """
    Network.status.update event.

    Report network interface status
    """

    EVENT_NAME = "network.status.update"
    EVENT_PROPAGATE = False
    EVENT_PARAMS = ["type", "interface", "network", "ipaddress", "status"]

    def __init__(self, params):
        """
        Constructor

        Args:
            params (dict): event parameters
        """
        Event.__init__(self, params)
