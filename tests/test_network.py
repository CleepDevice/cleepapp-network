#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import logging
import sys
sys.path.append('../')
from backend.network import Network
from cleep.exception import InvalidParameter, MissingParameter, CommandError, Unauthorized, CommandInfo
from cleep.libs.tests import session
from mock import Mock, patch, MagicMock

class TestSystem(unittest.TestCase):

    def setUp(self):
        self.session = session.TestSession()
        logging.basicConfig(level=logging.FATAL, format=u'%(asctime)s %(name)s:%(lineno)d %(levelname)s : %(message)s')

    def tearDown(self):
        self.session.clean()

    def init_session(self, start_module=True):
        self.module = self.session.setup(Network)
        if start_module:
            self.session.start_module(self.module)

    def test_configure(self):
        self.init_session(start_module=True)

if __name__ == '__main__':
    # coverage run --omit="*lib/python*/*","test_*" --concurrency=thread test_network.py; coverage report -m -i
    unittest.main()
    
