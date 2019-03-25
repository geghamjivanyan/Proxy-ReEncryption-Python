#
from unittest import TestCase

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


#
class BaseTest(TestCase):
    def setUp(self):
        #
        super(BaseTest, self).setUp()
