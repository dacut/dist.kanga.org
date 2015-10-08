import os.path, sys
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import unittest
from tests import suite
unittest.main(defaultTest='suite')
