import unittest
import logging
from mock import Mock, MagicMock

from gawseed.threatfeed.config import Config


class test_urllib_caching(unittest.TestCase):
    def test_urllib_cache(self):
        configtest = Config({'url_cache_directory': "/tmp"})
        val = Mock(
            status=200,
            data="hello world"
        )
        configtest._pool = MagicMock(return_value=val)
        configtest._pool.request = MagicMock(return_value=val)
        response = configtest.geturl("http://localhost/fake.json")

        self.assertEqual(response, "hello world")



