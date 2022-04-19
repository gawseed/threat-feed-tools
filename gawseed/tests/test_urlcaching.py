import os
import unittest
import logging
import hashlib

from mock import Mock, MagicMock

from gawseed.threatfeed.config import Config

class test_urllib_caching(unittest.TestCase):
    cachedir = "/tmp"

    def test_urllib_cachestring(self):
        configtest = Config({'url_cache_directory': self.cachedir})
        self.assertTrue(configtest.cache_url_string("test")
                        == hashlib.sha256("test".encode('utf-8')).hexdigest()[0:20])

    def test_urllib_cache_location(self):
        configtest = Config({'url_cache_directory': self.cachedir})
        self.assertTrue(configtest.cache_url_location("test")
                        == os.path.join(self.cachedir,
                                        hashlib.sha256("test".encode('utf-8')).hexdigest()[0:20]))

    def test_urllib_cache(self):
        configtest = Config({'url_cache_directory': self.cachedir})
        url1 = "http://localhost/fake.json"
        url1_cache_spot = os.path.join(self.cachedir, configtest.cache_url_string(url1))

        if os.path.exists(url1_cache_spot):
            os.unlink(url1_cache_spot)

        fakedata = Mock(
            status=200,
            data="hello world"
        )
        configtest._pool = MagicMock(return_value=fakedata)
        configtest._pool.request = MagicMock(return_value=fakedata)
        response = configtest.geturl(url1)

        self.assertEqual(response, "hello world")
        self.assertTrue(os.path.exists(url1_cache_spot))

        # now refetch but with a new fake-data that is wrong to test that the cache is used

        # use a new cache to avoid the in-memory cache
        configtest = Config({'url_cache_directory': self.cachedir})
        fakedata = Mock(
            status=200,
            data="hello world -- no!"
        )
        configtest._pool = MagicMock(return_value=fakedata)
        configtest._pool.request = MagicMock(return_value=fakedata)
        response = configtest.geturl(url1)
        self.assertEqual(response, "hello world")
        self.assertTrue(os.path.exists(url1_cache_spot))

    def test_urllib_without_cache(self):
        "A duplicate version that makes sure a cache isn't used"
        configtest = Config()
        url1 = "http://localhost/fake.json"
        url1_cache_spot = os.path.join(self.cachedir, configtest.cache_url_string(url1))

        if os.path.exists(url1_cache_spot):
            os.unlink(url1_cache_spot)

        fakedata = Mock(
            status=200,
            data="hello world"
        )
        configtest._pool = MagicMock(return_value=fakedata)
        configtest._pool.request = MagicMock(return_value=fakedata)
        response = configtest.geturl(url1)

        self.assertEqual(response, "hello world")
        self.assertFalse(os.path.exists(url1_cache_spot))

        # now refetch but with a new fake-data that is wrong to test that the cache is used
        configtest = Config()
        fakedata = Mock(
            status=200,
            data="hello world -- yes!"
        )
        configtest._pool = MagicMock(return_value=fakedata)
        configtest._pool.request = MagicMock(return_value=fakedata)
        response = configtest.geturl(url1)
        self.assertEqual(response, "hello world -- yes!")
        self.assertFalse(os.path.exists(url1_cache_spot))

    def test_urllib_memory_cache(self):
        "A duplicate version that makes sure a cache isn't used"
        configtest = Config()
        url1 = "http://localhost/fake.json"
        url1_cache_spot = os.path.join(self.cachedir, configtest.cache_url_string(url1))

        if os.path.exists(url1_cache_spot):
            os.unlink(url1_cache_spot)

        fakedata = Mock(
            status=200,
            data="hello world"
        )
        configtest._pool = MagicMock(return_value=fakedata)
        configtest._pool.request = MagicMock(return_value=fakedata)
        response = configtest.geturl(url1)

        self.assertEqual(response, "hello world")
        self.assertFalse(os.path.exists(url1_cache_spot))

        # now refetch but with a new fake-data that is wrong to test that the cache is used
        fakedata = Mock(
            status=200,
            data="hello world -- yes!"
        )
        configtest._pool = MagicMock(return_value=fakedata)
        configtest._pool.request = MagicMock(return_value=fakedata)
        response = configtest.geturl(url1)
        self.assertEqual(response, "hello world")
        self.assertFalse(os.path.exists(url1_cache_spot))
