import json
import time
import sys
import urllib3

from gawseed.threatfeed.config import Config

class EnrichmentURL(Config):
    """Pulls enrichment data from a supplied URL.  The URL format line will be passed a 'tag' and 'match_info'."""
    def __init__(self, conf, search_index, data_source, is_binary, loader=None):
        super().__init__(conf)
        
        self._pool = urllib3.PoolManager()
        self._conf = conf
        self._cache = {}
        self._loader = loader

        self.require(['url'])

        self._url = self.config('url',
                                help="A URL to use for gathering enrichment data.  It may be a python string to be formatted with a 'tag' and 'match_info' value")
        self._tag = self.config('tag',
                                help="The tag to be passed to the URL")
        self._type = self.config('type','text/plain',
                                 help="The expected content type to be returned.  Non-matches will be dropped")
        self._match_key = self.config('match_key', 'value',
                                      help="The match key column name to be used")
        self._data_key = self.config('data_key', 'key',
                                     help="The data key to used")
        self._output_key = self.config('output_key', 'geturl',
                                       help="The output key to store the returned data in.")

        self._cache_time = self.config('cache_time', 3600,
                                       help="If set, will cache the data for a particular key for this number of seconds")

    def geturl(self, url, reqtype='GET', params={}):
        prior_results = self.check_cache(url)
        if prior_results:
            return prior_results
        
        self.verbose("Fetched URL: " + url)
        r = self._pool.request(reqtype, url)
        if r.status != 200:
            print("failed to fetch URL:" + str(r.status))
            return None

        # XXX: check against the expected type (self._type)
        return self.cache(url, r.data)

    def convert(self, result):
        if self._type == 'text/plain' or self._type == 'text':
            return result.decode()
        if self._type == 'application/json' or self._type == 'json':
            return json.loads(result.decode())
        
        # (probably shouldn't do this)
        return result
        
    def gather(self, count, row, match, enrichment_data = {}):
        fetched = self.geturl(self._url.format(tag=match['tag'],
                                               match_info=match[self._match_key],
                                               data_info=row[self._data_key]))
        if not fetched:
            sys.stderr.write("Failed to gather enrichment data...\n")
            return (None, None)
        converted = self.convert(fetched)
        return (self._output_key, converted)

    def cache(self, key, value):
        if not self._cache_time:
            return value
        self._cache[key] = { 'data': value,
                             'timestamp': time.time() }
        return value
        
    def check_cache(self, key):
        if not self._cache_time:
            return None

        if key in self._cache and time.time() < self._cache[key]['timestamp'] + self._cache_time:
            return self._cache[key]['data']

        return None
