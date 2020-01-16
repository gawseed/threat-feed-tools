import urllib3
from gawseed.threatfeed.config import Config
import json

class EnrichmentURL(Config):
    def __init__(self, conf, search_index, data_source, is_binary):
        super().__init__(conf)
        
        self._pool = urllib3.PoolManager()
        self._conf = conf

        self.require(['url'])

        self._url = self.config('url')
        self._tag = self.config('tag')
        self._type = self.config('type','text/plain')
        self._match_key = self.config('match_key', 'value')
        self._data_key = self.config('data_key', 'key')
        self._output_key = self.config('output_key', 'geturl')

    def geturl(self, url, type='GET', params={}):
        r = self._pool.request(type, url)
        if r.status != 200:
            print("failed to fetch URL:" + str(r.status))
            return None

        # XXX: check against the expected type (self._type)
        return r.data

    def convert(self, result):
        if self._type == 'text/plain' or self._type == 'text':
            return result.decode()
        if self._type == 'application/json' or self._type == 'json':
            return json.loads(result.decode())
        
        # (probably shouldn't do this)
        return result
        
    def gather(self, count, row, match):
        fetched = self.geturl(self._url.format(tag=match['tag'], match_info=match[self._match_key],
                                               data_info=row[self._data_key]))
        converted = self.convert(fetched)
        return (self._output_key, converted)
