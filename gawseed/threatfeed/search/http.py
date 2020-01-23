import sys
import re

from gawseed.threatfeed.search.re import RESearch

class HTTPSearch(RESearch):
    """Matches a regexp threat against a host/uri combo data field (aka bro log)"""
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        super().__init__(search_list, data_iterator, binary_search, conf)
    
    def search(self, row):
        # XXX: currently assumes a split host/uri scheme like bro.  Need to make this generic
        if b'host' not in row or b'uri' not in row or row[b'host'] is None or row[b'uri'] is None:
            return None
        if self._binary_search:
            url = "http://" + row[b'host'].decode() + "/" + row[b'uri'].decode()
        else:
            url = "http://" + row[b'host'].decode() + "/" + row[b'uri'].decode()

        return self.search_one(url)

