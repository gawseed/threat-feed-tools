import sys
import re

from gawseed.threatfeed.search.re import RESearch

class DNSSearch(RESearch):
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        super().__init__(search_list, data_iterator, binary_search, conf)
        self._key = self.config('key', 'query') # assumes bro
        if binary_search:
            self._key = bytes(self._key, 'utf-8')

