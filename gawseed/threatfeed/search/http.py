import sys
import re

from gawseed.threatfeed.search.re import RESearch

class HTTPSearch(RESearch):
    """Matches a regexp threat against a host/uri combo data field (aka bro log)"""
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        super().__init__(search_list, data_iterator, binary_search, conf)

        self._host_key = self.config('host_key', 'host',
                                     help="The column name for the host to construct a URL out of")
    
        self._uri_key = self.config('uri_key', 'uri',
                                     help="The column name for the uri portion of the URL")

        if binary_search:
            self._host_key = self.maybe_convert_token_to_binary(self._host_key)
            self._uri_key = self.maybe_convert_token_to_binary(self._uri_key)

    def search(self, row):
        # XXX: currently assumes a split host/uri scheme like bro.  Need to make this generic
        if self._host_key not in row or self._uri_key not in row or row[self._host_key] is None or row[self._uri_key] is None:
            return None
        if self._binary_search:
            url = "http://" + row[self._host_key].decode() + "/" + row[self._uri_key].decode()
        else:
            url = "http://" + row[self._host_key].decode() + "/" + row[self._uri_key].decode()

        return self.search_one(url)

