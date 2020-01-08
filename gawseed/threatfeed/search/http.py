import re

from gawseed.threatfeed.search import Search

class HTTPSearch(Search):
    def __init__(self, search_list,
                 data_iterator=None,
                 binary_search=False):
        super().__init__(search_list, data_iterator, binary_search)

        self._relist = []
        for item in search_list:
            compiled = re.compile(item)
            self._relist.append({ 'match': search_list[item],
                                  're': compiled})
    
    def search(self, row):
        if b'host' not in row or b'uri' not in row or row[b'host'] is None or row[b'uri'] is None:
            return None
        if self._binary_search:
            url = "http://" + row[b'host'].decode() + "/" + row[b'uri'].decode()
        else:
            url = "http://" + row[b'host'].decode() + "/" + row[b'uri'].decode()

        for expr in self._relist:
            match = expr['re'].match(url)
            if match:
                return expr['match']

