import sys
import re

from gawseed.threatfeed.search import Search

class RESearch(Search):
    """A base class for regular expression based search engines to reuse functions from.

       `search_items` should be a list regular expressions, and will be built
        into self._relist as {'match': item, 're': compiled_version }"""
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        super().__init__(search_list, data_iterator, binary_search, conf)
        self.require(['key'])
        self._key = self.config('key')

        self._relist = []
        for item in search_list:
            try: 
                compiled = re.compile(item)
                self._relist.append({ 'match': search_list[item],
                                      're': compiled})
            except:
                sys.stderr.write("failed to compile regular expression: %s" % (item))
    
    def search(self, row):
        """If the `source` value matches any stored expression, 
           the expression will be returned."""
        return self.search_one(row[self._key])

    def search_one(self, source):
        """If the `source` value matches any stored expression, 
           the expression will be returned."""
        for expr in self._relist:
            match = expr['re'].match(source)
            if match:
                return expr['match']
            
